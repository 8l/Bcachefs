
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "inode.h"
#include "io.h"

ssize_t bch_inode_status(char *buf, size_t len, const struct bkey *k)
{
	if (k->p.offset)
		return scnprintf(buf, len, "offset nonzero: %llu", k->p.offset);

	if (k->size)
		return scnprintf(buf, len, "size nonzero: %u", k->size);

	switch (k->type) {
	case KEY_TYPE_DELETED:
		return scnprintf(buf, len, "deleted");
	case KEY_TYPE_DISCARD:
		return scnprintf(buf, len, "discarded");
	case KEY_TYPE_ERROR:
		return scnprintf(buf, len, "error");
	case KEY_TYPE_COOKIE:
		return scnprintf(buf, len, "cookie");

	case BCH_INODE_FS:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode))
			return scnprintf(buf, len, "bad size: %lu",
					 bkey_val_bytes(k));

		if (k->p.inode < BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "fs inode in blockdev range: %llu",
					 k->p.inode);
		return 0;

	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode_blockdev))
			return scnprintf(buf, len, "bad size: %lu",
					 bkey_val_bytes(k));

		if (k->p.inode >= BLOCKDEV_INODE_MAX &&
		    k->p.inode < BCACHE_USER_INODE_RANGE)
			return scnprintf(buf, len,
					 "blockdev inode in fs range: %llu",
					 k->p.inode);
		return 0;

	default:
		return scnprintf(buf, len, "unknown inode type: %u", k->type);
	}
}

static bool bch_inode_invalid(const struct cache_set *c, struct bkey_s_c k)
{
	if (k.k->p.offset)
		return true;

	switch (k.k->type) {
	case BCH_INODE_FS:
		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode))
			return true;

		if (k.k->p.inode < BLOCKDEV_INODE_MAX)
			return true;

		return false;
	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode_blockdev))
			return true;

		if (k.k->p.inode >= BLOCKDEV_INODE_MAX &&
		    k.k->p.inode < BCACHE_USER_INODE_RANGE)
			return true;

		return false;
	default:
		return true;
	}
}

const struct btree_keys_ops bch_inode_ops = {
};

const struct bkey_ops bch_bkey_inode_ops = {
	.key_invalid	= bch_inode_invalid,
};

int bch_inode_create(struct cache_set *c, struct bkey_i *inode,
		     u64 min, u64 max, u64 *hint)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	bool searched_from_start = false;
	int ret;

	if ((max && *hint >= max) || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;
again:
	bch_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(*hint, 0));

	while ((k = bch_btree_iter_peek_with_holes(&iter)).k) {
		if (max && k.k->p.inode >= max)
			break;

		if (k.k->type < BCH_INODE_FS) {
			inode->k.p = k.k->p;

			pr_debug("inserting inode %llu (size %u)",
				 inode->k.p.inode, inode->k.u64s);

			ret = bch_btree_insert_at(&iter, &keylist_single(inode),
						  NULL, NULL, 0, BTREE_INSERT_ATOMIC);

			if (ret == -EINTR || ret == -EAGAIN)
				continue;

			bch_btree_iter_unlock(&iter);
			if (!ret)
				*hint = k.k->p.inode + 1;

			return ret;
		} else {
			/* slot used */
			bch_btree_iter_advance_pos(&iter);
		}
	}
	bch_btree_iter_unlock(&iter);

	if (!searched_from_start) {
		/* Retry from start */
		*hint = min;
		searched_from_start = true;
		goto again;
	}

	return -ENOSPC;
}

int bch_inode_update(struct cache_set *c, struct bkey_i *inode)
{
	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(inode),
				NULL, NULL);
}
EXPORT_SYMBOL(bch_inode_update);

int bch_inode_truncate(struct cache_set *c, u64 inode_nr, u64 new_size)
{
	return bch_discard(c, POS(inode_nr, new_size), POS(inode_nr + 1, 0), 0);
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct bkey_i delete;
	int ret;

	ret = bch_inode_truncate(c, inode_nr, 0);
	if (ret < 0)
		return ret;

	bkey_init(&delete.k);
	delete.k.p.inode = inode_nr;

	return bch_btree_insert(c, BTREE_ID_INODES,
				&keylist_single(&delete),
				NULL, NULL);
}

int bch_inode_find_by_inum(struct cache_set *c, u64 inode_nr,
			   struct bkey_i_inode *ret)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_INODES, k,
				      POS(inode_nr, 0)) {
		/* hole, not found */
		if (bkey_deleted(k.k))
			break;

		bkey_reassemble(&ret->k_i, k);
		bch_btree_iter_unlock(&iter);
		return 0;

	}
	bch_btree_iter_unlock(&iter);

	return -ENOENT;
}

static int __bch_blockdev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
					     struct bkey_i_inode_blockdev *ret,
					     u64 start_inode, u64 end_inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	for_each_btree_key(&iter, c, BTREE_ID_INODES, k,
			   POS(start_inode, 0)) {
		if (k.k->p.inode >= end_inode)
			break;

		if (k.k->type == BCH_INODE_BLOCKDEV) {
			struct bkey_s_c_inode_blockdev inode =
				bkey_s_c_to_inode_blockdev(k);

			pr_debug("found inode %llu: %pU (u64s %u)",
				 inode.k->p.inode, inode.v->i_uuid.b,
				 inode.k->u64s);

			if (!memcmp(uuid, &inode.v->i_uuid, 16)) {
				bkey_reassemble(&ret->k_i, k);
				bch_btree_iter_unlock(&iter);
				return 0;
			}
		}
	}
	bch_btree_iter_unlock(&iter);
	return -ENOENT;
}

int bch_blockdev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
				    struct bkey_i_inode_blockdev *ret)
{
	if (!__bch_blockdev_inode_find_by_uuid(c, uuid, ret,
					       0, BLOCKDEV_INODE_MAX))
		return 0;

	if (!__bch_blockdev_inode_find_by_uuid(c, uuid, ret,
					       BCACHE_USER_INODE_RANGE,
					       ULLONG_MAX))
		return 0;

	return -ENOENT;
}
EXPORT_SYMBOL(bch_blockdev_inode_find_by_uuid);
