
#include "bcache.h"
#include "btree.h"
#include "inode.h"

/* XXX: need ptr_invalid() method for inodes */

struct create_op {
	struct btree_op		op;
	struct bch_inode	 *inode;
	u64			max;
};

static int bch_inode_create_fn(struct btree_op *b_op, struct btree *b,
			       struct bkey *k)
{
	struct create_op *op = container_of(b_op, struct create_op, op);
	struct keylist keys;
	int ret;

	/* slot used? */
	if (bch_val_u64s(k))
		return MAP_CONTINUE;

	/* hole: */

	if (op->max && KEY_INODE(k) >= op->max)
		return -ENOSPC;

	bkey_copy_key(&op->inode->i_key, k);

	pr_debug("inserting inode %llu (size %llu)",
		 KEY_INODE(&op->inode->i_key), KEY_U64s(&op->inode->i_key));

	bch_keylist_init_single(&keys, &op->inode->i_key);
	ret = bch_btree_insert_node(b, b_op, &keys, NULL, false);

	BUG_ON(!ret && !bch_keylist_empty(&keys));

	return ret;
}

int bch_inode_create(struct cache_set *c, struct bch_inode *inode,
		     u64 min, u64 max, u64 *hint)
{
	int ret;
	struct create_op op;
	bool searched_from_start = false;

	if ((max && *hint >= max) || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;

	bch_btree_op_init(&op.op, BTREE_ID_INODES, 0);
	op.inode	= inode;
	op.max		= max;
again:
	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(*hint, 0, 0),
				 bch_inode_create_fn, MAP_HOLES);
	if (ret == MAP_CONTINUE)
		ret = -ENOSPC;

	if (ret == -ENOSPC && !searched_from_start) {
		/* Retry from start */
		*hint = min;
		searched_from_start = true;
		goto again;
	}

	if (!ret)
		*hint = KEY_INODE(&inode->i_key) + 1;

	return ret;
}

int bch_inode_update(struct cache_set *c, struct bch_inode *inode)
{
	struct keylist keys;

	bch_keylist_init_single(&keys, &inode->i_key);
	return bch_btree_insert(c, BTREE_ID_INODES, &keys, NULL);
}
EXPORT_SYMBOL(bch_inode_update);

struct inode_rm_op {
	struct btree_op		op;
	u64			inode_nr;
	u64			new_size;
};

/* XXX: this is slow, due to writes and sequential lookups */
static int inode_truncate_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct inode_rm_op *op = container_of(b_op, struct inode_rm_op, op);
	struct keylist keys;
	struct bkey erase_key;
	int ret;

	if (KEY_INODE(k) > op->inode_nr)
		return MAP_DONE;

	if (KEY_INODE(k) < op->inode_nr)
		BUG();

	if (bkey_cmp(k, &KEY(op->inode_nr, op->new_size, 0)) <= 0)
		return MAP_CONTINUE;

	op->new_size = max(op->new_size, KEY_START(k)) + KEY_SIZE_MAX;

	erase_key = KEY(op->inode_nr, op->new_size, KEY_SIZE_MAX);
	SET_KEY_DELETED(&erase_key, true);

	if (bkey_cmp(&erase_key, &b->key) > 0)
		bch_cut_back(&b->key, &erase_key);

	bch_keylist_init_single(&keys, &erase_key);

	ret = bch_btree_insert_node(b, b_op, &keys, NULL, false);

	return ret ?: MAP_CONTINUE;
}

int bch_inode_truncate(struct cache_set *c, u64 inode_nr, u64 new_size)
{
	struct inode_rm_op op;
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, 0);
	op.inode_nr	= inode_nr;
	op.new_size	= new_size;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(inode_nr, new_size, 0),
				 inode_truncate_fn, 0);
	if (ret < 0)
		return ret;
	return 0;
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct keylist keys;
	struct bkey inode;
	int ret;

	ret = bch_inode_truncate(c, inode_nr, 0);
	if (ret < 0)
		BUG();

	inode = KEY(inode_nr, 0, 0);
	SET_KEY_DELETED(&inode, 1);
	bch_keylist_init_single(&keys, &inode);

	return bch_btree_insert(c, BTREE_ID_INODES, &keys, NULL);
}

struct find_by_inum_op {
	struct btree_op		op;
	struct bch_inode	*ret;
};

static int find_by_inum_fn(struct btree_op *b_op, struct btree *b,
			   struct bkey *k)
{
	struct find_by_inum_op *op = container_of(b_op,
			struct find_by_inum_op, op);

	/* hole, not found */
	if (!bch_val_u64s(k))
		return -ENOENT;

	bkey_copy(op->ret, k);
	return MAP_DONE;
}

int bch_inode_find_by_inum(struct cache_set *c, u64 inode_nr,
			   struct bch_inode *ret)
{
	struct find_by_inum_op op;

	bch_btree_op_init(&op.op, BTREE_ID_INODES, 0);
	op.ret = ret;

	return bch_btree_map_keys(&op.op, c,
				  &KEY(inode_nr, 0, 0),
				  find_by_inum_fn, MAP_HOLES);
}

struct find_op {
	struct btree_op		op;
	uuid_le			*uuid;
	struct bch_inode_blockdev	*ret;
};

static int blockdev_inode_find_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct find_op *op = container_of(b_op, struct find_op, op);
	struct bch_inode *inode = container_of(k, struct bch_inode, i_key);

	if (KEY_INODE(k) >= BLOCKDEV_INODE_MAX)
		return -ENOENT;

	if (inode->i_inode_format == BCH_INODE_BLOCKDEV) {
		struct bch_inode_blockdev *binode =
			container_of(inode, struct bch_inode_blockdev, i_inode);

		pr_debug("found inode %llu: %pU (u64s %llu)",
			 KEY_INODE(k), binode->i_uuid.b, KEY_U64s(k));

		if (!memcmp(op->uuid, &binode->i_uuid, 16)) {
			memcpy(op->ret, binode, sizeof(*binode));
			return MAP_DONE;
		}
	}

	return MAP_CONTINUE;
}

int bch_blockdev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
				    struct bch_inode_blockdev *ret)
{
	struct find_op op;

	bch_btree_op_init(&op.op, BTREE_ID_INODES, -1);
	op.uuid = uuid;
	op.ret = ret;

	return bch_btree_map_keys(&op.op, c, NULL,
				  blockdev_inode_find_fn, 0) == MAP_DONE
		? 0 : -ENOENT;
}
EXPORT_SYMBOL(bch_blockdev_inode_find_by_uuid);
