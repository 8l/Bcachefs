
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "dirent.h"

#include "linux/cryptohash.h"

static u64 bch_dirent_hash(const struct qstr *name)
{
	union {
		u32 b[SHA_DIGEST_WORDS];
		u64 ret;
	} digest;

	unsigned done = 0;

	sha_init(digest.b);

	while (done < name->len) {
		u32 workspace[SHA_WORKSPACE_WORDS];
		u8 message[SHA_MESSAGE_BYTES];
		unsigned bytes = min_t(unsigned, name->len - done, SHA_MESSAGE_BYTES);

		memcpy(message, name->name + done, bytes);
		memset(message + bytes, 0, SHA_MESSAGE_BYTES - bytes);
		sha_transform(digest.b, message, workspace);
		done += bytes;
	}

	/* [0,2) reserved for dots */

	return digest.ret >= 2 ? digest.ret : 2;
}

#define __dirent_name_bytes(d)					\
	(bkey_bytes(&(d)->k) - sizeof(struct bkey_i_dirent))

static unsigned dirent_name_bytes(const struct bkey_i_dirent *d)
{
	unsigned len = __dirent_name_bytes(d);

	while (len && !d->v.d_name[len - 1])
		--len;

	return len;
}

static int dirent_cmp(const struct bkey_i_dirent *d, const struct qstr *q)
{
	int len = dirent_name_bytes(d);

	return len - q->len ?: memcmp(d->v.d_name, q->name, len);
}

static bool bch_dirent_invalid(const struct btree_keys *bk,
			       const struct bkey *k)
{
	if (k->size)
		return true;

	if (bkey_deleted(k))
		return false;

	if (bkey_bytes(k) < sizeof(struct bkey_i_dirent))
		return true;

	return false;
}

static void bch_dirent_to_text(const struct btree_keys *bk, char *buf,
			       size_t size, const struct bkey *k)
{
	const struct bkey_i_dirent *d = bkey_i_to_dirent_c(k);

	scnprintf(buf, size, "%s -> %llu", d->v.d_name, d->v.d_inum);
}

const struct btree_keys_ops bch_dirent_ops = {
	.sort_fixup	= bch_generic_sort_fixup,
	.key_invalid	= bch_dirent_invalid,
	.val_to_text	= bch_dirent_to_text,
};

static int __bch_dirent_create(struct cache_set *c, u64 dir_inum,
			       const struct qstr *name, u64 dst_inum,
			       bool update)
{
	struct btree_iter iter;
	const struct bkey *k;
	struct keylist keys;
	struct bkey_i_dirent *dirent;
	int ret = -ENOENT;

	bch_keylist_init(&keys);

	bkey_init(keys.top);
	keys.top->type = BCH_DIRENT;
	set_bkey_val_bytes(keys.top, sizeof(struct bch_dirent) + name->len);

	if (bch_keylist_realloc(&keys, keys.top->u64s))
		return -ENOMEM;

	dirent = bkey_i_to_dirent(keys.top);
	dirent->v.d_inum = dst_inum;
	memcpy(dirent->v.d_name, name->name, name->len);
	memset(dirent->v.d_name + name->len, 0,
	       round_up(name->len, sizeof(u64)) - name->len);

	BUG_ON(dirent_name_bytes(dirent) != name->len);
	BUG_ON(dirent_cmp(dirent, name));

	bch_keylist_enqueue(&keys);

	bch_btree_iter_init(&iter, c, BTREE_ID_DIRENTS,
			    POS(dir_inum, bch_dirent_hash(name)));

	while ((k = bch_btree_iter_peek_with_holes(&iter))) {
		/* hole? */
		if (k->type != BCH_DIRENT) {
			if (!update)
				goto insert;
			break;
		}

		if (!dirent_cmp(bkey_i_to_dirent_c(k), name)) {
			/* found: */
			if (!update) {
				ret = -EEXIST;
				break;
			}
insert:
			dirent->k.p = k->p;

			ret = bch_btree_insert_at(&iter, &keys, NULL, NULL,
						  0, BTREE_INSERT_ATOMIC);
			if (ret != -EINTR && ret != -EAGAIN)
				break;
		} else {
			/* collision */
			bch_btree_iter_advance_pos(&iter);
		}
	}
	bch_btree_iter_unlock(&iter);
	bch_keylist_free(&keys);

	return ret;
}

int bch_dirent_create(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name, u64 dst_inum)
{
	return __bch_dirent_create(c, dir_inum, name, dst_inum, false);
}

int bch_dirent_update(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name, u64 dst_inum)
{
	return __bch_dirent_create(c, dir_inum, name, dst_inum, true);
}

int bch_dirent_delete(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct btree_iter iter;
	const struct bkey *k;
	u64 hash = bch_dirent_hash(name);
	int ret = -ENOENT;

	pr_debug("deleting %llu:%llu (%s)",
		 dir_inum, hash, name->name);

	bch_btree_iter_init(&iter, c, BTREE_ID_DIRENTS,
			    POS(dir_inum, bch_dirent_hash(name)));

	while ((k = bch_btree_iter_peek_with_holes(&iter))) {
		/* hole, not found */
		if (k->type != BCH_DIRENT)
			break;

		if (!dirent_cmp(bkey_i_to_dirent_c(k), name)) {
			struct bkey delete;

			/*
			 * XXX
			 * XXX
			 * XXX
			 *
			 * may need to insert a whiteout (this is a hash table with linear
			 * probing)
			 */

			bkey_init(&delete);
			delete.p = k->p;
			set_bkey_deleted(&delete);

			ret = bch_btree_insert_at(&iter,
						  &keylist_single(&delete),
						  NULL, NULL, 0,
						  BTREE_INSERT_ATOMIC);
			if (ret != -EINTR && ret != -EAGAIN)
				break;
		} else {
			/* collision */
			bch_btree_iter_advance_pos(&iter);
		}
	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

u64 bch_dirent_lookup(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct btree_iter iter;
	const struct bkey *k;
	const struct bkey_i_dirent *dirent;
	u64 hash = bch_dirent_hash(name);

	pr_debug("searching for %llu:%llu (%s)",
		 dir_inum, hash, name->name);

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_DIRENTS, k,
				      POS(dir_inum, bch_dirent_hash(name))) {
		/* hole, not found */
		if (k->type != BCH_DIRENT)
			break;

		dirent = bkey_i_to_dirent_c(k);

		/* collision? */
		if (!dirent_cmp(dirent, name)) {
			u64 inum = dirent->v.d_inum;

			bch_btree_iter_unlock(&iter);
			pr_debug("found %s: %llu", name->name, inum);
			return inum;
		}
	}
	bch_btree_iter_unlock(&iter);

	pr_debug("%s not found", name->name);
	return 0;
}

int bch_empty_dir(struct cache_set *c, u64 dir_inum)
{
	struct btree_iter iter;
	const struct bkey *k;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, k, POS(dir_inum, 0)) {
		if (k->p.inode > dir_inum)
			break;

		if (k->type == BCH_DIRENT &&
		    k->p.inode == dir_inum) {
			bch_btree_iter_unlock(&iter);
			return -ENOTEMPTY;
		}

	}
	bch_btree_iter_unlock(&iter);

	return 0;
}

int bch_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct cache_set *c = sb->s_fs_info;
	struct btree_iter iter;
	const struct bkey *k;
	const struct bkey_i_dirent *dirent;
	unsigned len;

	if (!dir_emit_dots(file, ctx))
		return 0;

	pr_debug("listing for %lu from %llu", inode->i_ino, ctx->pos);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, k,
			   POS(inode->i_ino, ctx->pos)) {
		if (k->type != BCH_DIRENT)
			continue;

		dirent = bkey_i_to_dirent_c(k);

		pr_debug("saw %llu:%llu (%s) -> %llu",
			 k->p.inode, k->p.offset,
			 dirent->v.d_name, dirent->v.d_inum);

		if (bkey_cmp(k->p, POS(inode->i_ino, ctx->pos)) < 0)
			continue;

		if (k->p.inode > inode->i_ino)
			break;

		len = dirent_name_bytes(dirent);

		pr_debug("emitting %s", dirent->v.d_name);

		/*
		 * XXX: dir_emit() can fault and block, while we're holding locks
		 */
		if (!dir_emit(ctx, dirent->v.d_name, len,
			      dirent->v.d_inum, DT_UNKNOWN))
			break;

		ctx->pos = k->p.offset + 1;
	}
	bch_btree_iter_unlock(&iter);

	return 0;
}
