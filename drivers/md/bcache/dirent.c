
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

#define key_to_dirent(k)	container_of(k, struct bch_dirent, d_key)

#define __dirent_name_bytes(d)						\
	(bkey_bytes(&(d)->d_key) - sizeof(struct bch_dirent))

static unsigned dirent_name_bytes(const struct bch_dirent *d)
{
	unsigned len = __dirent_name_bytes(d);

	while (len && !d->d_name[len - 1])
		--len;

	return len;
}

static int dirent_cmp(const struct bch_dirent *d, const struct qstr *q)
{
	int len = dirent_name_bytes(d);

	return len - q->len ?: memcmp(d->d_name, q->name, len);
}

static bool bch_dirent_invalid(const struct btree_keys *bk,
			       const struct bkey *k)
{
	if (KEY_SIZE(k))
		return true;

	if (KEY_DELETED(k))
		return false;

	if (bkey_bytes(k) < sizeof(struct bch_dirent))
		return true;

	return false;
}

static void bch_dirent_to_text(const struct btree_keys *bk, char *buf,
			       size_t size, const struct bkey *k)
{
	struct bch_dirent *d = key_to_dirent(k);

	scnprintf(buf, size, "%s -> %llu", d->d_name, d->d_inum);
}

const struct btree_keys_ops bch_dirent_ops = {
	.sort_fixup	= bch_generic_sort_fixup,
	.key_invalid	= bch_dirent_invalid,
	.val_to_text	= bch_dirent_to_text,
};

struct create_op {
	struct btree_op		op;
	struct keylist		keys;
	const struct qstr	*name;
	bool			update;
};

static int bch_dirent_create_fn(struct btree_op *b_op, struct btree *b,
				struct bkey *k)
{
	struct create_op *op = container_of(b_op, struct create_op, op);
	struct bkey *new_key = bch_keylist_front(&op->keys);
	struct bch_dirent *new_dirent = key_to_dirent(new_key);
	int ret;

	BUG_ON(bch_keylist_empty(&op->keys));

	/* hole? */
	if (!bch_val_u64s(k)) {
		if (!op->update)
			goto insert;
		return -ENOENT;
	}

	/* collision? */
	if (dirent_cmp(key_to_dirent(k), op->name))
		return MAP_CONTINUE;

	/* found: */
	if (!op->update)
		return -EEXIST;
insert:
	bkey_copy_key(new_key, k);

	ret = bch_btree_insert_node(b, b_op, &op->keys, NULL, NULL, 0);
	BUG_ON(!ret && !bch_keylist_empty(&op->keys));

	if (!ret)
		pr_debug("added %s -> %llu to %llu",
			 new_dirent->d_name,
			 new_dirent->d_inum,
			 KEY_INODE(new_key));

	return ret ?: MAP_DONE;
}

static int __bch_dirent_create(struct cache_set *c, u64 dir_inum,
			       const struct qstr *name, u64 dst_inum,
			       bool update)
{
	struct create_op op;
	struct bkey *k;
	struct bch_dirent *dirent;
	unsigned u64s = DIV_ROUND_UP(sizeof(struct bch_dirent) +
				     name->len, sizeof(u64));
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_DIRENTS, 0);
	bch_keylist_init(&op.keys);
	op.name = name;
	op.update = update;

	if (bch_keylist_realloc(&op.keys, u64s))
		return -ENOMEM;

	k = op.keys.top;
	*k = KEY(dir_inum, bch_dirent_hash(name), 0);
	SET_KEY_U64s(k, u64s);

	dirent = key_to_dirent(k);
	dirent->d_inum = dst_inum;

	memcpy(dirent->d_name, name->name, name->len);
	memset(dirent->d_name + name->len, 0,
	       round_up(name->len, sizeof(u64)) - name->len);

	BUG_ON(dirent_name_bytes(dirent) != name->len);
	BUG_ON(dirent_cmp(dirent, name));

	bch_keylist_enqueue(&op.keys);

	ret = bch_btree_map_keys(&op.op, c, k, bch_dirent_create_fn, MAP_HOLES);

	if (!ret)
		pr_debug("added %llu:%s parent %llu",
			 dst_inum, name->name, dir_inum);

	bch_keylist_free(&op.keys);

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
	return __bch_dirent_create(c, dir_inum, name, dst_inum,
				   true) == MAP_DONE ? 0 : -ENOENT;
}

struct delete_op {
	struct btree_op		op;
	const struct qstr	*name;
};

static int bch_dirent_delete_fn(struct btree_op *b_op, struct btree *b,
				struct bkey *k)
{
	struct delete_op *op = container_of(b_op, struct delete_op, op);
	struct keylist keys;
	int ret;

	/* hole, not found */
	if (!bch_val_u64s(k))
		return -ENOENT;

	/* collision? */
	if (dirent_cmp(key_to_dirent(k), op->name))
		return MAP_CONTINUE;

	/*
	 * XXX
	 * XXX
	 * XXX
	 *
	 * may need to insert a whiteout (this is a hash table with linear
	 * probing)
	 */

	bch_keylist_init(&keys);
	*keys.top = *k;
	SET_KEY_DELETED(keys.top, 1);
	bch_set_val_u64s(keys.top, 0);
	bch_keylist_enqueue(&keys);

	ret = bch_btree_insert_node(b, b_op, &keys, NULL, NULL, 0);
	BUG_ON(!ret && !bch_keylist_empty(&keys));

	return ret;
}

int bch_dirent_delete(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct delete_op op;
	u64 hash = bch_dirent_hash(name);
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_DIRENTS, 0);
	op.name = name;

	pr_debug("deleting %llu:%llu (%s)",
		 dir_inum, hash, name->name);

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(dir_inum, bch_dirent_hash(name), 0),
				 bch_dirent_delete_fn, MAP_HOLES);

	pr_debug("%s %sfound", name->name, ret ? "not " : "");

	return ret;
}

u64 bch_dirent_lookup(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct btree_iter iter;
	struct bkey *k;
	u64 hash = bch_dirent_hash(name);

	pr_debug("searching for %llu:%llu (%s)",
		 dir_inum, hash, name->name);

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_DIRENTS, k,
				 &KEY(dir_inum, bch_dirent_hash(name), 0)) {
		struct bch_dirent *dirent = key_to_dirent(k);

		/* hole, not found */
		if (!bch_val_u64s(k))
			break;

		/* collision? */
		if (!dirent_cmp(dirent, name)) {
			u64 inum = dirent->d_inum;

			btree_iter_unlock(&iter);
			pr_debug("found %s: %llu", name->name, inum);
			return inum;
		}
	}
	btree_iter_unlock(&iter);

	pr_debug("%s not found", name->name);
	return 0;
}

int bch_empty_dir(struct cache_set *c, u64 dir_inum)
{
	struct btree_iter iter;
	struct bkey *k;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, k,
			   &KEY(dir_inum, 0, 0)) {
		struct bch_dirent *dirent = key_to_dirent(k);

		pr_debug("saw %llu:%llu (%s) -> %llu (checking for %llu)",
			 KEY_INODE(k), KEY_OFFSET(k),
			 dirent->d_name, dirent->d_inum, dir_inum);

		if (KEY_INODE(k) > dir_inum)
			break;

		if (KEY_INODE(k) == dir_inum) {
			btree_iter_unlock(&iter);
			return -ENOTEMPTY;
		}

	}
	btree_iter_unlock(&iter);

	return 0;
}

int bch_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct cache_set *c = sb->s_fs_info;
	struct btree_iter iter;
	struct bkey *k;

	if (!dir_emit_dots(file, ctx))
		return 0;

	pr_debug("listing for %lu from %llu", inode->i_ino, ctx->pos);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, k,
			   &KEY(inode->i_ino, ctx->pos, 0)) {
		struct bch_dirent *dirent = key_to_dirent(k);
		unsigned len;

		pr_debug("saw %llu:%llu (%s) -> %llu",
			 KEY_INODE(k), KEY_OFFSET(k),
			 dirent->d_name, dirent->d_inum);

		if (bkey_cmp(k, &KEY(inode->i_ino, ctx->pos, 0)) < 0)
			continue;

		if (KEY_INODE(k) > inode->i_ino)
			break;

		len = dirent_name_bytes(dirent);

		pr_debug("emitting %s", dirent->d_name);

		/*
		 * XXX: dir_emit() can fault and block, while we're holding locks
		 */
		if (!dir_emit(ctx, dirent->d_name, len,
			      dirent->d_inum, DT_UNKNOWN))
			break;

		ctx->pos = KEY_OFFSET(k) + 1;
	}
	btree_iter_unlock(&iter);

	return 0;
}
