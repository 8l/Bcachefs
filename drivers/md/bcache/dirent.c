
#include "bcache.h"
#include "btree.h"
#include "extents.h"

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

static bool bch_dirent_invalid(struct btree_keys *bk, struct bkey *k)
{
	if (bkey_bytes(k) < sizeof(struct bch_dirent))
		return true;

	if (KEY_SIZE(k))
		return true;

	return false;
}

static bool bch_dirent_bad(struct btree_keys *bk, struct bkey *k)
{
	return KEY_DELETED(k);
}

static void bch_dirent_to_text(char *buf, size_t size, const struct bkey *k)
{
	struct bch_dirent *d = key_to_dirent(k);
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	// XXX: d->d_name might not be null terminated...
	p("%llu:%llu ver %llu: %s -> %llu",
	  KEY_INODE(k), KEY_OFFSET(k), KEY_VERSION(k),
	  d->d_name, d->d_inum);
}

static void bch_dirent_dump(struct btree_keys *keys, const struct bkey *k)
{
	char buf[80];

	bch_dirent_to_text(buf, sizeof(buf), k);
	printk(" %s\n", buf);
}

const struct btree_keys_ops bch_dirent_ops = {
	.sort_cmp	= bch_generic_sort_cmp,
	.sort_fixup	= bch_generic_sort_fixup,
	.insert_fixup	= bch_generic_insert_fixup,

	.key_invalid	= bch_dirent_invalid,
	.key_bad	= bch_dirent_bad,
	.key_to_text	= bch_dirent_to_text,
	.key_dump	= bch_dirent_dump,
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
	struct bkey *new_key = op->keys.keys;
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

	ret = bch_btree_insert_node(b, b_op, &op->keys, NULL, NULL);
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

	bch_keylist_push(&op.keys);

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
	bkey_copy(keys.top, k);
	SET_KEY_DELETED(keys.top, true);
	bch_keylist_push(&keys);

	ret = bch_btree_insert_node(b, b_op, &keys, NULL, NULL);
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

struct lookup_op {
	struct btree_op		op;
	const struct qstr	*name;
	u64			inum;
};

static int bch_dirent_lookup_fn(struct btree_op *b_op, struct btree *b,
				struct bkey *k)
{
	struct lookup_op *op = container_of(b_op, struct lookup_op, op);
	struct bch_dirent *dirent = key_to_dirent(k);

	/* hole, not found */
	if (!bch_val_u64s(k))
		return -ENOENT;

	/* collision? */
	if (dirent_cmp(dirent, op->name))
		return MAP_CONTINUE;

	op->inum = dirent->d_inum;

	return MAP_DONE;
}

u64 bch_dirent_lookup(struct cache_set *c, u64 dir_inum,
		      const struct qstr *name)
{
	struct lookup_op op;
	u64 hash = bch_dirent_hash(name);
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_DIRENTS, -1);
	op.name = name;

	pr_debug("searching for %llu:%llu (%s)",
		 dir_inum, hash, name->name);

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(dir_inum, bch_dirent_hash(name), 0),
				 bch_dirent_lookup_fn, MAP_HOLES);

	pr_debug("%s %sfound", name->name, ret ? "not " : "");

	if (!ret)
		return op.inum;

	return 0;
}

struct empty_dir_op {
	struct btree_op		op;
	u64			dir_inum;
};

static int bch_empty_dir_fn(struct btree_op *b_op, struct btree *b,
			    struct bkey *k)
{
	struct empty_dir_op *op = container_of(b_op, struct empty_dir_op, op);
	struct bch_dirent *dirent = key_to_dirent(k);

	pr_debug("saw %llu:%llu (%s) -> %llu (checking for %llu)",
		 KEY_INODE(k), KEY_OFFSET(k),
		 dirent->d_name, dirent->d_inum, op->dir_inum);

	if (KEY_INODE(k) > op->dir_inum)
		return MAP_DONE;

	if (KEY_INODE(k) < op->dir_inum)
		return MAP_CONTINUE;

	return -ENOTEMPTY;
}

int bch_empty_dir(struct cache_set *c, u64 dir_inum)
{
	struct empty_dir_op op;
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_DIRENTS, -1);
	op.dir_inum = dir_inum;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(dir_inum, 0, 0),
				 bch_empty_dir_fn, 0);

	return ret == -ENOTEMPTY ? ret : 0;
}

struct readdir_op {
	struct btree_op		op;
	struct dir_context	*ctx;
	u64			inum;
};

static int bch_readdir_fn(struct btree_op *b_op, struct btree *b,
			  struct bkey *k)
{
	struct readdir_op *op = container_of(b_op, struct readdir_op, op);
	struct bch_dirent *dirent = key_to_dirent(k);
	unsigned len;

	pr_debug("saw %llu:%llu (%s) -> %llu",
		 KEY_INODE(k), KEY_OFFSET(k),
		 dirent->d_name, dirent->d_inum);

	if (bkey_cmp(k, &KEY(op->inum, op->ctx->pos, 0)) < 0)
		return MAP_CONTINUE;

	if (KEY_INODE(k) > op->inum)
		return MAP_DONE;

	len = dirent_name_bytes(dirent);

	pr_debug("emitting %s", dirent->d_name);

	/*
	 * XXX: dir_emit() can fault and block, while we're holding locks
	 */
	if (!dir_emit(op->ctx, dirent->d_name, len,
		      dirent->d_inum, DT_UNKNOWN))
		return MAP_DONE;

	op->ctx->pos = KEY_OFFSET(k) + 1;

	return MAP_CONTINUE;
}

int bch_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct cache_set *c = sb->s_fs_info;
	struct readdir_op op;
	int ret;

	if (!dir_emit_dots(file, ctx))
		return 0;

	bch_btree_op_init(&op.op, BTREE_ID_DIRENTS, -1);
	op.ctx = ctx;
	op.inum = inode->i_ino;

	pr_debug("listing for %llu from %llu", op.inum, ctx->pos);

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(op.inum, ctx->pos, 0),
				 bch_readdir_fn, 0);
	return ret < 0 ? ret : 0;
}
