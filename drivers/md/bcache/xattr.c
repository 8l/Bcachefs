
#include "bcache.h"
#include "btree.h"
#include "xattr.h"

#include "linux/cryptohash.h"
#include "linux/posix_acl_xattr.h"
#include "linux/xattr.h"

#define key_to_xattr(k)	container_of(k, struct bch_xattr, x_key)

static u64 bch_xattr_hash(const struct qstr *name)
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

static void *xattr_val(struct bch_xattr *xattr)
{
	return xattr->x_name + xattr->x_name_len;
}

static int xattr_cmp(const struct bch_xattr *xattr, const struct qstr *q)
{
	int len = xattr->x_name_len;

	return len - q->len ?: memcmp(xattr->x_name, q->name, len);
}

struct xattr_get_op {
	struct btree_op		op;
	unsigned		type;
	struct qstr		name;
	void			*buffer;
	size_t			size;
};

static int bch_xattr_get_fn(struct btree_op *b_op, struct btree *b,
			    struct bkey *k)
{
	struct xattr_get_op *op = container_of(b_op, struct xattr_get_op, op);
	struct bch_xattr *xattr = key_to_xattr(k);

	/* hole, not found */
	if (!bch_val_u64s(k))
		return -ENOENT;

	/* collision? */
	if (xattr_cmp(xattr, &op->name))
		return MAP_CONTINUE;

	if (xattr->x_val_len > op->size)
		return -ERANGE;

	memcpy(op->buffer, xattr_val(xattr), xattr->x_val_len);

	return MAP_DONE;
}

static int bch_xattr_get(struct dentry *dentry, const char *name,
			 void *buffer, size_t size, int type)
{
	struct cache_set *c = dentry->d_inode->i_sb->s_fs_info;
	struct xattr_get_op op;
	int ret;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	bch_btree_op_init(&op.op, BTREE_ID_XATTRS, -1);
	op.type		= type;
	op.name		= (struct qstr) QSTR_INIT(name, strlen(name));
	op.buffer	= buffer;
	op.size		= size;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(dentry->d_inode->i_ino,
				      bch_xattr_hash(&op.name), 0),
				 bch_xattr_get_fn, MAP_HOLES);

	pr_debug("%s %sfound", name, ret ? "not " : "");

	if (ret < 0)
		return ret;

	return 0;
}

struct xattr_set_op {
	struct btree_op		op;
	unsigned		type;
	struct qstr		name;
	const void		*buffer;
	size_t			size;
	int			flags;
};

static int bch_xattr_set_fn(struct btree_op *b_op, struct btree *b,
			    struct bkey *k)
{
	struct xattr_set_op *op = container_of(b_op, struct xattr_set_op, op);
	struct bch_xattr *xattr = key_to_xattr(k);
	struct keylist keys;
	int ret;

	/* hole, not found */
	if (!bch_val_u64s(k)) {
		if (op->flags & XATTR_REPLACE)
			return -ENODATA;
	} else {
		/* collision? */
		if (xattr_cmp(xattr, &op->name))
			return MAP_CONTINUE;

		if (op->flags & XATTR_CREATE)
			return -EEXIST;
	}

	bch_keylist_init(&keys);

	bkey_init(keys.top);
	bkey_copy_key(keys.top, k);

	if (op->size) {
		unsigned u64s = DIV_ROUND_UP(sizeof(struct bch_xattr) +
					     op->name.len + op->size,
					     sizeof(u64));

		if (bch_keylist_realloc(&keys, u64s))
			return -ENOMEM;

		SET_KEY_U64s(keys.top, u64s);

		xattr = key_to_xattr(keys.top);

		memcpy(xattr->x_name, op->name.name, op->name.len);
		memcpy(xattr_val(xattr), op->buffer, op->size);

		BUG_ON(xattr_cmp(xattr, &op->name));
	} else {
		/* removing */
		SET_KEY_DELETED(keys.top, true);
	}

	bch_keylist_push(&keys);

	ret = bch_btree_insert_node_sync(b, b_op, &keys, NULL);
	BUG_ON(!ret && !bch_keylist_empty(&keys));

	bch_keylist_free(&keys);

	return ret ?: MAP_DONE;
}

static int bch_xattr_set(struct dentry *dentry, const char *name,
			 const void *value, size_t size,
			 int flags, int type)
{
	struct cache_set *c = dentry->d_inode->i_sb->s_fs_info;
	struct xattr_set_op op;
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_XATTRS, 0);
	op.type		= type;
	op.name		= (struct qstr) QSTR_INIT((char *) name, strlen(name));
	op.buffer	= value;
	op.size		= size;
	op.flags	= flags;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(dentry->d_inode->i_ino,
				      bch_xattr_hash(&op.name), 0),
				 bch_xattr_set_fn, MAP_HOLES);

	return ret;
}

static const struct xattr_handler *bch_xattr_type_to_handler(unsigned);

static size_t bch_xattr_emit(struct dentry *dentry, struct bch_xattr *xattr,
			     char *buffer, size_t buffer_size)
{
	const struct xattr_handler *handler = bch_xattr_type_to_handler(xattr->x_type);

	return handler
		? handler->list(dentry, buffer, buffer_size,
				xattr->x_name,
				xattr->x_name_len,
				handler->flags)
		: 0;
}

struct xattr_list_op {
	struct btree_op		op;
	struct dentry		*dentry;
	u64			inum;
	char			*buffer;
	size_t			buffer_size;
};

static int bch_xattr_list_fn(struct btree_op *b_op, struct btree *b,
			     struct bkey *k)
{
	struct xattr_list_op *op = container_of(b_op, struct xattr_list_op, op);
	struct bch_xattr *xattr = key_to_xattr(k);
	size_t len;

	BUG_ON(KEY_INODE(k) < op->inum);

	if (KEY_INODE(k) > op->inum)
		return MAP_DONE;

	len = bch_xattr_emit(op->dentry, xattr, op->buffer, op->buffer_size);
	if (len > op->buffer_size)
		return -ERANGE;

	op->buffer += len;
	op->buffer_size -= len;

	return MAP_CONTINUE;
}

ssize_t bch_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct cache_set *c = dentry->d_sb->s_fs_info;
	struct xattr_list_op op;
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_XATTRS, -1);
	op.dentry	= dentry;
	op.inum		= dentry->d_inode->i_ino;
	op.buffer	= buffer;
	op.buffer_size	= buffer_size;

	pr_debug("listing for %llu", op.inum);

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(op.inum, 0, 0),
				 bch_xattr_list_fn, 0);
	return ret < 0 ? ret : buffer_size - op.buffer_size;
}

static size_t bch_vfs_xattr_list(struct dentry *dentry, char *list,
				 size_t list_size, const char *name,
				 size_t name_len, int type)
{
	const struct xattr_handler *handler = bch_xattr_type_to_handler(type);
	const size_t prefix_len = strlen(handler->prefix);
	const size_t total_len = prefix_len + name_len + 1;

	if (list && total_len <= list_size) {
		memcpy(list, handler->prefix, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static const struct xattr_handler bch_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= bch_vfs_xattr_list,
	.get	= bch_xattr_get,
	.set	= bch_xattr_set,
	.flags	= BCH_XATTR_INDEX_USER,
};

static const struct xattr_handler bch_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= bch_vfs_xattr_list,
	.get	= bch_xattr_get,
	.set	= bch_xattr_set,
	.flags	= BCH_XATTR_INDEX_TRUSTED,
};

static const struct xattr_handler bch_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= bch_vfs_xattr_list,
	.get	= bch_xattr_get,
	.set	= bch_xattr_set,
	.flags	= BCH_XATTR_INDEX_SECURITY,
};

static const struct xattr_handler *bch_xattr_handler_map[] = {
	[BCH_XATTR_INDEX_USER]			= &bch_xattr_user_handler,
	[BCH_XATTR_INDEX_POSIX_ACL_ACCESS]	= &posix_acl_access_xattr_handler,
	[BCH_XATTR_INDEX_POSIX_ACL_DEFAULT]	= &posix_acl_default_xattr_handler,
	[BCH_XATTR_INDEX_TRUSTED]		= &bch_xattr_trusted_handler,
	[BCH_XATTR_INDEX_SECURITY]		= &bch_xattr_security_handler,
};

const struct xattr_handler *bch_xattr_handlers[] = {
	&bch_xattr_user_handler,
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	&bch_xattr_trusted_handler,
	&bch_xattr_security_handler,
	NULL
};

static const struct xattr_handler *bch_xattr_type_to_handler(unsigned type)
{
	return type < ARRAY_SIZE(bch_xattr_handler_map)
		? bch_xattr_handler_map[type]
		: NULL;
}
