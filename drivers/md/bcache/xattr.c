
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "xattr.h"

#include "linux/cryptohash.h"
#include "linux/posix_acl_xattr.h"
#include "linux/xattr.h"

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

#define xattr_val(_xattr)	((_xattr)->x_name + (_xattr)->x_name_len)

static int xattr_cmp(const struct bch_xattr *xattr, const struct qstr *q)
{
	int len = xattr->x_name_len;

	return len - q->len ?: memcmp(xattr->x_name, q->name, len);
}

static bool bch_xattr_invalid(const struct cache_set *c, const struct bkey *k)
{
	if (k->type != BCH_XATTR)
		return true;

	if (bkey_bytes(k) < sizeof(struct bkey_i_xattr))
		return true;

	return false;
}

const struct btree_keys_ops bch_xattr_ops = {
	.sort_fixup	= bch_generic_sort_fixup,
};

const struct bkey_ops bch_bkey_xattr_ops = {
	.key_invalid	= bch_xattr_invalid,
};

static int bch_xattr_get(struct dentry *dentry, const char *name,
			 void *buffer, size_t size, int type)
{
	struct cache_set *c = dentry->d_inode->i_sb->s_fs_info;
	struct qstr qname = (struct qstr) QSTR_INIT(name, strlen(name));
	struct btree_iter iter;
	const struct bkey *k;
	const struct bch_xattr *xattr;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_XATTRS, k,
				      POS(dentry->d_inode->i_ino,
					  bch_xattr_hash(&qname))) {
		/* hole, not found */
		if (k->type != BCH_XATTR)
			break;

		xattr = &bkey_i_to_xattr_c(k)->v;

		/* collision? */
		if (!xattr_cmp(xattr, &qname)) {
			if (xattr->x_val_len > size) {
				bch_btree_iter_unlock(&iter);
				return -ERANGE;
			}

			memcpy(buffer, xattr_val(xattr), xattr->x_val_len);
			bch_btree_iter_unlock(&iter);
			return 0;
		}
	}
	bch_btree_iter_unlock(&iter);
	return -ENOENT;
}

static int bch_xattr_set(struct dentry *dentry, const char *name,
			 const void *value, size_t size,
			 int flags, int type)
{
	struct cache_set *c = dentry->d_inode->i_sb->s_fs_info;
	struct btree_iter iter;
	const struct bkey *k;
	struct qstr qname = (struct qstr) QSTR_INIT((char *) name, strlen(name));
	int ret = -ENODATA;

	bch_btree_iter_init(&iter, c, BTREE_ID_XATTRS,
			    POS(dentry->d_inode->i_ino,
				bch_xattr_hash(&qname)));

	while ((k = bch_btree_iter_peek_with_holes(&iter))) {
		struct keylist keys;
		int ret;

		/* hole, not found */
		if (k->type != BCH_XATTR) {
			if (flags & XATTR_REPLACE) {
				ret = -ENODATA;
				break;
			}
		} else {
			const struct bch_xattr *xattr = &bkey_i_to_xattr_c(k)->v;

			/* collision? */
			if (xattr_cmp(xattr, &qname)) {
				bch_btree_iter_advance_pos(&iter);
				continue;
			}

			if (flags & XATTR_CREATE) {
				ret = -EEXIST;
				break;
			}
		}

		bch_keylist_init(&keys);

		bkey_init(keys.top);
		keys.top->p = k->p;

		if (size) {
			struct bch_xattr *xattr;

			keys.top->type = BCH_XATTR;
			set_bkey_val_bytes(keys.top,
					   sizeof(struct bch_xattr) +
					   qname.len + size);

			if (bch_keylist_realloc(&keys, keys.top->u64s)) {
				ret = -ENOMEM;
				break;
			}

			xattr = &bkey_i_to_xattr(keys.top)->v;

			memcpy(xattr->x_name, qname.name, qname.len);
			memcpy(xattr_val(xattr), value, size);

			BUG_ON(xattr_cmp(xattr, &qname));
		} else {
			/* removing */
			set_bkey_deleted(keys.top);
		}

		bch_keylist_enqueue(&keys);

		ret = bch_btree_insert_at(&iter, &keys, NULL, NULL,
					  0, BTREE_INSERT_ATOMIC);
		bch_keylist_free(&keys);

		if (ret != -EINTR && ret != -EAGAIN)
			break;
	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

static const struct xattr_handler *bch_xattr_type_to_handler(unsigned);

static size_t bch_xattr_emit(struct dentry *dentry,
			     const struct bch_xattr *xattr,
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

ssize_t bch_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct cache_set *c = dentry->d_sb->s_fs_info;
	struct btree_iter iter;
	const struct bkey *k;
	const struct bch_xattr *xattr;
	u64 inum = dentry->d_inode->i_ino;
	ssize_t ret = 0;
	size_t len;

	for_each_btree_key(&iter, c, BTREE_ID_XATTRS, k, POS(inum, 0)) {
		BUG_ON(k->p.inode < inum);

		if (k->p.inode > inum)
			break;

		if (k->type != BCH_XATTR)
			continue;

		xattr = &bkey_i_to_xattr_c(k)->v;

		len = bch_xattr_emit(dentry, xattr, buffer, buffer_size);
		if (len > buffer_size) {
			bch_btree_iter_unlock(&iter);
			return -ERANGE;
		}

		ret += len;
		buffer += len;
		buffer_size -= len;

	}
	bch_btree_iter_unlock(&iter);

	return ret;
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
