#ifndef _BCACHE_XATTR_H
#define _BCACHE_XATTR_H

extern const struct btree_keys_ops bch_xattr_ops;
extern const struct bkey_ops bch_bkey_xattr_ops;

struct dentry;
struct xattr_handler;

ssize_t bch_xattr_list(struct dentry *, char *, size_t);

extern const struct xattr_handler *bch_xattr_handlers[];

#endif /* _BCACHE_XATTR_H */
