#ifndef _BCACHE_XATTR_H
#define _BCACHE_XATTR_H

struct dentry;
struct xattr_handler;

ssize_t bch_xattr_list(struct dentry *, char *, size_t);

extern const struct xattr_handler *bch_xattr_handlers[];

#endif /* _BCACHE_XATTR_H */
