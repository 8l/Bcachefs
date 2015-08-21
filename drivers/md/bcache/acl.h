/*
  File: fs/bch/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define BCH_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} bch_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} bch_acl_entry_short;

typedef struct {
	__le32		a_version;
} bch_acl_header;

static inline size_t bch_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(bch_acl_header) +
		       count * sizeof(bch_acl_entry_short);
	} else {
		return sizeof(bch_acl_header) +
		       4 * sizeof(bch_acl_entry_short) +
		       (count - 4) * sizeof(bch_acl_entry);
	}
}

static inline int bch_acl_count(size_t size)
{
	ssize_t s;

	size -= sizeof(bch_acl_header);
	s = size - 4 * sizeof(bch_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(bch_acl_entry_short))
			return -1;
		return size / sizeof(bch_acl_entry_short);
	} else {
		if (s % sizeof(bch_acl_entry))
			return -1;
		return s / sizeof(bch_acl_entry) + 4;
	}
}

extern struct posix_acl *bch_get_acl(struct inode *, int);
extern int bch_set_acl(struct inode *, struct posix_acl *, int);
extern int bch_init_acl(struct inode *, struct inode *);
