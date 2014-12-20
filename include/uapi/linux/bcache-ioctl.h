#ifndef _LINUX_BCACHE_IOCTL_H
#define _LINUX_BCACHE_IOCTL_H

#include <linux/bcache.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BCH_IOCTL_REGISTER     _IOW('r', 1, char **)
#define BCH_IOCTL_ADD_DISKS    _IOW('a', 2, struct bch_ioctl_add_disks)
#define BCH_IOCTL_RM_DISK      _IOW('r', 3, struct bch_ioctl_rm_disk)
#define BCH_IOCTL_UNREGISTER   _IOW('r', 4, char *)

/* Ioctl interface */

enum BCH_IOCTL {
	BCH_IOCTL_READ			= 3200,
	BCH_IOCTL_WRITE			= 3201,
	BCH_IOCTL_LIST_KEYS		= 3202,

	BCH_IOCTL_INODE_UPDATE		= 3203,
	BCH_IOCTL_INODE_CREATE		= 3204,
	BCH_IOCTL_INODE_DELETE		= 3205,
	BCH_IOCTL_BLOCKDEV_FIND_BY_UUID	= 3206,

	BCH_IOCTL_COPY			= 3207,
	BCH_IOCTL_QUERY_UUID		= 3208,
	BCH_IOCTL_DISCARD		= 3209,

	BCH_IOCTL_VERSIONED_COPY	= 3210,
	BCH_IOCTL_VERSIONED_DISCARD	= 3211,

	BCH_IOCTL_VERSIONED_READ	= 3212,
};

struct bch_ioctl_read {
	__u64			inode;
	__u64			offset;		/* in sectors */
	__u64			sectors;

	__u64			buf;		/* for the data */
};

struct bch_ioctl_write {
	struct bkey		extent;
	__u64			buf;
	__u32			flags;
#define BCH_IOCTL_WRITE_FLUSH		(1 << 0)
#define BCH_IOCTL_WRITE_FUA		(1 << 1)
};

struct bch_ioctl_copy {
	__u64			src_inode;
	__u64			src_offset;	/* in sectors */

	__u64			dst_inode;
	__u64			dst_offset;	/* in sectors */

	__u64			sectors;
};

struct bch_ioctl_discard {
	__u64			inode;
	__u64			offset;		/* in sectors */
	__u64			sectors;
};

struct bch_ioctl_list_keys {
	__u32			btree_id;
	__u32			flags;
#define BCH_IOCTL_LIST_VALUES		(1 << 0)

	struct bkey		start;
	struct bkey		end;

	__u64			buf;
	__u32			buf_size;	/* in bytes */
	__u32			keys_found;	/* in u64s */
};

/* XXX: should not be blockdev inode specific */

struct bch_ioctl_inode_update {
	struct bch_inode_blockdev inode;
};

struct bch_ioctl_inode_create {
	struct bch_inode_blockdev inode;
};

struct bch_ioctl_inode_delete {
	__u64			inum;
};

struct bch_ioctl_blockdev_find_by_uuid {
	__u8			uuid[16];
	struct bch_inode_blockdev inode;
};

/* Returns cache set uuid */
struct bch_ioctl_query_uuid {
	uuid_le			uuid;
};

struct bch_ioctl_versioned_copy {
	__u64			src_inode;
	__u64			src_offset;		/* sectors */

	__u64			dst_inode;
	__u64			dst_offset;		/* sectors */

	__u64			sectors;
	__u64			version;
};

struct bch_ioctl_versioned_discard {
	__u64			inode;
	__u64			offset;		/* in sectors */
	__u64			sectors;
	__u64			version;
};

struct bch_ioctl_add_disks {
	char *const		*devs;
	const char		*uuid;
};

struct bch_ioctl_rm_disk {
	const char		*dev;
	int			force;
};

/*
 * vers_buf is an array of bch_version_record defined in uapi/bcache.h.
 */

struct bch_ioctl_versioned_read {
	struct bch_ioctl_read	read;

	__u64			*vers_buf;	/* for the versions */
	__u64			vers_size;	/* in version records */
	__u64			*vers_found;	/* in version records */
};

#ifdef __cplusplus
}
#endif

#endif /* _LINUX_BCACHE_IOCTL_H */
