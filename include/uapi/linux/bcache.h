#ifndef _LINUX_BCACHE_H
#define _LINUX_BCACHE_H

/*
 * Bcache on disk data structures
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <asm/types.h>
#include <asm/byteorder.h>
#include <linux/uuid.h>

#define BITMASK(name, type, field, offset, end)				\
static const unsigned	name##_OFFSET = offset;				\
static const unsigned	name##_BITS = (end - offset);			\
static const __u64	name##_MAX = (1ULL << (end - offset)) - 1;	\
									\
static inline __u64 name(const type *k)					\
{ return (k->field >> offset) & ~(~0ULL << (end - offset)); }		\
									\
static inline void SET_##name(type *k, __u64 v)				\
{									\
	k->field &= ~(~(~0ULL << (end - offset)) << offset);		\
	k->field |= (v & ~(~0ULL << (end - offset))) << offset;		\
}

/* Btree keys - all units are in sectors */

struct bkey {
	__u64	header;
	/* Word order matches machine byte order */
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __LITTLE_ENDIAN : defined(__LITTLE_ENDIAN)
	__u32	kw[0];
	__u64	k2;
	__u64	k1;
#elif defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	__u64	k1;
	__u64	k2;
	__u32	kw[0];
#else
#error edit for your odd byteorder.
#endif
	__u64	val[];
};

#define BKEY_U64s	(sizeof(struct bkey) / sizeof(__u64))

#define KEY_FIELD(name, field, offset, end)				\
	BITMASK(name, struct bkey, field, offset, end)

#define PTR_FIELD(name, offset, end)					\
static inline __u64 name(const struct bkey *k, unsigned i)		\
{ return (k->val[i] >> offset) & ~(~0ULL << (end - offset)); }		\
									\
static inline void SET_##name(struct bkey *k, unsigned i, __u64 v)	\
{									\
	k->val[i] &= ~(~(~0ULL << (end - offset)) << offset);		\
	k->val[i] |= (v & ~(~0ULL << (end - offset))) << offset;	\
}

#define KEY_OFFSET_BITS		(KEY_OFFSET_H_BITS + KEY_OFFSET_L_BITS)
#define KEY_OFFSET_MAX		(~(~0ULL << KEY_OFFSET_BITS))

KEY_FIELD(KEY_U64s,	header, 56, 64)
KEY_FIELD(KEY_DELETED,	header, 55, 56)
KEY_FIELD(KEY_CACHED,	header, 54, 55)
KEY_FIELD(KEY_CSUM,	header, 52, 54)

/*
 * Sequence number used to determine which extent is the newer one, when dealing
 * with overlapping extents from different servers.
 */
KEY_FIELD(KEY_VERSION,	header, 0,  32)

/* start of actual key: */

KEY_FIELD(KEY_SNAPSHOT,	k2,  0, 20)

KEY_FIELD(KEY_OFFSET_L,	k2, 20, 64)
KEY_FIELD(KEY_OFFSET_H,	k1,  0, 8)

KEY_FIELD(KEY_INODE,	k1, 8,  48)

#define KEY_HIGH_BITS	48
#define KEY_HIGH_MASK	(~(~0ULL << KEY_HIGH_BITS))

/* actual key ends here (don't compare against the rest) */

KEY_FIELD(KEY_SIZE,	k1, 48, 64)	/* Extent size, in sectors */

static inline __u64 KEY_OFFSET(const struct bkey *k)
{
	return KEY_OFFSET_L(k) | (KEY_OFFSET_H(k) << KEY_OFFSET_L_BITS);
}

static inline void SET_KEY_OFFSET(struct bkey *k, __u64 v)
{
	SET_KEY_OFFSET_L(k, v);
	SET_KEY_OFFSET_H(k, v >> KEY_OFFSET_L_BITS);
}

#ifndef __cplusplus

#define KEY(inode, offset, size)					\
((struct bkey) {							\
	.header	= BKEY_U64s << KEY_U64s_OFFSET,				\
	.k1	= (((((__u64) (size)) & KEY_SIZE_MAX) << KEY_SIZE_OFFSET)|\
		   ((((__u64) (inode)) & KEY_INODE_MAX) << KEY_INODE_OFFSET)|\
		   ((((__u64) (offset)) >> KEY_OFFSET_L_BITS) & KEY_OFFSET_H_MAX)),\
	.k2	= ((((__u64) (offset)) & KEY_OFFSET_L_MAX) << KEY_OFFSET_L_OFFSET),\
})

#else

static inline struct bkey KEY(__u64 inode, __u64 offset, __u64 size)
{
	struct bkey ret;

	ret.header = (__u64) BKEY_U64s << KEY_U64s_OFFSET;
	ret.k1 = (((size & KEY_SIZE_MAX) << KEY_SIZE_OFFSET)|
		  ((inode & KEY_INODE_MAX) << KEY_INODE_OFFSET)|
		  ((offset >> KEY_OFFSET_L_BITS) & KEY_OFFSET_H_MAX));
	ret.k2 = (offset & KEY_OFFSET_L_MAX) << KEY_OFFSET_L_OFFSET;

	return ret;
}

#endif

#define ZERO_KEY			KEY(0, 0, 0)
#define MAX_KEY				KEY(~0ULL, ~0ULL, 0)

#define KEY_START(k)			(KEY_OFFSET(k) - KEY_SIZE(k))
#define START_KEY(k)			KEY(KEY_INODE(k), KEY_START(k), 0)

#define PTR_DEV_BITS			12

PTR_FIELD(PTR_GEN,			0,  8)
PTR_FIELD(PTR_OFFSET,			8,  51)
PTR_FIELD(PTR_DEV,			51, 51 + PTR_DEV_BITS)

#define PTR_CHECK_DEV			((1 << PTR_DEV_BITS) - 1)

#define PTR(gen, offset, dev)						\
	((((__u64) dev) << 51) | ((__u64) offset) << 8 | gen)

/* Bkey utility code */

static inline unsigned long bkey_bytes(const struct bkey *k)
{
	return KEY_U64s(k) * sizeof(__u64);
}

#define bkey_copy(_dest, _src)	memcpy(_dest, _src, bkey_bytes(_src))

static inline void bkey_copy_key(struct bkey *dest, const struct bkey *src)
{
	SET_KEY_INODE(dest, KEY_INODE(src));
	SET_KEY_OFFSET(dest, KEY_OFFSET(src));
}

static inline struct bkey *bkey_next(const struct bkey *k)
{
	__u64 *d = (__u64 *) k;
	return (struct bkey *) (d + KEY_U64s(k));
}

static inline struct bkey *bkey_idx(const struct bkey *k, unsigned nr_keys)
{
	__u64 *d = (__u64 *) k;
	return (struct bkey *) (d + nr_keys);
}

#define bset_bkey_last(i)	bkey_idx((struct bkey *) (i)->d, (i)->keys)

#define __BKEY_PADDED(key, pad)					\
	struct { struct bkey key; __u64 key ## _pad[pad]; }

/* Inodes */

#define BLOCKDEV_INODE_MAX	4096

#define BCACHE_ROOT_INO		4096

#define BCACHE_USER_INODE_RANGE	(1ULL << 39)

enum bch_inode_types {
	BCH_INODE_BLOCKDEV	= 0,
	BCH_INODE_FS		= 1,
};

struct bch_inode {
	struct bkey		i_key;
	/* Randomly generated, conceptually similar to a generation number */
	__u64			i_sequence;

	__u16			i_inode_format;
	__u16			i_inode_type;
	__u32			i_flags;

	/* Nanoseconds */
	__s64			i_atime;
	__s64			i_ctime;
	__s64			i_mtime;

	__u64			i_size;

	__u32			i_uid;
	__u32			i_gid;
	__u32			i_nlink;

	__u16			i_mode;
	__u16			i_replicas;	/* target number of replicas */

	__u32			i_dev;
	__u32			pad2;
};

struct bch_inode_blockdev {
	struct bch_inode	i_inode;

	uuid_le			i_uuid;
	__u8			i_label[32];
};

BITMASK(INODE_FLASH_ONLY,	struct bch_inode_blockdev,
				i_inode.i_flags, 0, 1);
BITMASK(INODE_NET,		struct bch_inode_blockdev,
				i_inode.i_flags, 1, 2);

#ifdef __cplusplus
}
// neither __builtin_types_compatible_p nor typeof really works
// in C++, but we can do a much better job with an inlined function

void inline BCH_INODE_INIT(struct bch_inode_blockdev *inode) {
	memset(inode, 0, sizeof(*(inode)));
	SET_KEY_U64s(&(inode)->i_inode.i_key, sizeof(*inode) / sizeof(__u64));
        (inode)->i_inode.i_inode_format = BCH_INODE_BLOCKDEV;
}

extern "C" {
#else

#define BCH_INODE_INIT(inode)					\
do {								\
	struct bch_inode *_i = (void *) inode;			\
								\
	memset(inode, 0, sizeof(*(inode)));			\
	SET_KEY_U64s(&_i->i_key, sizeof(*inode) / sizeof(__u64));\
								\
	if (__builtin_types_compatible_p(typeof(inode),		\
			struct bch_inode *))			\
		_i->i_inode_format = BCH_INODE_FS;		\
	else if (__builtin_types_compatible_p(typeof(inode),	\
			struct bch_inode_blockdev *))		\
		_i->i_inode_format = BCH_INODE_BLOCKDEV;	\
} while (0)
#endif

/* Dirents */

struct bch_dirent {
	struct bkey		d_key;
	__u64			d_inum;
	__u8			d_name[];
};

/* Xattrs */

#define BCH_XATTR_INDEX_USER			0
#define BCH_XATTR_INDEX_POSIX_ACL_ACCESS	1
#define BCH_XATTR_INDEX_POSIX_ACL_DEFAULT	2
#define BCH_XATTR_INDEX_TRUSTED			3
#define BCH_XATTR_INDEX_SECURITY	        4

struct bch_xattr {
	struct bkey		x_key;
	__u8			x_type;
	__u8			x_name_len;
	__u16			x_val_len;
	__u8			x_name[];
};

/* Superblock */

/* Version 0: Cache device
 * Version 1: Backing device
 * Version 2: Seed pointer into btree node checksum
 * Version 3: Cache device with new UUID format
 * Version 4: Backing device with data offset
 */
#define BCACHE_SB_VERSION_CDEV_V0	0
#define BCACHE_SB_VERSION_BDEV		1
#define BCACHE_SB_VERSION_CDEV_WITH_UUID 3
#define BCACHE_SB_VERSION_BDEV_WITH_OFFSET 4
#define BCACHE_SB_VERSION_CDEV_V2	5
#define BCACHE_SB_VERSION_CDEV		5
#define BCACHE_SB_MAX_VERSION		5

#define SB_SECTOR			8
#define SB_SIZE				4096
#define SB_LABEL_SIZE			32
#define SB_JOURNAL_BUCKETS		256U
/* SB_JOURNAL_BUCKETS must be divisible by BITS_PER_LONG */
#define MAX_CACHES_PER_SET		64

#define BDEV_DATA_START_DEFAULT		16	/* sectors */

struct cache_sb {
	__u64			csum;
	__u64			offset;	/* sector where this sb was written */
	__u64			version; /* of on disk format */

	__u8			magic[16];

	uuid_le			uuid;   /* specific to this disk */
	union {
		uuid_le		set_uuid;  /* specific to the cache_set */
		__u64		set_magic; /* xored with magic numbers of other on disk data structs */
	};
	__u8			label[SB_LABEL_SIZE];

	__u64			flags;
	__u64			seq;
	__u64			pad[8];

	union {
	struct {
		/* Cache devices */
		__u64		nbuckets;	/* device size */

		__u16		block_size;	/* sectors */
		__u16		bucket_size;	/* sectors */

		__u16		nr_in_set;
		__u16		nr_this_dev;
	};
	struct {
		/* Backing devices */
		__u64		data_offset;

		/*
		 * block_size from the cache device section is still used by
		 * backing devices, so don't add anything here until we fix
		 * things to not need it for backing devices anymore
		 */
	};
	};

	__u32			last_mount;	/* time_t */

	__u16			first_bucket;   /* index to the first bucket used */
	union {
		__u16		njournal_buckets;
		__u16		keys; /* name simply here for MACRO convenience */
	};
	__u64			d[SB_JOURNAL_BUCKETS];	/* journal buckets */
};

static inline _Bool SB_IS_BDEV(const struct cache_sb *sb)
{
	return sb->version == BCACHE_SB_VERSION_BDEV
		|| sb->version == BCACHE_SB_VERSION_BDEV_WITH_OFFSET;
}

BITMASK(CACHE_SYNC,			struct cache_sb, flags, 0, 1);
BITMASK(CACHE_DISCARD,			struct cache_sb, flags, 1, 2);
BITMASK(CACHE_REPLACEMENT,		struct cache_sb, flags, 2, 5);
#define CACHE_REPLACEMENT_LRU		0U
#define CACHE_REPLACEMENT_FIFO		1U
#define CACHE_REPLACEMENT_RANDOM	2U

BITMASK(CACHE_TIER,			struct cache_sb, flags, 5, 7);
#define CACHE_TIERS			4U

BITMASK(BDEV_CACHE_MODE,		struct cache_sb, flags, 0, 4);
#define CACHE_MODE_WRITETHROUGH		0U
#define CACHE_MODE_WRITEBACK		1U
#define CACHE_MODE_WRITEAROUND		2U
#define CACHE_MODE_NONE			3U
BITMASK(BDEV_STATE,			struct cache_sb, flags, 61, 63);
#define BDEV_STATE_NONE			0U
#define BDEV_STATE_CLEAN		1U
#define BDEV_STATE_DIRTY		2U
#define BDEV_STATE_STALE		3U

/*
 * Magic numbers
 *
 * The various other data structures have their own magic numbers, which are
 * xored with the first part of the cache set's UUID
 */

#define BCACHE_SB_MAGIC			0xca451a4ef67385c6ULL
#define BCACHE_SB_MAGIC2		0x816dba487ff56582ULL
#define JSET_MAGIC			0x245235c1a3625032ULL
#define PSET_MAGIC			0x6750e15f87337f91ULL
#define BSET_MAGIC			0x90135c78b99e07f5ULL

static inline __u64 jset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ JSET_MAGIC;
}

static inline __u64 pset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ PSET_MAGIC;
}

static inline __u64 bset_magic(struct cache_sb *sb)
{
	return sb->set_magic ^ BSET_MAGIC;
}

/*
 * Journal
 *
 * On disk format for a journal entry:
 * seq is monotonically increasing; every journal entry has its own unique
 * sequence number.
 *
 * last_seq is the oldest journal entry that still has keys the btree hasn't
 * flushed to disk yet.
 *
 * version is for on disk format changes.
 */

#define BCACHE_JSET_VERSION_UUIDv1	1
#define BCACHE_JSET_VERSION_UUID	1	/* Always latest UUID format */
#define BCACHE_JSET_VERSION_JKEYS	2
#define BCACHE_JSET_VERSION		2

enum btree_id {
	BTREE_ID_EXTENTS		= 0,
	BTREE_ID_INODES			= 1,
	BTREE_ID_DIRENTS		= 2,
	BTREE_ID_XATTRS			= 3,
	BTREE_ID_NR			= 4,
};

struct jset_keys {
	__u16			keys;
	__u8			btree_id;
	__u8			level;
	__u32			flags; /* designates what this jset holds */

	union {
		struct bkey	start[0];
		__u64		d[0];
	};
};

#define JSET_KEYS_U64s	(sizeof(struct jset_keys) / sizeof(__u64))

BITMASK(JKEYS_TYPE,	struct jset_keys, flags, 0, 2);
#define JKEYS_BTREE_KEYS	0
#define JKEYS_BTREE_ROOT	1
#define JKEYS_PRIO_PTRS		2

struct jset {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys; /* size of d[] in u64s */

	__u64			last_seq; /* of the oldest dirty journal entry */

	__u16			read_clock;
	__u16			write_clock;
	__u32			pad;

	union {
		struct jset_keys start[0];
		__u64		d[0];
	};
};

/* Bucket prios/gens */

struct prio_set {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			pad;

	__u64			next_bucket;

	struct bucket_disk {
		__u16		read_prio;
		__u16		write_prio;
		__u8		gen;
	} __attribute((packed)) data[];
};

/* Btree nodes */

/* Version 1: Seed pointer into btree node checksum
 */
#define BCACHE_BSET_CSUM		1
#define BCACHE_BSET_KEY_v1		2
#define BCACHE_BSET_VERSION		2

/*
 * Btree nodes
 *
 * On disk a btree node is a list/log of these; within each set the keys are
 * sorted
 */
struct bset {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys; /* count of d[] in u64s */

	union {
		struct bkey	start[0];
		__u64		d[0];
	};
};

/* OBSOLETE */

struct bkey_v0 {
	__u64	high;
	__u64	low;
	__u64	ptr[];
};

#define KEY0_FIELD(name, field, offset, size)				\
	BITMASK(name, struct bkey_v0, field, offset, size)

KEY0_FIELD(KEY0_PTRS,		high, 60, 63)
KEY0_FIELD(KEY0_CSUM,		high, 56, 58)
KEY0_FIELD(KEY0_DIRTY,		high, 36, 37)

KEY0_FIELD(KEY0_SIZE,		high, 20, 36)
KEY0_FIELD(KEY0_INODE,		high, 0,  20)

static inline unsigned long bkey_v0_u64s(const struct bkey_v0 *k)
{
	return (sizeof(struct bkey_v0) / sizeof(__u64)) + KEY0_PTRS(k);
}

static inline struct bkey_v0 *bkey_v0_next(const struct bkey_v0 *k)
{
	__u64 *d = (__u64 *) k;
	return (struct bkey_v0 *) (d + bkey_v0_u64s(k));
}

struct jset_v0 {
	__u64			csum;
	__u64			magic;
	__u64			seq;
	__u32			version;
	__u32			keys;

	__u64			last_seq;

	__BKEY_PADDED(uuid_bucket, 4);
	__BKEY_PADDED(btree_root, 4);
	__u16			btree_level;
	__u16			pad[3];

	__u64			prio_bucket[MAX_CACHES_PER_SET];

	union {
		struct bkey	start[0];
		__u64		d[0];
	};
};

/* UUIDS - per backing device/flash only volume metadata */

struct uuid_entry_v0 {
	uuid_le		uuid;
	__u8		label[32];
	__u32		first_reg;
	__u32		last_reg;
	__u32		invalidated;
	__u32		pad;
};

struct uuid_entry {
	union {
		struct {
			uuid_le	uuid;
			__u8	label[32];
			__u32	first_reg;
			__u32	last_reg;
			__u32	invalidated;

			__u32	flags;
			/* Size of flash only volumes */
			__u64	sectors;
		};

		__u8		pad[128];
	};
};

BITMASK(UUID_FLASH_ONLY,	struct uuid_entry, flags, 0, 1);

#ifdef __cplusplus
}
#endif
#endif /* _LINUX_BCACHE_H */
