#ifndef _LINUX_BCACHE_H
#define _LINUX_BCACHE_H

/*
 * Bcache on disk data structures
 */

#ifdef __cplusplus
typedef bool _Bool;
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

struct bkey_format {
	__u8		key_u64s;
	__u8		nr_fields;
	/* One unused slot for now: */
	__u8		bits_per_field[6];
	__u64		field_offset[6];
};

/* Btree keys - all units are in sectors */

struct bpos {
	/* Word order matches machine byte order */
#if defined(__LITTLE_ENDIAN)
	__u32		snapshot;
	__u64		offset;
	__u64		inode;
#elif defined(__BIG_ENDIAN)
	__u64		inode;
	__u64		offset;		/* Points to end of extent - sectors */
	__u32		snapshot;
#else
#error edit for your odd byteorder.
#endif
} __attribute__((packed)) __attribute__((aligned(4)));

#define KEY_INODE_MAX			((__u64)~0ULL)
#define KEY_OFFSET_MAX			((__u64)~0ULL)
#define KEY_SNAPSHOT_MAX		((__u32)~0U)

static inline struct bpos POS(__u64 inode, __u64 offset)
{
	struct bpos ret;

	ret.inode	= inode;
	ret.offset	= offset;
	ret.snapshot	= 0;

	return ret;
}

#define POS_MIN				POS(0, 0)
#define POS_MAX				POS(KEY_INODE_MAX, KEY_OFFSET_MAX)

/* Empty placeholder struct, for container_of() */
struct bch_val {
	__u64		__nothing[0];
};

struct bkey_packed {
	__u64		_data[0];

	/* Size of combined key and value, in u64s */
	__u8		u64s;

	/* Format of key (0 for format local to btree node */
	__u8		format;

	/* Type of the value */
	__u8		type;
	__u8		key_start[0];

	/*
	 * We copy bkeys with struct assignment in various places, and while
	 * that shouldn't be done with packed bkeys we can't disallow it in C,
	 * and it's legal to cast a bkey to a bkey_packed  - so padding it out
	 * to the same size as struct bkey should hopefully be safest.
	 */
	__u8		pad[5];
	__u64		pad2[4];
} __attribute__((packed)) __attribute__((aligned(8)));

struct bkey {
	__u64		_data[0];

	/* Size of combined key and value, in u64s */
	__u8		u64s;

	/* Format of key (0 for format local to btree node */
	__u8		format;

	/* Type of the value */
	__u8		type;

	__u8		pad[1];
#if defined(__LITTLE_ENDIAN)
	__u32		version;
	__u32		size;		/* extent size, in sectors */
	struct bpos	p;
#elif defined(__BIG_ENDIAN)
	struct bpos	p;
	__u32		size;		/* extent size, in sectors */
	__u32		version;
#endif
} __attribute__((packed)) __attribute__((aligned(8)));

#define BKEY_U64s			(sizeof(struct bkey) / sizeof(__u64))
#define KEY_PACKED_BITS_START		24

#define KEY_SIZE_MAX			((__u32)~0U)

#define KEY_FORMAT_LOCAL_BTREE		0
#define KEY_FORMAT_CURRENT		1

enum bch_bkey_fields {
	BKEY_FIELD_INODE,
	BKEY_FIELD_OFFSET,
	BKEY_FIELD_SNAPSHOT,
	BKEY_FIELD_SIZE,
	BKEY_FIELD_VERSION,
	BKEY_NR_FIELDS,
};

#define bkey_format_field(name, field)					\
	[BKEY_FIELD_##name] = (sizeof(((struct bkey *) NULL)->field) * 8)

#define BKEY_FORMAT_CURRENT						\
((struct bkey_format) {							\
	.key_u64s	= BKEY_U64s,					\
	.nr_fields	= BKEY_NR_FIELDS,				\
	.bits_per_field = {						\
		bkey_format_field(INODE,	p.inode),		\
		bkey_format_field(OFFSET,	p.offset),		\
		bkey_format_field(SNAPSHOT,	p.snapshot),		\
		bkey_format_field(SIZE,		size),			\
		bkey_format_field(VERSION,	version),		\
	},								\
})

/* bkey with inline value */
struct bkey_i {
	struct bkey	k;
	struct bch_val	v;
};

#ifndef __cplusplus

#define KEY(_inode, _offset, _size)					\
((struct bkey) {							\
	.u64s		= BKEY_U64s,					\
	.format		= KEY_FORMAT_CURRENT,				\
	.p		= POS(_inode, _offset),				\
	.size		= _size,					\
})

#else

static inline struct bkey KEY(__u64 inode, __u64 offset, __u64 size)
{
	struct bkey ret;

	memset(&ret, 0, sizeof(ret));
	ret.u64s	= BKEY_U64s;
	ret.format	= KEY_FORMAT_CURRENT;
	ret.p.inode	= inode;
	ret.p.offset	= offset;
	ret.size	= size;

	return ret;
}

#endif

static inline void bkey_init(struct bkey *k)
{
	*k = KEY(0, 0, 0);
}

#define bkey_bytes(_k)		((_k)->u64s * sizeof(__u64))

static inline void bkey_copy(struct bkey_i *dst, const struct bkey_i *src)
{
	memcpy(dst, src, bkey_bytes(&src->k));
}

#define __BKEY_PADDED(key, pad)					\
	struct { struct bkey_i key; __u64 key ## _pad[pad]; }

#define BKEY_VAL_TYPE(name, nr)						\
struct bkey_i_##name {							\
	union {								\
		struct bkey		k;				\
		struct bkey_i		k_i;				\
	};								\
	struct bch_##name		v;				\
}

/*
 * - DELETED keys are used internally to mark keys that should be ignored but
 *   override keys in composition order.  Their version number is ignored.
 *
 * - DISCARDED keys indicate that the data is all 0s because it has been
 *   discarded. DISCARDs may have a version; if the version is nonzero the key
 *   will be persistent, otherwise the key will be dropped whenever the btree
 *   node is rewritten (like DELETED keys).
 *
 * - ERROR: any read of the data returns a read error, as the data was lost due
 *   to a failing device. Like DISCARDED keys, they can be removed (overridden)
 *   by new writes or cluster-wide GC. Node repair can also overwrite them with
 *   the same or a more recent version number, but not with an older version
 *   number.
*/
#define KEY_TYPE_DELETED		0
#define KEY_TYPE_DISCARD		1
#define KEY_TYPE_ERROR			2
#define KEY_TYPE_COOKIE			3
#define KEY_TYPE_GENERIC_NR		128

struct bch_cookie {
	struct bch_val		v;
	__u64			cookie;
};
BKEY_VAL_TYPE(cookie,		KEY_TYPE_COOKIE);

/* Extents */

/*
 * bcache keys index the end of the extent as the offset
 * The end is exclusive, while the start is inclusive
 */

struct bch_extent_ptr {
	__u64			_val;
};

BITMASK(PTR_GEN,	struct bch_extent_ptr, _val, 0,  8);
BITMASK(PTR_DEV,	struct bch_extent_ptr, _val, 8,  16);
BITMASK(PTR_OFFSET,	struct bch_extent_ptr, _val, 16, 63);

/* high bit of the first pointer is used for EXTENT_CACHED, blech */

static inline struct bch_extent_ptr PTR(__u64 gen, __u64 offset, __u64 dev)
{
	return (struct bch_extent_ptr) {
		._val = ((gen		<< PTR_GEN_OFFSET) |
			 (dev		<< PTR_DEV_OFFSET) |
			 (offset	<< PTR_OFFSET_OFFSET))
	};
}

/* Dummy DEV numbers: */

#define PTR_LOST_DEV			PTR_DEV_MAX

enum {
	BCH_EXTENT		= 128,
};

struct bch_extent {
	struct bch_val		v;
	struct bch_extent_ptr	ptr[0];
	__u64			data[0]; /* hack for EXTENT_CACHED */
};
BKEY_VAL_TYPE(extent,		BCH_EXTENT);

BITMASK(EXTENT_CACHED, struct bch_extent, data[0], 63, 64)

/* Inodes */

#define BLOCKDEV_INODE_MAX	4096

enum bch_inode_types {
	BCH_INODE_FS		= 128,
	BCH_INODE_BLOCKDEV	= 129,
};

enum {
	BCH_FS_PRIVATE_START		= 16,
	__BCH_INODE_I_SIZE_DIRTY	= 16,
};

#define BCH_FL_USER_FLAGS	((1U << BCH_FS_PRIVATE_START) - 1)

#define BCH_INODE_I_SIZE_DIRTY	(1 << __BCH_INODE_I_SIZE_DIRTY)

struct bch_inode {
	struct bch_val		v;

	__u16			i_mode;
	__u16			pad;
	__u32			i_flags;

	/* Nanoseconds */
	__s64			i_atime;
	__s64			i_ctime;
	__s64			i_mtime;

	__u64			i_size;

	__u32			i_uid;
	__u32			i_gid;
	__u32			i_nlink;

	__u32			i_dev;
};
BKEY_VAL_TYPE(inode,		BCH_INODE_FS);

struct bch_inode_blockdev {
	struct bch_val		v;
	struct bch_inode	i_inode;

	uuid_le			i_uuid;
	__u8			i_label[32];
} __packed;
BKEY_VAL_TYPE(inode_blockdev,	BCH_INODE_BLOCKDEV);

BITMASK(INODE_FLASH_ONLY,	struct bch_inode_blockdev,
				i_inode.i_flags, 0, 1);

/* Superblock */

/* Version 0: Cache device
 * Version 1: Backing device
 * Version 2: Seed pointer into btree node checksum
 * Version 3: Cache device with new UUID format
 * Version 4: Backing device with data offset
 * Version 5: All the incompat changes
 * Version 6: Cache device UUIDs all in superblock, another incompat bset change
 */
#define BCACHE_SB_VERSION_CDEV_V0	0
#define BCACHE_SB_VERSION_BDEV		1
#define BCACHE_SB_VERSION_CDEV_WITH_UUID 3
#define BCACHE_SB_VERSION_BDEV_WITH_OFFSET 4
#define BCACHE_SB_VERSION_CDEV_V2	5
#define BCACHE_SB_VERSION_CDEV_V3	6
#define BCACHE_SB_VERSION_CDEV		6
#define BCACHE_SB_MAX_VERSION		6

#define SB_SECTOR			8
#define SB_LABEL_SIZE			32
#define MAX_CACHES_PER_SET		64

#define BDEV_DATA_START_DEFAULT		16	/* sectors */

struct cache_member {
	uuid_le			uuid;
	__u64			nbuckets;	/* device size */
	__u16			first_bucket;   /* index of first bucket used */
	__u16			bucket_size;	/* sectors */
	__u32			last_mount;	/* time_t */

	__u64			f1;
	__u64			f2;
};

BITMASK(CACHE_STATE,		struct cache_member, f1, 0,  4)
#define CACHE_ACTIVE			0U
#define CACHE_RO			1U
#define CACHE_FAILED			2U
#define CACHE_SPARE			3U

BITMASK(CACHE_TIER,		struct cache_member, f1, 4,  8)
#define CACHE_TIERS			4U

BITMASK(CACHE_REPLICATION_SET,	struct cache_member, f1, 8,  16)

BITMASK(CACHE_HAS_METADATA,	struct cache_member, f1, 24, 25)
BITMASK(CACHE_HAS_DATA,		struct cache_member, f1, 25, 26)

BITMASK(CACHE_REPLACEMENT,	struct cache_member, f1, 26, 30)
#define CACHE_REPLACEMENT_LRU		0U
#define CACHE_REPLACEMENT_FIFO		1U
#define CACHE_REPLACEMENT_RANDOM	2U

BITMASK(CACHE_DISCARD,		struct cache_member, f1, 30, 31);

BITMASK(CACHE_NR_READ_ERRORS,	struct cache_member, f2, 0,  20);
BITMASK(CACHE_NR_WRITE_ERRORS,	struct cache_member, f2, 20, 40);

struct cache_sb {
	__u64			csum;
	__u64			offset;	/* sector where this sb was written */
	__u64			version; /* of on disk format */

	uuid_le			magic;	/* bcache superblock UUID */

	/* Identifies this disk within the cache set: */
	uuid_le			disk_uuid;

	/*
	 * Internal cache set UUID - xored with various magic numbers and thus
	 * must never change:
	 */
	union {
		uuid_le		set_uuid;
		__u64		set_magic;
	};

	__u8			label[SB_LABEL_SIZE];

	__u64			flags;

	/* Incremented each time superblock is written: */
	__u64			seq;

	/*
	 * User visible UUID for identifying the cache set the user is allowed
	 * to change:
	 */
	uuid_le			user_uuid;
	__u64			pad[6];

	union {
	struct {
		/* Cache devices */

		/* Number of cache_member entries: */
		__u8		nr_in_set;

		/*
		 * Index of this device - for PTR_DEV(), and also this device's
		 * slot in the cache_member array:
		 */
		__u8		nr_this_dev;
	};
	struct {
		/* Backing devices */
		__u64		bdev_data_offset;
	};
	};

	__u16			block_size;	/* sectors */
	__u16			pad2[3];

	__u32			bdev_last_mount;	/* time_t */
	__u16			pad3;
	__u16			u64s;	/* size of variable length portion */

	union {
		struct cache_member	members[0];
		/*
		 * Journal buckets also in the variable length portion, after
		 * the member info:
		 */
		__u64			_data[0];
	};
};

BITMASK(CACHE_SYNC,			struct cache_sb, flags, 0, 1);

BITMASK(CACHE_ERROR_ACTION,		struct cache_sb, flags, 1, 4);
#define BCH_ON_ERROR_CONTINUE		0U
#define BCH_ON_ERROR_RO			1U
#define BCH_ON_ERROR_PANIC		2U

BITMASK(CACHE_SET_META_REPLICAS_WANT,	struct cache_sb, flags, 4, 8);
BITMASK(CACHE_SET_DATA_REPLICAS_WANT,	struct cache_sb, flags, 8, 12);

BITMASK(CACHE_SB_CSUM_TYPE,		struct cache_sb, flags, 12, 16);
BITMASK(CACHE_PREFERRED_CSUM_TYPE,	struct cache_sb, flags, 16, 20);
#define BCH_CSUM_NONE			0U
#define BCH_CSUM_CRC32C			1U
#define BCH_CSUM_CRC64			2U
#define BCH_CSUM_NR			3U

/* Node size for variable sized buckets */
BITMASK(CACHE_BTREE_NODE_SIZE,		struct cache_sb, flags, 20, 36);

BITMASK(CACHE_SET_META_REPLICAS_HAVE,	struct cache_sb, flags, 36, 40);
BITMASK(CACHE_SET_DATA_REPLICAS_HAVE,	struct cache_sb, flags, 40, 44);

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

static inline unsigned bch_journal_buckets_offset(struct cache_sb *sb)
{
	return sb->nr_in_set * (sizeof(struct cache_member) / sizeof(__u64));
}

static inline unsigned bch_nr_journal_buckets(struct cache_sb *sb)
{
	return sb->u64s - bch_journal_buckets_offset(sb);
}

static inline _Bool __SB_IS_BDEV(__u64 version)
{
	return version == BCACHE_SB_VERSION_BDEV
		|| version == BCACHE_SB_VERSION_BDEV_WITH_OFFSET;
}

static inline _Bool SB_IS_BDEV(const struct cache_sb *sb)
{
	return __SB_IS_BDEV(sb->version);
}

/*
 * Magic numbers
 *
 * The various other data structures have their own magic numbers, which are
 * xored with the first part of the cache set's UUID
 */

#define BCACHE_MAGIC							\
	UUID_LE(0xf67385c6, 0x1a4e, 0xca45,				\
		0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81)

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

#define DEFINE_BCH_BTREE_IDS()					\
	DEF_BTREE_ID(EXTENTS, 0, "extents")			\
	DEF_BTREE_ID(INODES,  1, "inodes")

#define DEF_BTREE_ID(kwd, val, name) BTREE_ID_##kwd = val,

enum btree_id {
	DEFINE_BCH_BTREE_IDS()
	BTREE_ID_NR
};

#undef DEF_BTREE_ID

struct jset_entry {
	__u16			u64s;
	__u8			btree_id;
	__u8			level;
	__u32			flags; /* designates what this jset holds */

	union {
		struct bkey_i	start[0];
		__u64		_data[0];
	};
};

#define JSET_KEYS_U64s	(sizeof(struct jset_entry) / sizeof(__u64))


BITMASK(JKEYS_TYPE,	struct jset_entry, flags, 0, 8);
enum {
	JKEYS_BTREE_KEYS		= 0,
	JKEYS_BTREE_ROOT		= 1,
	JKEYS_PRIO_PTRS			= 2,

	/*
	 * Journal sequence numbers can be blacklisted: bsets record the max
	 * sequence number of all the journal entries they contain updates for,
	 * so that on recovery we can ignore those bsets that contain index
	 * updates newer that what made it into the journal.
	 *
	 * This means that we can't reuse that journal_seq - we have to skip it,
	 * and then record that we skipped it so that the next time we crash and
	 * recover we don't think there was a missing journal entry.
	 */
	JKEYS_JOURNAL_SEQ_BLACKLISTED	= 3,
};

struct jset {
	__u64			csum;
	__u64			magic;
	__u32			version;
	__u32			flags;

	/* Sequence number of oldest dirty journal entry */
	__u64			seq;
	__u64			last_seq;

	__u16			read_clock;
	__u16			write_clock;
	__u32			u64s; /* size of d[] in u64s */

	union {
		struct jset_entry start[0];
		__u64		_data[0];
	};
};

BITMASK(JSET_CSUM_TYPE,		struct jset, flags, 0, 4);

/* Bucket prios/gens */

struct prio_set {
	__u64			csum;
	__u64			magic;
	__u32			version;
	__u32			flags;

	__u64			next_bucket;

	struct bucket_disk {
		__u16		read_prio;
		__u16		write_prio;
		__u8		gen;
	} __attribute((packed)) data[];
};

BITMASK(PSET_CSUM_TYPE,		struct prio_set, flags, 0, 4);

/* Btree nodes */

/* Version 1: Seed pointer into btree node checksum
 */
#define BCACHE_BSET_CSUM		1
#define BCACHE_BSET_KEY_v1		2
#define BCACHE_BSET_JOURNAL_SEQ		3
#define BCACHE_BSET_VERSION		3

/*
 * Btree nodes
 *
 * On disk a btree node is a list/log of these; within each set the keys are
 * sorted
 */
struct bset {
	__u64			seq;

	/*
	 * Highest journal entry this bset contains keys for.
	 * If on recovery we don't see that journal entry, this bset is ignored:
	 * this allows us to preserve the order of all index updates after a
	 * crash, since the journal records a total order of all index updates
	 * and anything that didn't make it to the journal doesn't get used.
	 */
	__u64			journal_seq;

	__u32			flags;
	__u16			version;
	__u16			u64s; /* count of d[] in u64s */

	union {
		struct bkey_packed start[0];
		__u64		_data[0];
	};
} __attribute((packed));

BITMASK(BSET_CSUM_TYPE,		struct bset, flags, 0, 4);

/* Only used in first bset */
BITMASK(BSET_BTREE_LEVEL,	struct bset, flags, 4, 8);

struct btree_node {
	__u64			csum;
	__u64			magic;

	/* Closed interval: */
	struct bpos		min_key;
	struct bpos		max_key;
	struct bkey_format	format;

	struct bset		keys;
} __attribute((packed));

struct btree_node_entry {
	__u64			csum;
	struct bset		keys;
} __attribute((packed));

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
