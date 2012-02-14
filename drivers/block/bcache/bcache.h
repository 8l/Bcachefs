
#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/bio.h>
#include <linux/blktrace_api.h>
#include <linux/closure.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "util.h"

#include <linux/dynamic_fault.h>

struct bucket {
	atomic_t	pin;
	uint16_t	prio;
	uint8_t		gen;
	uint8_t		disk_gen;
	uint8_t		last_gc; /* Most out of date gen in the btree */
	uint8_t		gc_gen;

#define GC_MARK_DIRTY	-1
#define GC_MARK_BTREE	-2
	short		mark;
};

struct bkey {
	uint64_t	header;
	uint64_t	key;
	uint64_t	ptr[];
};

#define BKEY_PADDED(key)					\
	union { struct bkey key; uint64_t key ## _pad[8]; }

/* Version 1: Backing device
 * Version 2: Seed pointer into btree node checksum
 * Version 3: New UUID format
 */
#define BCACHE_SB_VERSION	3

#define SB_SECTOR		8
#define SB_SIZE			4096
#define SB_LABEL_SIZE		32
#define SB_JOURNAL_BUCKETS	256
/* SB_JOURNAL_BUCKETS must be divisible by BITS_PER_LONG */
#define MAX_CACHES_PER_SET	8

struct cache_sb {
	uint64_t		csum;
	uint64_t		offset;	/* sector where this sb was written */
	uint64_t		version;
#define CACHE_BACKING_DEV	1

	uint8_t			magic[16];

	uint8_t			uuid[16];
	union {
		uint8_t		set_uuid[16];
		uint64_t	set_magic;
	};
	uint8_t			label[SB_LABEL_SIZE];

	uint64_t		flags;
	uint64_t		seq;
	uint64_t		pad[8];

	uint64_t		nbuckets;	/* device size */
	uint16_t		block_size;	/* sectors */
	uint16_t		bucket_size;	/* sectors */

	uint16_t		nr_in_set;
	uint16_t		nr_this_dev;

	uint32_t		last_mount;	/* time_t */

	uint16_t		first_bucket;
	union {
		uint16_t	njournal_buckets;
		uint16_t	keys;
	};
	uint64_t		d[SB_JOURNAL_BUCKETS];	/* journal buckets */
};

BITMASK(CACHE_SYNC,		struct cache_sb, flags, 0, 1);
BITMASK(CACHE_DISCARD,		struct cache_sb, flags, 1, 1);
BITMASK(CACHE_REPLACEMENT,	struct cache_sb, flags, 2, 3);
#define CACHE_REPLACEMENT_LRU	0U
#define CACHE_REPLACEMENT_FIFO	1U
#define CACHE_REPLACEMENT_RANDOM 2U
BITMASK(CACHE_ASYNC_JOURNAL,	struct cache_sb, flags, 5, 1);

BITMASK(BDEV_CACHE_MODE,	struct cache_sb, flags, 0, 4);
#define CACHE_MODE_WRITETHROUGH	0U
#define CACHE_MODE_WRITEBACK	1U
#define CACHE_MODE_WRITEAROUND	2U
#define CACHE_MODE_NONE		3U
BITMASK(BDEV_STATE,		struct cache_sb, flags, 61, 2);
#define BDEV_STATE_NONE		0U
#define BDEV_STATE_CLEAN	1U
#define BDEV_STATE_DIRTY	2U
#define BDEV_STATE_STALE	3U

/* Version 1: Seed pointer into btree node checksum
 */
#define BCACHE_BSET_VERSION	1

/*
 * This is the on disk format for btree nodes - a btree node on disk is a list
 * of these; within each set the keys are sorted
 */
struct bset {
	uint64_t		csum;
	uint64_t		magic;
	uint64_t		seq;
	uint32_t		version;
	uint32_t		keys;

	union {
		struct bkey	start[0];
		uint64_t	d[0];
	};
};

/*
 * On disk format for priorities and gens - see super.c near prio_write() for
 * more.
 */
struct prio_set {
	uint64_t		csum;
	uint64_t		magic;
	uint64_t		seq;
	uint32_t		version;
	uint32_t		pad;

	uint64_t		next_bucket;

	struct bucket_disk {
		uint16_t	prio;
		uint8_t		gen;
	} __attribute((packed)) data[];
};

#include "journal.h"
#include "stats.h"
struct search;

struct bcache_device {
	struct kobject		kobj;

	struct cache_set	*c;
	unsigned		id;
	struct gendisk		*disk;

	/* If nonzero, we're closing */
	atomic_t		closing;

	atomic_long_t		sectors_dirty;
	unsigned long		sectors_dirty_gc;
	unsigned long		sectors_dirty_last;
	int64_t			sectors_dirty_derivative;

	mempool_t		*unaligned_bvec;
	struct bio_set		*bio_split;

	unsigned		data_csum:1;

	int (*cache_miss)(struct search *, struct bio *, unsigned);
	int (*ioctl) (struct bcache_device *, fmode_t, unsigned, unsigned long);
};

struct io {
	/* Used to track sequential IO so it can be skipped */
	struct hlist_node	hash;
	struct list_head	lru;

	unsigned long		jiffies;
	unsigned		sequential;
	sector_t		last;
};

struct dirty_io {
	struct closure		cl;
	struct cached_dev	*d;
	struct bio		bio;
};

struct dirty {
	struct rb_node		node;
	BKEY_PADDED(key);
	struct dirty_io		*io;
};

struct cached_dev {
	struct list_head	list;
	struct bcache_device	disk;
	struct block_device	*bdev;

	struct cache_sb		sb;
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];
	struct closure_with_waitlist sb_write;

	/* Refcount on the cache set. Always nonzero when we're caching. */
	atomic_t		count;
	struct work_struct	detach;

	/* If nonzero, we're disabling caching */
	atomic_t		detaching;

	/*
	 * Device might not be running if it's dirty and the cache set hasn't
	 * showed up yet.
	 */
	atomic_t		running;

	mempool_t		*bio_passthrough;

	/*
	 * Writes take a shared lock from start to finish; scanning for dirty
	 * data to refill the rb tree requires an exclusive lock.
	 */
	struct rw_semaphore	writeback_lock;

	/*
	 * Beginning and end of range in dirty rb tree - so that we can skip
	 * taking dirty_lock and checking the rb tree. Protected by
	 * writeback_lock.
	 */
	sector_t		writeback_start;
	sector_t		writeback_end;

	struct rb_root		dirty;
	spinlock_t		dirty_lock;

	/*
	 * Nonzero, and writeback has a refcount (d->count), iff there is dirty
	 * data in the cache. Protected by writeback_lock; must have an
	 * shared lock to set and exclusive lock to clear.
	 */
	atomic_t		has_dirty;

	uint64_t		next_writeback_io;
	unsigned		writeback_rate;
	struct delayed_work	writeback_rate_update;

	/*
	 * Internal to the writeback code, so refill_dirty() and read_dirty()
	 * can keep track of where they're at.
	 */
	sector_t		last_found;
	sector_t		last_read;

	/* Number of writeback bios in flight */
	atomic_t		in_flight;
	struct delayed_work	refill_dirty;
	struct delayed_work	read_dirty;

#define WRITEBACK_SLURP	100
	DECLARE_ARRAY_ALLOCATOR(struct dirty, dirty_freelist, WRITEBACK_SLURP);

	/* For tracking sequential IO */
#define RECENT_IO_BITS	7
#define RECENT_IO	(1 << RECENT_IO_BITS)
	struct io		io[RECENT_IO];
	struct hlist_head	io_hash[RECENT_IO + 1];
	struct list_head	io_lru;
	spinlock_t		io_lock;

	struct cache_accounting	accounting;

	/* The rest of this all shows up in sysfs */
	unsigned long		sequential_cutoff;
	unsigned		readahead;

	unsigned		sequential_merge:1;
	unsigned		verify:1;

	unsigned		writeback_metadata:1;
	unsigned		writeback_running:1;
	unsigned char		writeback_percent;
	unsigned		writeback_delay;
};

struct cache {
	struct cache_set	*set;
	struct cache_sb		sb;
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];

	struct kobject		kobj;
	struct block_device	*bdev;

	/* XXX: move to cache_set */
	struct dentry		*debug;

	/* XXX: replace with bios allocated from bio_meta mempool */
	struct bio		*uuid_bio;

	struct closure		prio;
	/* XXX: replace with bios allocated from bio_meta mempool */
	struct bio		*prio_bio;
	struct prio_set		*disk_buckets;

	/*
	 * When allocating new buckets, prio_write() gets first dibs - since we
	 * may not be allocate at all without writing priorities and gens.
	 * prio_buckets[] contains the last buckets we wrote priorities to (so
	 * gc can mark them as metadata), prio_next[] contains the buckets
	 * allocated for the next prio write.
	 */
	uint64_t		*prio_buckets;
	uint64_t		*prio_next;
	unsigned		prio_write;
	unsigned		prio_alloc;

	/* > 0: buckets in free_inc have been marked as free
	 * = 0: buckets in free_inc can't be used until priorities are written
	 * < 0: priority write in progress
	 */
	atomic_t		prio_written;

	/* Allocation stuff: */
	struct bucket		*buckets;

	DECLARE_HEAP(struct bucket *, heap);

	/*
	 * max(gen - disk_gen) for all buckets. When it gets too big we have to
	 * call prio_write() to keep gens from wrapping.
	 */
	uint8_t			need_save_prio;

	/*
	 * If nonzero, we know we aren't going to find any buckets to invalidate
	 * until a gc finishes - otherwise we could pointlessly burn a ton of
	 * cpu
	 */
	unsigned		invalidate_needs_gc:1;

	size_t			fifo_last_bucket;

	DECLARE_FIFO(long, free);
	DECLARE_FIFO(long, free_inc);
	DECLARE_FIFO(long, unused);

	bool			discard; /* Get rid of? */
	struct list_head	discards;
	struct page		*discard_page;

	struct journal_device	journal;

	/* The rest of this all shows up in sysfs */
#define IO_ERROR_SHIFT		20
	atomic_t		io_errors;
	atomic_t		io_count;

	atomic_long_t		meta_sectors_written;
	atomic_long_t		btree_sectors_written;
	atomic_long_t		sectors_written;
};

struct gc_stat {
	size_t			nodes;
	size_t			key_bytes;

	size_t			nkeys;
	uint64_t		data;	/* sectors */
	uint64_t		dirty;	/* sectors */
	unsigned		in_use; /* percent */
};

struct cache_set {
	struct closure		cl;

	struct list_head	list;
	struct kobject		kobj;
	struct kobject		internal;
	struct cache_accounting accounting;
	atomic_t		closing;

	struct cache_sb		sb;

	struct cache		*cache[MAX_CACHES_PER_SET];
	struct cache		*cache_by_alloc[MAX_CACHES_PER_SET];
	int			caches_loaded;

	struct bcache_device	**devices;
	struct list_head	cached_devs;
	uint64_t		cached_dev_sectors;
	struct closure		caching;

	struct closure_with_waitlist sb_write;

	mempool_t		*search;
	mempool_t		*bio_meta;
	struct bio_set		*bio_split;

	/* For the btree cache */
	struct shrinker		shrink;

	/* For the btree cache and anything allocation related */
	struct mutex		bucket_lock;

	/* log2(bucket_size), in sectors */
	unsigned short		bucket_bits;

	/* log2(block_size), in sectors */
	unsigned short		block_bits;

	/*
	 * Default number of pages for a new btree node - may be less than a
	 * full bucket
	 */
	unsigned		btree_pages;

	/*
	 * Lists of struct btrees; lru is the list for structs that have memory
	 * allocated for actual btree node, freed is for structs that do not.
	 */
	struct list_head	btree_cache;
	struct list_head	btree_cache_freeable;
	struct list_head	btree_cache_freed;

	/* Number of elements in btree_cache + btree_cache_freeable lists */
	unsigned		bucket_cache_used;

	/*
	 * If we need to allocate memory for a new btree node and that
	 * allocation fails, we can cannibalize another node in the btree cache
	 * to satisfy the allocation. However, only one thread can be doing this
	 * at a time, for obvious reasons - try_harder and try_wait are
	 * basically a lock for this that we can wait on asynchronously. The
	 * btree_root() macro releases the lock when it returns.
	 */
	struct closure		*try_harder;
	closure_list_t		try_wait;
	uint64_t		try_harder_start;

	/*
	 * When we free a btree node, we increment the gen of the bucket the
	 * node is in - but we can't rewrite the prios and gens until we
	 * finished whatever it is we were doing, otherwise after a crash the
	 * btree node would be freed but for say a split, we might not have the
	 * pointers to the new nodes inserted into the btree yet.
	 *
	 * This is a refcount that blocks prio_write() until the new keys are
	 * written.
	 */
	atomic_t		prio_blocked;
	closure_list_t		bucket_wait;

	/*
	 * For any bio we don't skip we subtract the number of sectors from
	 * rescale; when it hits 0 we rescale all the bucket priorities.
	 */
	atomic_t		rescale;
	/*
	 * When we invalidate buckets, we use both the priority and the amount
	 * of good data to determine which buckets to reuse first - to weight
	 * those together consistently we keep track of the smallest nonzero
	 * priority of any bucket.
	 */
	uint16_t		min_prio;

	/*
	 * max(gen - gc_gen) for all buckets. When it gets too big we have to gc
	 * to keep gens from wrapping around.
	 */
	uint8_t			need_gc;
	struct gc_stat		gc_stats;
	size_t			nbuckets;

	struct closure_with_waitlist gc;
	/* Where in the btree gc currently is */
	struct bkey		gc_done;

	/*
	 * The allocation code needs gc_mark in struct bucket to be correct, but
	 * it's not while a gc is in progress. Protected by bucket_lock.
	 */
	int			gc_mark_valid;

	/* Counts how many sectors bio_insert has added to the cache */
	atomic_t		sectors_to_gc;

	struct btree		*root;

#ifdef CONFIG_BCACHE_DEBUG
	struct btree		*verify_data;
	struct mutex		verify_lock;
#endif

	unsigned		nr_uuids;
	struct uuid_entry	*uuids;
	BKEY_PADDED(uuid_bucket);
	struct closure_with_waitlist uuid_write;

	/*
	 * A btree node on disk could have too many bsets for an iterator to fit
	 * on the stack - this is a single element mempool for btree_read_work()
	 */
	struct mutex		fill_lock;
	struct btree_iter	*fill_iter;

	/*
	 * btree_sort() is a merge sort and requires temporary space - single
	 * element mempool
	 */
	struct mutex		sort_lock;
	struct bset		*sort;

	/* List of buckets we're currently writing data to */
	struct list_head	data_buckets;
	spinlock_t		data_bucket_lock;

	struct journal		journal;

#define CONGESTED_MAX		1024
	unsigned		congested_last_us;
	atomic_t		congested;

	/* The rest of this all shows up in sysfs */
	unsigned		congested_read_threshold_us;
	unsigned		congested_write_threshold_us;

	spinlock_t		sort_time_lock;
	struct time_stats	sort_time;
	struct time_stats	btree_gc_time;
	struct time_stats	btree_split_time;
	spinlock_t		btree_read_time_lock;
	struct time_stats	btree_read_time;
	struct time_stats	try_harder_time;

	atomic_long_t		cache_read_races;
	atomic_long_t		writeback_keys_done;
	atomic_long_t		writeback_keys_failed;
	unsigned		error_limit;
	unsigned		error_decay;
	unsigned		verify:1;
	unsigned		key_merging_disabled:1;
	unsigned		gc_always_rewrite:1;
	unsigned		shrinker_disabled:1;

#define BUCKET_HASH_BITS	12
	struct hlist_head	bucket_hash[1 << BUCKET_HASH_BITS];
};

static inline bool key_merging_disabled(struct cache_set *c)
{
#ifdef CONFIG_BCACHE_DEBUG
	return c->key_merging_disabled;
#else
	return 0;
#endif
}

struct bbio {
	unsigned		submit_time_us;
	union {
		struct bkey	key;
		uint64_t	_pad[3];
	};
	struct bio		bio;
};

static inline unsigned local_clock_us(void)
{
	return local_clock() >> 10;
}

#define MAX_BSETS		4

#define btree_prio		USHRT_MAX
#define initial_prio		32768

#define btree_bytes(c)		((c)->btree_pages * PAGE_SIZE)
#define btree_blocks(b)							\
	((unsigned) (KEY_SIZE(&b->key) >> (b)->c->block_bits))

#define btree_default_blocks(c)						\
	((unsigned) ((PAGE_SECTORS * (c)->btree_pages) >> (c)->block_bits))

#define bucket_pages(c)		((c)->sb.bucket_size / PAGE_SECTORS)
#define bucket_bytes(c)		((c)->sb.bucket_size << 9)
#define block_bytes(c)		((c)->sb.block_size << 9)

#define __set_bytes(i, k)	(sizeof(*(i)) + (k) * sizeof(uint64_t))
#define set_bytes(i)		__set_bytes(i, i->keys)

#define __set_blocks(i, k, c)	DIV_ROUND_UP(__set_bytes(i, k), block_bytes(c))
#define set_blocks(i, c)	__set_blocks(i, (i)->keys, c)

#define node(i, j)		((struct bkey *) ((i)->d + (j)))
#define end(i)			node(i, (i)->keys)

#define index(i, b)							\
	((size_t) (((void *) i - (void *) (b)->sets[0].data) /		\
		   block_bytes(b->c)))

#define btree_data_space(b)	(PAGE_SIZE << (b)->page_order)

#define prios_per_bucket(c)				\
	((bucket_bytes(c) - sizeof(struct prio_set)) /	\
	 sizeof(struct bucket_disk))
#define prio_buckets(c)					\
	DIV_ROUND_UP((size_t) (c)->sb.nbuckets, prios_per_bucket(c))

#define JSET_MAGIC		0x245235c1a3625032
#define PSET_MAGIC		0x6750e15f87337f91
#define BSET_MAGIC		0x90135c78b99e07f5

#define jset_magic(c)		((c)->sb.set_magic ^ JSET_MAGIC)
#define pset_magic(c)		((c)->sb.set_magic ^ PSET_MAGIC)
#define bset_magic(c)		((c)->sb.set_magic ^ BSET_MAGIC)

/* Bkey fields: all units are in sectors */

#define KEY_FIELD(name, field, offset, size)				\
	BITMASK(name, struct bkey, field, offset, size)

#define PTR_FIELD(name, offset, size)					\
	static inline uint64_t name(const struct bkey *k, unsigned i)	\
	{ return (k->ptr[i] >> offset) & ~(((uint64_t) ~0) << size); }	\
									\
	static inline void SET_##name(struct bkey *k, unsigned i, uint64_t v)\
	{								\
		k->ptr[i] &= ~(~((uint64_t) ~0 << size) << offset);	\
		k->ptr[i] |= v << offset;				\
	}

KEY_FIELD(KEY_PTRS,	header, 60, 3)
KEY_FIELD(HEADER_SIZE,	header, 58, 2)
KEY_FIELD(KEY_CSUM,	header, 56, 2)
KEY_FIELD(KEY_PINNED,	header, 55, 1)
KEY_FIELD(KEY_DIRTY,	header, 36, 1)

KEY_FIELD(KEY_SIZE,	header, 20, 16)
KEY_FIELD(KEY_DEV,	header, 0,  20)

KEY_FIELD(KEY_SECTOR,	key,	16, 47)
KEY_FIELD(KEY_SNAPSHOT,	key,	0,  16)

PTR_FIELD(PTR_DEV,		51, 12)
PTR_FIELD(PTR_OFFSET,		8,  43)
PTR_FIELD(PTR_GEN,		0,  8)

#define PTR(gen, offset, dev)						\
	((((uint64_t) dev) << 51) | ((uint64_t) offset) << 8 | gen)

#define sector_to_bucket(c, s)	((long) ((s) >> (c)->bucket_bits))
#define bucket_to_sector(c, b)	(((sector_t) (b)) << (c)->bucket_bits)
#define bucket_remainder(c, b)	((b) & ((c)->sb.bucket_size - 1))

#define PTR_CACHE(c, k, n)	((c)->cache[PTR_DEV(k, n)])
#define PTR_BUCKET_NR(c, k, n)	sector_to_bucket(c, PTR_OFFSET(k, n))

#define PTR_BUCKET(c, k, n)						\
	(PTR_CACHE(c, k, n)->buckets + PTR_BUCKET_NR(c, k, n))

/* Btree key macros */

#define KEY_HEADER(len, dev)						\
	(((uint64_t) 1 << 63) | ((uint64_t) (len) << 20) | (dev))

#define KEY(dev, sector, len)	(struct bkey)				\
	{ .header = KEY_HEADER(len, dev), .key = (sector) }

#define KEY_START(k)		((k)->key - KEY_SIZE(k))
#define START_KEY(k)		KEY(KEY_DEV(k), KEY_START(k), 0)
#define MAX_KEY			KEY(~(~0 << 20), ((uint64_t) ~0) >> 1, 0)
#define ZERO_KEY		KEY(0, 0, 0)

#define csum_set(i)							\
	crc64(((void *) (i)) + 8, ((void *) end(i)) - (((void *) (i)) + 8))

/* Error handling macros */

#define btree_bug(b, ...)						\
	({ if (cache_set_error((b)->c, __VA_ARGS__)) dump_stack(); })

#define cache_bug(c, ...)						\
	({ if (cache_set_error(c, __VA_ARGS__)) dump_stack(); })

#define btree_bug_on(cond, b, ...)					\
	({ if (cond) btree_bug(b, __VA_ARGS__); })

#define cache_bug_on(cond, c, ...)					\
	({ if (cond) cache_bug(c, __VA_ARGS__); })

#define cache_set_err_on(cond, c, ...)					\
	({ if (cond) cache_set_error(c, __VA_ARGS__); })

/* Looping macros */

#define for_each_cache(ca, cs)						\
	for (int _i = 0; ca = cs->cache[_i], _i < (cs)->sb.nr_in_set; _i++)

#define for_each_bucket(b, ca)						\
	for (b = (ca)->buckets + (ca)->sb.first_bucket;			\
	     b < (ca)->buckets + (ca)->sb.nbuckets; b++)

static inline void __bkey_put(struct cache_set *c, struct bkey *k)
{
	for (unsigned i = 0; i < KEY_PTRS(k); i++)
		atomic_dec_bug(&PTR_BUCKET(c, k, i)->pin);
}

/* Blktrace macros */

#define blktrace_msg(c, fmt, ...)					\
do {									\
	struct request_queue *q = bdev_get_queue(c->bdev);		\
	if (q)								\
		blk_add_trace_msg(q, fmt, ##__VA_ARGS__);		\
} while (0)

#define blktrace_msg_all(s, fmt, ...)					\
do {									\
	struct cache *_c;						\
	for_each_cache(_c, (s))						\
		blktrace_msg(_c, fmt, ##__VA_ARGS__);			\
} while (0)

#define err_printk(...)	printk(KERN_ERR "bcache: " __VA_ARGS__)

static inline void cached_dev_put(struct cached_dev *d)
{
	if (atomic_dec_and_test(&d->count))
		schedule_work(&d->detach);
}

static inline bool cached_dev_get(struct cached_dev *d)
{
	if (!atomic_inc_not_zero(&d->count))
		return false;

	smp_mb__after_atomic_inc();
	return true;
}

static inline uint8_t gen_after(uint8_t a, uint8_t b)
{
	uint8_t r = a - b;
	return r > 128U ? 0 : r;
}

#define ptr_stale(c, k, n)					\
	gen_after(PTR_BUCKET(c, k, n)->gen, PTR_GEN(k, n))

#define bucket_gc_gen(b)	((uint8_t) ((b)->gen - (b)->last_gc))
#define bucket_disk_gen(b)	((uint8_t) ((b)->gen - (b)->disk_gen))

#define kobj_attribute_write(n, fn)					\
	static struct kobj_attribute ksysfs_##n = __ATTR(n, S_IWUSR, NULL, fn)

#define kobj_attribute_rw(n, show, store)				\
	static struct kobj_attribute ksysfs_##n =			\
		__ATTR(n, S_IWUSR|S_IRUSR, show, store)

#define bio_split_get(bio, len, c)					\
	__bio_split_get(bio, len, (c)->bio_split)

/* Forward declarations */

bool bcache_in_writeback(struct cached_dev *, sector_t, unsigned);
void bcache_writeback_queue(struct cached_dev *);
void bcache_writeback_add(struct cached_dev *, unsigned);

void count_io_errors(struct cache *, int, const char *);
void bcache_endio(struct cache_set *, struct bio *, int, const char *);
void bbio_free(struct bio *, struct cache_set *);
struct bio *bbio_alloc(struct cache_set *);
struct bio *bbio_kmalloc(gfp_t, int);
struct bio *__bio_split_get(struct bio *, int, struct bio_set *);

void __submit_bbio(struct bio *, struct cache_set *);
void submit_bbio(struct bio *, struct cache_set *, struct bkey *, unsigned);
int submit_bbio_split(struct bio *, struct cache_set *,
		      struct bkey *, unsigned);

void cache_read_endio(struct bio *, int);

struct bcache_cgroup;
struct cgroup;
struct bcache_cgroup *cgroup_to_bcache(struct cgroup *cgroup);
struct bcache_cgroup *bio_to_cgroup(struct bio *bio);

void bcache_queue_gc(struct cache_set *);
uint8_t inc_gen(struct cache *, struct bucket *);
void rescale_priorities(struct cache_set *, int);
bool bucket_add_unused(struct cache *, struct bucket *);
bool can_save_prios(struct cache *);
void free_some_buckets(struct cache *);
void unpop_bucket(struct cache_set *, struct bkey *);
int __pop_bucket_set(struct cache_set *, uint16_t,
		     struct bkey *, int, struct closure *);
int pop_bucket_set(struct cache_set *, uint16_t,
		   struct bkey *, int, struct closure *);

bool cache_set_error(struct cache_set *, const char *, ...);

void prio_write(struct cache *);
void write_bdev_super(struct cached_dev *, struct closure *);

extern struct workqueue_struct *bcache_wq;
extern const char * const bcache_cache_modes[];

struct cache_set *cache_set_alloc(struct cache_sb *);
void free_discards(struct cache *);
int alloc_discards(struct cache *);
void bcache_btree_cache_free(struct cache_set *);
int bcache_btree_cache_alloc(struct cache_set *);
void bcache_writeback_init_cached_dev(struct cached_dev *);

void bcache_debug_exit(void);
int bcache_debug_init(struct kobject *);
void bcache_writeback_exit(void);
int bcache_writeback_init(void);
void bcache_request_exit(void);
int bcache_request_init(void);
void bcache_btree_exit(void);
int bcache_btree_init(void);
