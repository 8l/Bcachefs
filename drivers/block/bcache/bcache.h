
#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/bio.h>
#include <linux/blktrace_api.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "util.h"

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
 */
#define BCACHE_SB_VERSION	2

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

BITMASK(CACHE_SYNC,	struct cache_sb, flags, 0, 1);

BITMASK(BDEV_WRITEBACK,	struct cache_sb, flags, 0, 1);
BITMASK(BDEV_STATE,	struct cache_sb, flags, 61, 2);
#define BDEV_STATE_NONE		0U
#define BDEV_STATE_CLEAN	1U
#define BDEV_STATE_DIRTY	2U
#define BDEV_STATE_STALE	3U

/* Version 1: Seed pointer into btree node checksum
 */
#define BCACHE_BSET_VERSION	1

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

struct cache_accounting {
	struct kobject		kobj;
	unsigned		rescale;

	union {
		unsigned long	all[7];

		struct {
			unsigned long	cache_hits;
			unsigned long	cache_misses;
			unsigned long	cache_bypass_hits;
			unsigned long	cache_bypass_misses;

			unsigned long	cache_readaheads;
			unsigned long	cache_miss_collisions;
			unsigned long	sectors_bypassed;
		};
	};
};

struct io {
	/* Used to track sequential IO so it can be skipped */
	struct hlist_node	hash;
	struct list_head	lru;

	unsigned long		jiffies;
	unsigned		sequential;
	sector_t		last;
};

struct cached_dev {
	struct list_head	list;
	struct cache_sb		sb;
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];

	struct closure		*sb_writer;
	struct semaphore	sb_write;

	struct kobject		kobj;
	struct block_device	*bdev;
	struct gendisk		*disk;

	struct cache_set	*c;
	unsigned		id;

	spinlock_t		lock;
	/* Refcount on the cache set. Always nonzero when we're caching. */
	atomic_t		count;
	atomic_t		unregister;
	struct work_struct	detach;

	/* If nonzero, we're disabling caching */
	atomic_t		closing;
	atomic_t		running;

	struct rw_semaphore	writeback_lock;
	struct work_struct	refill;

	union {
		atomic_t	all[7];

		atomic_t	stats[2][2];

		struct {
			atomic_t	cache_hits;
			atomic_t	cache_misses;
			atomic_t	cache_bypass_hits;
			atomic_t	cache_bypass_misses;

			atomic_t	cache_readaheads;
			atomic_t	cache_miss_collisions;
			atomic_t	sectors_bypassed;
		};
	};

	union {
		struct cache_accounting accounting[4];

		struct {
			struct cache_accounting total;
			struct cache_accounting five_minute;
			struct cache_accounting hour;
			struct cache_accounting day;
		};
	};

	struct timer_list	accounting_timer;

	unsigned long		sequential_cutoff;
	unsigned		sequential_merge:1;

	unsigned		data_csum:1;

	unsigned		writeback:1;
	unsigned		writeback_metadata:1;
	unsigned		writeback_running:1;
	unsigned short		writeback_percent;
	unsigned		writeback_delay;

	unsigned long		readahead;

	/* Number of writeback bios in flight */
	atomic_t		in_flight;

	/* Nonzero, and writeback has a refcount (d->count), iff there is dirty
	 * data in the cache
	 */
	atomic_long_t		last_refilled;

	uint64_t		last_found;
	uint64_t		last_read;
	struct rb_root		dirty;

	/* Beginning and end of range in dirty rb tree */
	uint64_t		writeback_start;
	uint64_t		writeback_end;

#define RECENT_IO_BITS	7
#define RECENT_IO	(1 << RECENT_IO_BITS)
	struct io		io[RECENT_IO];
	struct hlist_head	io_hash[RECENT_IO + 1];
	struct list_head	io_lru;
};

struct cache {
	struct cache_set	*set;
	struct cache_sb		sb;
	struct bio		sb_bio;
	struct bio_vec		sb_bv[1];

	struct kobject		kobj;
	struct block_device	*bdev;
	struct dentry		*debug;

	struct bucket		*buckets;

	struct bio		*uuid_bio;

	DECLARE_HEAP(struct bucket *, heap);

	struct closure		prio;
	struct bio		*prio_bio;
	struct prio_set		*disk_buckets;

	/* Bucket that journal uses */
	uint64_t		prio_start;

	uint64_t		*prio_buckets;
	uint64_t		*prio_next;
	unsigned		prio_write;
	unsigned		prio_alloc;

	/* > 0: buckets in free_inc have been marked as free
	 * = 0: buckets in free_inc can't be used until priorities are written
	 * < 0: priority write in progress
	 */
	atomic_t		prio_written;
	uint8_t			need_save_prio;
	unsigned		invalidate_needs_gc:1;

	DECLARE_FIFO(long, free);
	DECLARE_FIFO(long, free_inc);
	DECLARE_FIFO(long, unused);

	atomic_long_t		meta_sectors_written;
	atomic_long_t		btree_sectors_written;
	atomic_long_t		sectors_written;

#define IO_ERROR_SHIFT		20
	atomic_t		io_errors;
	atomic_t		io_count;

	bool			discard;
	struct list_head	discards;
	struct page		*discard_page;

	sector_t		journal_area_start;
	sector_t		journal_area_end;

	/* Free journal sectors */
	sector_t		journal_start;
	sector_t		journal_end;
	DECLARE_FIFO(struct journal_seq, journal);
	struct bio		journal_bio;
	struct bio_vec		journal_bv[8];
};

struct gc_stat {
	unsigned		count;
	unsigned		ms_max;
	time_t			last;

	size_t			nodes;
	size_t			key_bytes;

	size_t			nkeys;
	uint64_t		data;	/* sectors */
	uint64_t		dirty;	/* sectors */
	unsigned		in_use; /* percent */
};

struct cache_set {
	struct list_head	list;
	struct cache_sb		sb;

	struct cache		*cache[MAX_CACHES_PER_SET];
	struct cache		*cache_by_alloc[MAX_CACHES_PER_SET];
	int			caches_loaded;

	atomic_t		closing;
	struct kobject		kobj;
	struct kobject		internal;
	struct kobject		accounting[4];
	struct work_struct	unregister;
	struct list_head	devices;

	struct mutex		sb_write;
	struct closure		*sb_writer;

	mempool_t		*search;
	struct bio_set		*bio_split;
	struct shrinker		shrink;

	/*
	 * Buckets used for cached data go on the heap. The heap is ordered by
	 * bucket->priority; a priority of ~0 indicates a btree bucket. Priority
	 * is increased on cache hit, and periodically all the buckets on the
	 * heap have their priority scaled down by a linear function.
	 */
	spinlock_t		bucket_lock;
	unsigned short		bucket_bits;
	unsigned short		block_bits;
	unsigned		btree_pages;

	/* Refcount for when we can't write the priorities to disk until a
	 * btree write finishes.
	 */
	atomic_t		prio_blocked;
	closure_list_t		bucket_wait;

	atomic_t		rescale;
	uint16_t		min_prio;
	uint8_t			need_gc;
	struct gc_stat		gc_stats;
	size_t			nbuckets;

	struct list_head	lru;
	struct list_head	freed;
	struct closure		*try_harder;
	closure_list_t		try_wait;

	struct work_struct	gc_work;
	struct mutex		gc_lock;
	/* Where in the btree gc currently is */
	struct bkey		gc_done;
	/* Protected by bucket_lock */
	int			gc_mark_valid;
	/* Counts how many sectors bio_insert has added to the cache */
	atomic_t		sectors_to_gc;

	struct btree		*root;

	int			nr_uuids;
	struct uuid_entry	*uuids;
	BKEY_PADDED(uuid_bucket);
	struct closure		uuid_write;

	struct mutex		fill_lock;
	struct btree_iter	*fill_iter;

	struct mutex		sort_lock;
	struct bset		*sort;

	struct list_head	open_buckets;
	struct list_head	dirty_buckets;
	spinlock_t		open_bucket_lock;

	struct journal		journal;

#define CONGESTED_MAX		1024
	unsigned		congested_threshold_us;
	unsigned		congested_last_us;
	atomic_t		congested;

	atomic_long_t		writeback_keys_done;
	atomic_long_t		writeback_keys_failed;
	atomic_long_t		btree_write_count;
	atomic_long_t		keys_write_count;
	int			error_limit;
	int			error_decay;

#define BUCKET_HASH_BITS	12
	struct hlist_head	bucket_hash[1 << BUCKET_HASH_BITS];
};

struct btree_write {
#ifdef CONFIG_BCACHE_LATENCY_DEBUG
	unsigned long		wait_time;
#endif
	struct btree		*b;
	closure_list_t		wait;
	struct closure		*owner;
	atomic_t		*journal;

	int			prio_blocked;
	bool			nofree;
};

struct bkey_float;

struct btree {
	struct list_head	lru;
	struct hlist_node	hash;
	struct rw_semaphore	lock;
	struct delayed_work	work;

	unsigned long		jiffies;

	struct cache_set	*c;
	closure_list_t		wait;

	unsigned long		expires;
	struct btree_write	*write;
	atomic_t		io;
	int			prio_blocked;

	struct btree_write	writes[2];

	atomic_t		nread;
	short			level;
	uint16_t		written;
	uint16_t		nsets;
	unsigned		next:1;
	unsigned		page_order:7;

	BKEY_PADDED(key);

	union {
		struct bset	*data;
		struct bset	*sets[5];
		/* Has to be 1 greater than the normal max for coalescing in
		 * btree_gc_recurse() */
	};

	/* We construct a binary tree in an array as if the array started at 1,
	 * so that things line up on the same cachelines better
	 */
	struct bset_tree {
		unsigned	size;
		unsigned	extra;
		struct bkey	end;
		struct bkey_float *key;
	}			tree[4];

	struct bio		bio;
};

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
	return sched_clock() >> 10;
}

#define btree_prio		USHRT_MAX
#define initial_prio		32768

#define btree_bytes(c)		((c)->btree_pages * PAGE_SIZE)
#define btree_blocks(b)							\
	((unsigned) (KEY_SIZE(&b->key) >> (b)->c->block_bits))

#define bucket_pages(c)		((c)->sb.bucket_size / PAGE_SECTORS)
#define bucket_bytes(c)		((c)->sb.bucket_size << 9)
#define block_bytes(c)		((c)->sb.block_size << 9)

#define __set_bytes(i, k)	(sizeof(*(i)) + (k) * sizeof(uint64_t))
#define set_bytes(i)		__set_bytes(i, i->keys)

#define __set_blocks(i, k, c)	DIV_ROUND_UP(__set_bytes(i, k), block_bytes(c))
#define set_blocks(i, c)	__set_blocks(i, (i)->keys, c)

#define node(i, j)		((struct bkey *) ((i)->d + (j)))
#define end(i)			node(i, (i)->keys)
#define last_key(i)		(i->keys ? prev(node(i, (i)->keys)) : NULL)

#define index(i, b)							\
	((size_t) (((void *) i - (void *) (b)->data) / block_bytes(b->c)))

#define bset_tree_order(b)	(b->page_order > 4 ? b->page_order - 4 : 0)

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

KEY_FIELD(KEY_IS_HEADER, header, 63, 1)
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

/* Btree/bkey debug printing */

#define KEYHACK_SIZE 80
struct keyprint_hack {
	char s[KEYHACK_SIZE];
};

struct keyprint_hack bcache_pkey(const struct bkey *k);
struct keyprint_hack bcache_pbtree(const struct btree *b);
#define pkey(k)		(bcache_pkey(k).s)
#define pbtree(b)	(bcache_pbtree(b).s)

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

/* Forward declarations */

#ifdef CONFIG_BCACHE_EDEBUG

unsigned count_data(struct btree *);
void check_key_order_msg(struct btree *, struct bset *, const char *, ...);

#define check_key_order(b, i)	check_key_order_msg(b, i, "keys out of order")
#define EBUG_ON(cond)		BUG_ON(cond)

#else /* EDEBUG */

#define count_data(b)					0
#define check_key_order(b, i)				do {} while (0)
#define check_key_order_msg(b, i, ...)			do {} while (0)
#define EBUG_ON(cond)		do {} while (0)

#endif


void btree_op_init_stack(struct btree_op *);

bool in_writeback(struct cached_dev *, sector_t, unsigned);
void queue_writeback(struct cached_dev *);

int get_congested(struct cache_set *);
void count_io_errors(struct cache *, int, const char *);
void bcache_endio(struct cache_set *, struct bio *, int, const char *);
struct bio *bbio_kmalloc(gfp_t, int);
struct bio *bio_split_get(struct bio *, int, struct cache_set *);
void submit_bbio(struct bio *, struct cache_set *, struct bkey *, unsigned);
int submit_bbio_split(struct bio *, struct cache_set *,
		      struct bkey *, unsigned);

void cache_read_endio(struct bio *, int);

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

void prio_write(struct cache *, struct closure *);
void write_bdev_super(struct cached_dev *, struct closure *);
bool cache_set_error(struct cache_set *, const char *, ...);
int bcache_make_request(struct request_queue *, struct bio *);

extern struct kmem_cache *search_cache;
extern struct workqueue_struct *bcache_wq;
extern struct list_head cache_sets; /* only needed for old shrinker, will die */

struct cache_set *cache_set_alloc(struct cache_sb *);
void free_discards(struct cache *);
int alloc_discards(struct cache *);
void free_journal(struct cache_set *);
int alloc_journal(struct cache_set *);
void free_open_buckets(struct cache_set *);
int alloc_open_buckets(struct cache_set *);
void free_btree_cache(struct cache_set *);
int alloc_btree_cache(struct cache_set *);
void bcache_debug_init_cache(struct cache *);
void bcache_writeback_init_cached_dev(struct cached_dev *);

#ifdef CONFIG_DEBUG_FS
void bcache_debug_init_cache(struct cache *);
#else
static inline void bcache_debug_init_cache(struct cache *c) {}
#endif

void bcache_debug_exit(void);
int bcache_debug_init(struct kobject *);
void bcache_writeback_exit(void);
int bcache_writeback_init(void);
void bcache_request_exit(void);
int bcache_request_init(void);
void bcache_util_exit(void);
int bcache_util_init(void);
