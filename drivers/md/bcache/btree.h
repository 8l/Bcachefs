#ifndef _BCACHE_BTREE_H
#define _BCACHE_BTREE_H

#include "bset.h"
#include "debug.h"

struct btree_write {
	struct closure		*owner;
	atomic_t		*journal;

	/* If btree_split() frees a btree node, it writes a new pointer to that
	 * btree node indicating it was freed; it takes a refcount on
	 * c->prio_blocked because we can't write the gens until the new
	 * pointer is on disk. This allows btree_write_endio() to release the
	 * refcount that btree_split() took.
	 */
	int			prio_blocked;
};

struct btree {
	/* Hottest entries first */
	struct hlist_node	hash;

	/* Key/pointer for this btree node */
	BKEY_PADDED(key);

	/* Single bit - set when accessed, cleared by shrinker */
	unsigned long		accessed;
	unsigned long		seq;
	struct rw_semaphore	lock;
	struct cache_set	*c;

	unsigned long		flags;
	uint16_t		written;	/* would be nice to kill */
	uint8_t			level;
	uint8_t			nsets;
	uint8_t			page_order;

	/*
	 * Set of sorted keys - the real btree node - plus a binary search tree
	 *
	 * sets[0] is special; set[0]->tree, set[0]->prev and set[0]->data point
	 * to the memory we have allocated for this btree node. Additionally,
	 * set[0]->data points to the entire btree node as it exists on disk.
	 */
	struct bset_tree	sets[MAX_BSETS];

	/* Used to refcount bio splits, also protects b->bio */
	struct closure_with_waitlist	io;

	/* Gets transferred to w->prio_blocked - see the comment there */
	int			prio_blocked;

	struct list_head	list;
	struct delayed_work	work;

	uint64_t		io_start_time;
	struct btree_write	writes[2];
	struct bio		*bio;
};

#define BTREE_FLAG(flag)						\
static inline bool btree_node_ ## flag(struct btree *b)			\
{	return test_bit(BTREE_NODE_ ## flag, &b->flags); }		\
									\
static inline void set_btree_node_ ## flag(struct btree *b)		\
{	set_bit(BTREE_NODE_ ## flag, &b->flags); }			\

enum btree_flags {
	BTREE_NODE_read_done,
	BTREE_NODE_io_error,
	BTREE_NODE_dirty,
	BTREE_NODE_write_idx,
};

BTREE_FLAG(read_done);
BTREE_FLAG(io_error);
BTREE_FLAG(dirty);
BTREE_FLAG(write_idx);

static inline struct btree_write *btree_current_write(struct btree *b)
{
	return b->writes + btree_node_write_idx(b);
}

static inline struct btree_write *btree_prev_write(struct btree *b)
{
	return b->writes + (btree_node_write_idx(b) ^ 1);
}

static inline unsigned bset_offset(struct btree *b, struct bset *i)
{
	return (((size_t) i) - ((size_t) b->sets->data)) >> 9;
}

static inline struct bset *write_block(struct btree *b)
{
	return ((void *) b->sets[0].data) + b->written * block_bytes(b->c);
}

static inline bool bset_written(struct btree *b, struct bset_tree *t)
{
	return t->data < write_block(b);
}

static inline bool bkey_written(struct btree *b, struct bkey *k)
{
	return k < write_block(b)->start;
}

static inline void set_gc_sectors(struct cache_set *c)
{
	atomic_set(&c->sectors_to_gc, c->sb.bucket_size * c->nbuckets / 8);
}

/* Looping macros */

#define for_each_cached_btree(b, cursor, c)				\
	for (unsigned _i = 0;						\
	     _i < ARRAY_SIZE((c)->bucket_hash);				\
	     _i++)							\
		hlist_for_each_entry_rcu((b), cursor,			\
					 (c)->bucket_hash + _i, hash)

#define for_each_sorted_set_start(b, i, start)				\
	for (int _i = start; i = (b)->sets[_i].data, _i <= (b)->nsets; _i++)

#define for_each_sorted_set(b, i)	for_each_sorted_set_start(b, i, 0)

#define bkey_filter(b, i, k, filter)					\
({									\
	while (k < end(i) && filter(b, k))				\
		k = next(k);						\
	k;								\
})

#define all_keys(b, k)		0

#define for_each_key_filter(b, k, filter)				\
	for (struct bset_tree *_t = (b)->sets;				\
	     _t <= &(b)->sets[(b)->nsets];				\
	     _t++)							\
		for (k = _t->data->start;				\
		     (k = bkey_filter(b, _t->data, k, filter))		\
			< end(_t->data);				\
		     k = next(k))

#define for_each_key(b, k)	for_each_key_filter(b, k, all_keys)

/* Recursing down the btree */

struct btree_op {
	struct closure		cl;
	struct cache_set	*c;

	/* Journal entry we have a refcount on */
	atomic_t		*journal;

	/* Bio to be inserted into the cache */
	struct bio		*cache_bio;

	unsigned		inode;

	/* Btree level at which we start taking write locks */
	short			lock;

	/* Btree insertion type */
	enum {
		BTREE_INSERT,
		BTREE_REPLACE
	} type:8;

	unsigned		csum:1;
	unsigned		skip:1;
	unsigned		flush_journal:1;

	unsigned		bio_insert_done:1;
	unsigned		lookup_done:1;
	unsigned		insert_collision:1;

	/* Anything after this point won't get zeroed in do_bio_hook() */

	/* Keys to be inserted */
	struct keylist		keys;
	BKEY_PADDED(replace);
};

void btree_op_init_stack(struct btree_op *);

static inline void rw_lock(bool w, struct btree *b, int level)
{
	w ? down_write_nested(&b->lock, level + 1)
	  : down_read_nested(&b->lock, level + 1);
	if (w)
		b->seq++;
}

static inline void rw_unlock(bool w, struct btree *b)
{
#ifdef CONFIG_BCACHE_EDEBUG
	if (w &&
	    b->key.ptr[0] &&
	    btree_node_read_done(b))
		for (unsigned i = 0; i <= b->nsets; i++)
			check_key_order(b, b->sets[i].data);
#endif

	if (w)
		b->seq++;
	(w ? up_write : up_read)(&b->lock);
}

#define insert_lock(s, b)	((b)->level <= (s)->lock)

/*
 * These macros are for recursing down the btree - they handle the details of
 * locking and looking up nodes in the cache for you. They're best treated as
 * mere syntax when reading code that uses them.
 *
 * op->lock determines whether we take a read or a write lock at a given depth.
 * If you've got a read lock and find that you need a write lock (i.e. you're
 * going to have to split), set op->lock and return -EINTR; btree_root() will
 * call you again and you'll have the correct lock.
 */
#define btree(f, k, b, op, ...)						\
({									\
	int _r, l = (b)->level - 1;					\
	bool _w = l <= (op)->lock;					\
	struct btree *_b = get_bucket((b)->c, k, l, op);		\
	if (!IS_ERR(_b)) {						\
		_r = btree_ ## f(_b, op, ##__VA_ARGS__);		\
		rw_unlock(_w, _b);					\
	} else								\
		_r = PTR_ERR(_b);					\
	_r;								\
})

#define btree_root(f, c, op, ...)					\
({									\
	int _r = -EINTR;						\
	do {								\
		struct btree *_b = (c)->root;				\
		bool _w = insert_lock(op, _b);				\
		rw_lock(_w, _b, _b->level);				\
		if (_b == (c)->root &&					\
		    _w == insert_lock(op, _b))				\
			_r = btree_ ## f(_b, op, ##__VA_ARGS__);	\
		rw_unlock(_w, _b);					\
	} while (_r == -EINTR);						\
									\
	if ((c)->try_harder == &(op)->cl) {				\
		time_stats_update(&(c)->try_harder_time,		\
				  (c)->try_harder_start);		\
		(c)->try_harder = NULL;					\
		__closure_wake_up(&(c)->try_wait);			\
	}								\
	_r;								\
})

static inline bool should_split(struct btree *b)
{
	struct bset *i = write_block(b);
	return b->written >= btree_blocks(b) ||
		(i->seq == b->sets[0].data->seq &&
		 b->written + __set_blocks(i, i->keys + 15, b->c)
		 > btree_blocks(b));
}

void btree_read_done(struct closure *);
void btree_read(struct btree *);
void btree_write(struct btree *b, bool now, struct btree_op *op);

void bcache_btree_set_root(struct btree *);
struct btree *bcache_btree_alloc(struct cache_set *, int, struct closure *);
struct btree *get_bucket(struct cache_set *, struct bkey *,
			 int, struct btree_op *);

bool bcache_btree_insert_keys(struct btree *, struct btree_op *);
bool btree_insert_check_key(struct btree *, struct btree_op *, struct bio *);
int bcache_btree_insert(struct btree_op *, struct cache_set *);
int btree_search_recurse(struct btree *, struct btree_op *);

void bcache_queue_gc(struct cache_set *);
size_t btree_gc_finish(struct cache_set *);
int btree_check(struct cache_set *, struct btree_op *);
uint8_t __btree_mark_key(struct cache_set *, int, struct bkey *);

#endif
