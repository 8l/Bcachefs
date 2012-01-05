#ifndef _BCACHE_BTREE_H
#define _BCACHE_BTREE_H

#include "bset.h"

static inline struct bset *write_block(struct btree *b)
{
	 return ((void *) b->sets[0].data) + b->written * block_bytes(b->c);
}

static inline void set_gc_sectors(struct cache_set *c)
{
	atomic_set(&c->sectors_to_gc, c->sb.bucket_size * c->nbuckets / 8);
}

/* Looping macros */

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

#define for_each_key_after_filter(b, k, search, filter)			\
	for (struct bset_tree *_t = (b)->sets;				\
	     _t <= &(b)->sets[(b)->nsets];				\
	     _t++)							\
		for (k = bset_search(b, _t, search);			\
		     (k = bkey_filter(b, _t->data, k, filter))		\
			< end(_t->data);				\
		     k = next(k))

#define for_each_key_filter(b, k, filter)				\
	for_each_key_after_filter(b, k, NULL, filter)

#define for_each_key(b, k)	for_each_key_filter(b, k, all_keys)

/* Recursing down the btree */

struct btree_op {
	struct closure		cl;
	struct cached_dev	*d;

	/* For cache lookups, keys we took refcounts on.
	 * Everywhere else, keys to be inserted.
	 */
	struct keylist		keys;

	/* Journal entry we have a refcount on */
	atomic_t		*journal;

	/* Btree level at which we start taking write locks */
	short			lock;

	/* Btree insertion type */
	enum {
		INSERT_READ		= 0,
		INSERT_WRITE		= 1,
		INSERT_WRITEBACK	= 3,
		INSERT_UNDIRTY		= 4,
		INSERT_REPLAY		= 6
	} insert_type:8;

	/*
	 * These two fields logically belong in struct search (maybe we should
	 * move them back?)
	 *
	 * cache_hit is true if the last bio split hit, i.e. if s->bio has been
	 * submitted.
	 *
	 * cache_miss is true if _any_ split missed.
	 */
	unsigned		cache_hit:1;
	unsigned		cache_miss:1;
};

static inline void rw_lock(bool w, struct btree *b, int level)
{
	w ? down_write_nested(&b->lock, level + 1)
	  : down_read_nested(&b->lock, level + 1);
}

static inline void rw_unlock(bool w, struct btree *b)
{
	(w ? up_write : up_read)(&b->lock);
}

#define insert_lock(s, b)	((b)->level	<= (s)->lock)

#define btree(f, k, b, op, ...)						\
({									\
	int _r, l = b->level - 1;					\
	bool _w = l <= (op)->lock;					\
	struct btree *_b = get_bucket(b->c, k, l, op);			\
	BUG_ON(ptr_bad(b, k));						\
	if (!IS_ERR(_b)) {						\
		_r = btree_ ## f(_b, op, ## __VA_ARGS__);		\
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
		(c)->try_harder = NULL;					\
		closure_run_wait(&(c)->try_wait);			\
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

extern const char * const bcache_insert_types[];

static inline const char *insert_type(struct btree_op *op)
{
	return bcache_insert_types[op->insert_type];
}

/* Hack around symbol collisions */
#define btree_alloc(x, y, z)	bcache_btree_alloc(x, y, z)
#define btree_insert(x, y)	bcache_btree_insert(x, y)

struct btree *btree_alloc(struct cache_set *, int, struct closure *);
int btree_insert(struct btree_op *, struct cache_set *);
void btree_insert_async(struct closure *);
int btree_search_recurse(struct btree *, struct btree_op *,
			 struct bio *, uint64_t *);

void set_new_root(struct btree *);
struct btree *get_bucket(struct cache_set *, struct bkey *,
			 int, struct btree_op *);

size_t btree_gc_finish(struct cache_set *);
int btree_check(struct cache_set *, struct btree_op *);
void __btree_mark_key(struct cache_set *, int, struct bkey *);

void btree_read_work(struct work_struct *);
void btree_read(struct btree *);
void btree_write(struct btree *b, bool now, struct btree_op *op);
bool btree_insert_keys(struct btree *, struct btree_op *);

#endif
