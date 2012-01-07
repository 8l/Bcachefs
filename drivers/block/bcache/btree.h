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
	struct cached_dev	*d;

	/* Journal entry we have a refcount on */
	atomic_t		*journal;

	/* Btree level at which we start taking write locks */
	short			lock;

	/* Btree insertion type */
	enum {
		INSERT_READ,
		INSERT_WRITE,
		INSERT_WRITEBACK,
		INSERT_UNDIRTY,
		INSERT_REPLAY,
	} insert_type:8;

	unsigned		cache_hit:1;

	/* Anything after this point won't get zeroed in do_bio_hook() */

	/* Keys to be inserted */
	struct keylist		keys;
};

void btree_op_init_stack(struct btree_op *);

static inline void rw_lock(bool w, struct btree *b, int level)
{
	w ? down_write_nested(&b->lock, level + 1)
	  : down_read_nested(&b->lock, level + 1);
}

static inline void rw_unlock(bool w, struct btree *b)
{
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

extern const char * const bcache_insert_types[];

static inline const char *insert_type(struct btree_op *op)
{
	return bcache_insert_types[op->insert_type];
}

void btree_read_work(struct work_struct *);
void btree_read(struct btree *);
void btree_write(struct btree *b, bool now, struct btree_op *op);

void bcache_btree_set_root(struct btree *);
struct btree *bcache_btree_alloc(struct cache_set *, int, struct closure *);
struct btree *get_bucket(struct cache_set *, struct bkey *,
			 int, struct btree_op *);

bool bcache_btree_insert_keys(struct btree *, struct btree_op *);
int bcache_btree_insert(struct btree_op *, struct cache_set *);
int btree_search_recurse(struct btree *, struct btree_op *,
			 struct bio *, unsigned *);

size_t btree_gc_finish(struct cache_set *);
int btree_check(struct cache_set *, struct btree_op *);
void __btree_mark_key(struct cache_set *, int, struct bkey *);

#endif
