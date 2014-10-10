#ifndef _LINUX_BCACHE_OPEN_H
#define _LINUX_BCACHE_OPEN_H

#include <linux/bcache.h>
#include <linux/blk_types.h>
#include <linux/closure.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/wait.h>

struct cache_set;
struct bkey;

#define BKEY_EXTENT_PTRS_MAX	4
#define BKEY_EXTENT_MAX_U64s	(BKEY_U64s + BKEY_EXTENT_PTRS_MAX)

#define BKEY_PADDED(key)	__BKEY_PADDED(key, BKEY_EXTENT_PTRS_MAX)

/* Keylists */

/* keylists can be used as a stack, using push and pop,
   or as a queue, using push and pop_front.
*/

struct keylist {
	/* This is a pointer to the LSB (inline_keys until realloc'd) */
	union {
		struct bkey		*start_keys;
		uint64_t		*start_keys_p;
	};
	/* This is a pointer to the next to enqueue (push) */
	union {
		struct bkey		*top;
		uint64_t		*top_p;
	};
	/* This is a pointer to the next to dequeue (pop_front) */
	union {
		struct bkey		*bot;
		uint64_t		*bot_p;
	};
	/* This is a pointer to beyond the MSB */
	union {
		struct bkey		*end_keys;
		uint64_t		*end_keys_p;
	};
	/* Enough room for btree_split's keys without realloc */
#define KEYLIST_INLINE		roundup_pow_of_two(BKEY_EXTENT_MAX_U64s * 2)
	/* Prevent key lists from growing too big */
	/*
	 * This should always be big enough to allow btree_gc_coalesce and
	 * btree_split to complete.
	 * The current value is the (current) size of a bucket, so it
	 * is far more than enough, as those two operations require only
	 * a handful of keys.
	 */
#define KEYLIST_MAX		(1 << 18)
	uint64_t		inline_keys[KEYLIST_INLINE];
};

static inline void bch_keylist_init(struct keylist *l)
{
	l->bot_p = l->top_p = l->start_keys_p = l->inline_keys;
	l->end_keys_p = (&l->inline_keys[KEYLIST_INLINE]);
}

/* __bch_keylist_push can be used if we've just checked the size */

static inline void __bch_keylist_push(struct keylist *l)
{
	l->top = bkey_next(l->top);
}

static inline void bch_keylist_push(struct keylist *l)
{
	__bch_keylist_push(l);
	BUG_ON(l->top_p > l->end_keys_p);
}

/* __bch_keylist_add can be used if we've just checked the size */

static inline void __bch_keylist_add(struct keylist *l, struct bkey *k)
{
	bkey_copy(l->top, k);
	__bch_keylist_push(l);
}

static inline void bch_keylist_add(struct keylist *l, struct bkey *k)
{
	bkey_copy(l->top, k);
	bch_keylist_push(l);
}

static inline bool bch_keylist_empty(struct keylist *l)
{
	return l->bot == l->top;
}

static inline void bch_keylist_reset(struct keylist *l)
{
	l->bot = l->top = l->start_keys;
}

static inline void bch_keylist_free(struct keylist *l)
{
	if (l->start_keys_p != l->inline_keys)
		kfree(l->start_keys_p);
}

/* This returns the number of uint64_t, rather than the number of keys.
   As keys are variable sized, the actual number of keys would have to
   be counted.
*/
static inline size_t bch_keylist_nkeys(struct keylist *l)
{
	return l->top_p - l->bot_p;
}

static inline size_t bch_keylist_size(struct keylist *l)
{
	return l->top_p - l->start_keys_p;
}

static inline size_t bch_keylist_offset(struct keylist *l)
{
	return l->bot_p - l->start_keys_p;
}

static inline bool bch_keylist_is_end(struct keylist *l, struct bkey *k)
{
	return k == (l->top);
}

static inline bool bch_keylist_is_last(struct keylist *l, struct bkey *k)
{
	return bch_keylist_is_end(l, bkey_next(k));
}

static inline struct bkey *bch_keylist_front(struct keylist *l)
{
	return l->bot;
}

static inline void bch_keylist_pop_front(struct keylist *l)
{
	l->bot_p += (KEY_U64s(l->bot));
}

#define keylist_single(k)	(struct keylist)			\
	{ .start_keys = k,						\
	  .top = bkey_next(k),						\
	  .bot = k,							\
	  .end_keys = bkey_next(k)					\
	}

struct bkey *bch_keylist_pop(struct keylist *);
void bch_keylist_pop_front(struct keylist *);
int bch_keylist_realloc(struct keylist *, unsigned);

struct btree_op {
	struct closure		cl;

	/* Bitmasks for intent/read locks held per level */
	u8			locks_intent;
	u8			locks_read;

	/* Btree level below which we start taking intent locks */
	s8			locks_want;

	enum btree_id		id:8;

	unsigned		iterator_invalidated:1;

	/* State used by btree insertion is also stored here for convenience */
	unsigned		insert_collision:1;

	/* For allocating new nodes */
	u8			reserve;
};

struct bch_write_op {
	struct closure		cl;
	struct cache_set	*c;
	struct workqueue_struct	*io_wq;
	struct bio		*bio;

	/* Used internally, do not touch */
	struct btree_op		op;

	short			error;

	union {
		u8		flags;

	struct {
		/* Wait for data bucket allocation or just
		 * fail when out of space? */
		unsigned	wait:1;
		/* Discard key range? */
		unsigned	discard:1;
		/* Wait for journal commit? */
		unsigned	flush:1;
		/* Perform a compare-exchange with replace_key? */
		unsigned	replace:1;

		/* Set on completion, if cmpxchg index update failed */
		unsigned	replace_collision:1;
		/* Internal */
		unsigned	write_done:1;
	};
	};

	u8			btree_alloc_reserve;

	struct write_point	*wp;

	union {
	struct open_bucket	*open_buckets[2];
	struct {
	struct bch_write_op	*next;
	unsigned long		expires;
	};
	};


	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	BKEY_PADDED(replace_key);
};

void bch_write_op_init(struct bch_write_op *, struct cache_set *,
		       struct bio *, struct write_point *, bool,
		       bool, bool, struct bkey *, struct bkey *);

struct bbio {
	struct cache		*ca;

	unsigned int		bi_idx;		/* current index into bvl_vec */

	unsigned int            bi_bvec_done;	/* number of bytes completed in
						   current bvec */
	unsigned		submit_time_us;
	struct bkey		key;
	uint64_t		pad;
	/* Only ever have a single pointer (the one we're doing io to/from) */
	struct bio		bio;
};

#define to_bbio(_bio)		container_of((_bio), struct bbio, bio)

int bch_read(struct cache_set *, struct bio *, u64);
void bch_write(struct closure *);

int bch_list_keys(struct cache_set *, unsigned, struct bkey *, struct bkey *,
		  struct bkey *, size_t, unsigned, unsigned *);

void bch_cache_set_close(struct cache_set *);
struct cache_set *bch_cache_set_open(unsigned);
struct cache_set *bch_cache_set_open_by_uuid(uuid_le *);

int bch_blockdev_inode_find_by_uuid(struct cache_set *, uuid_le *,
				    struct bch_inode_blockdev *);

#endif /* _LINUX_BCACHE_OPEN_H */
