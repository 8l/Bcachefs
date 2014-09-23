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

struct keylist {
	union {
		struct bkey		*keys;
		uint64_t		*keys_p;
	};
	union {
		struct bkey		*top;
		uint64_t		*top_p;
	};

	/* Enough room for btree_split's keys without realloc */
#define KEYLIST_INLINE		16
	uint64_t		inline_keys[KEYLIST_INLINE];
};

static inline void bch_keylist_init(struct keylist *l)
{
	l->top_p = l->keys_p = l->inline_keys;
}

static inline void bch_keylist_push(struct keylist *l)
{
	l->top = bkey_next(l->top);
}

static inline void bch_keylist_add(struct keylist *l, struct bkey *k)
{
	bkey_copy(l->top, k);
	bch_keylist_push(l);
}

static inline bool bch_keylist_empty(struct keylist *l)
{
	return l->top == l->keys;
}

static inline void bch_keylist_reset(struct keylist *l)
{
	l->top = l->keys;
}

static inline void bch_keylist_free(struct keylist *l)
{
	if (l->keys_p != l->inline_keys)
		kfree(l->keys_p);
}

static inline size_t bch_keylist_nkeys(struct keylist *l)
{
	return l->top_p - l->keys_p;
}

static inline bool bch_keylist_is_last(struct keylist *l, struct bkey *k)
{
	return bkey_next(k) == l->top;
}

static inline size_t bch_keylist_bytes(struct keylist *l)
{
	return bch_keylist_nkeys(l) * sizeof(uint64_t);
}

#define keylist_single(k)	(struct keylist)			\
	{ .keys = k, .top = bkey_next(k) }

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
	struct open_bucket	*open_buckets[2];

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
