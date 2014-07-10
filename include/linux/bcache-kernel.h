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

static inline void bch_keylist_init_single(struct keylist *l, struct bkey *k)
{
	l->keys = k;
	l->top = bkey_next(k);
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

static inline size_t bch_keylist_bytes(struct keylist *l)
{
	return bch_keylist_nkeys(l) * sizeof(uint64_t);
}

struct bkey *bch_keylist_pop(struct keylist *);
void bch_keylist_pop_front(struct keylist *);
int bch_keylist_realloc(struct keylist *, unsigned);

struct btree_op {
	struct closure		cl;

	enum btree_id		id;

	/* For allocating new nodes */
	unsigned		reserve;

	/* Btree level at which we start taking write locks */
	short			lock;

	/* State used by btree insertion is also stored here for convenience */
	u8			iterator_invalidated;

	unsigned		insert_collision:1;
};

struct data_insert_op {
	struct closure		cl;
	struct cache_set	*c;
	struct bio		*bio;

	/* Used internally, do not touch */
	struct btree_op		op;

	uint16_t		write_point;
	short			error;

	union {
		uint16_t	flags;

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
		/* Tier to write to */
		unsigned	tier:2;
		/* Use moving GC reserves for buckets, btree nodes and
		 * open buckets? */
		unsigned	moving_gc:1;
		/* Use tiering reserves for btree nodes? */
		unsigned	tiering:1;
		/* Set on completion */
		unsigned	replace_collision:1;
		/* Internal */
		unsigned	insert_data_done:1;
	};
	};

	struct open_bucket	*open_buckets[1];

	struct keylist		insert_keys;
	BKEY_PADDED(insert_key);
	BKEY_PADDED(replace_key);
};

static inline void bch_data_insert_op_init(struct data_insert_op *op,
					   struct cache_set *c,
					   struct bio *bio,
					   unsigned write_point,
					   bool wait, bool discard, bool flush,
					   struct bkey *insert_key,
					   struct bkey *replace_key)
{
	op->c		= c;
	op->bio		= bio;
	op->write_point	= write_point;
	op->error	= 0;
	op->flags	= 0;
	op->wait	= wait;
	op->discard	= discard;
	op->flush	= flush;

	bch_keylist_init(&op->insert_keys);
	bkey_copy(&op->insert_key, insert_key);

	if (replace_key) {
		op->replace = true;
		bkey_copy(&op->replace_key, replace_key);
	}
}

struct bbio {
	unsigned		submit_time_us;
	struct bkey		key;
	uint64_t		pad;
	/* Only ever have a single pointer (the one we're doing io to/from) */
	struct bio		bio;
};

#define to_bbio(_bio)		container_of((_bio), struct bbio, bio)

int bch_read(struct cache_set *, struct bio *, u64);
void bch_data_insert(struct closure *);

int bch_list_keys(struct cache_set *, unsigned, struct bkey *, struct bkey *,
		  struct bkey *, size_t, unsigned, unsigned *);

void bch_cache_set_close(struct cache_set *);
struct cache_set *bch_cache_set_open(unsigned);
struct cache_set *bch_cache_set_open_by_uuid(uuid_le *);

int bch_blockdev_inode_find_by_uuid(struct cache_set *, uuid_le *,
				    struct bch_inode_blockdev *);

#endif /* _LINUX_BCACHE_OPEN_H */
