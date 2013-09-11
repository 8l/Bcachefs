#ifndef _BCACHE_DEBUG_H
#define _BCACHE_DEBUG_H

struct bio;
struct bkey;
struct btree_keys;
struct btree_iter;
struct cached_dev;
struct cache_set;

#ifdef CONFIG_BCACHE_DEBUG

void bch_data_verify(struct cached_dev *, struct bio *);
int __bch_count_data(struct btree_keys *);
void __bch_check_keys(struct btree_keys *, const char *, ...);
void bch_btree_iter_next_check(struct btree_iter *);
void bch_dump_bucket(struct btree_keys *b);

#define EBUG_ON(cond)			BUG_ON(cond)
#define expensive_debug_checks(c)	((c)->expensive_debug_checks)
#define key_merging_disabled(c)		((c)->key_merging_disabled)
#define bypass_torture_test(d)		((d)->bypass_torture_test)

#else /* DEBUG */

static inline void bch_data_verify(struct cached_dev *dc, struct bio *bio) {}
static inline int __bch_count_data(struct btree_keys *b) { return -1; }
static inline void __bch_check_keys(struct btree *b, const char *fmt, ...) {}
static inline void bch_btree_iter_next_check(struct btree_iter *iter) {}
static inline void bch_dump_bucket(struct btree_keys *b) {}

#define EBUG_ON(cond)			do { if (cond); } while (0)
#define expensive_debug_checks(c)	0
#define key_merging_disabled(c)		0
#define bypass_torture_test(d)		0

#endif

#define bch_count_data(b)						\
	(expensive_debug_checks((b)->c) ? __bch_count_data(&b->keys) : -1)

#define bch_check_keys(b, ...)						\
do {									\
	if (expensive_debug_checks((b)->c))				\
		__bch_check_keys(&(b)->keys, __VA_ARGS__);		\
} while (0)

#ifdef CONFIG_DEBUG_FS
void bch_debug_init_cache_set(struct cache_set *);
#else
static inline void bch_debug_init_cache_set(struct cache_set *c) {}
#endif

#endif
