#ifndef _BCACHE_DEBUG_H
#define _BCACHE_DEBUG_H

/* Btree/bkey debug printing */

#define KEYHACK_SIZE 80
struct keyprint_hack {
	char s[KEYHACK_SIZE];
};

struct keyprint_hack bcache_pkey(const struct bkey *k);
struct keyprint_hack bcache_pbtree(const struct btree *b);
#define pkey(k)		(bcache_pkey(k).s)
#define pbtree(b)	(bcache_pbtree(b).s)

#ifdef CONFIG_BCACHE_EDEBUG

unsigned count_data(struct btree *);
void check_key_order_msg(struct btree *, struct bset *, const char *, ...);
void check_keys(struct btree *, const char *, ...);

#define check_key_order(b, i)	check_key_order_msg(b, i, "keys out of order")
#define EBUG_ON(cond)		BUG_ON(cond)

#else /* EDEBUG */

#define count_data(b)					0
#define check_key_order(b, i)				do {} while (0)
#define check_key_order_msg(b, i, ...)			do {} while (0)
#define check_keys(b, ...)				do {} while (0)
#define EBUG_ON(cond)		do {} while (0)

#endif

#ifdef CONFIG_BCACHE_DEBUG

void btree_verify(struct btree *, struct bset *);

#else /* DEBUG */

static inline void btree_verify(struct btree *b, struct bset *i) {}

#endif

#ifdef CONFIG_DEBUG_FS
void bcache_debug_init_cache(struct cache *);
#else
static inline void bcache_debug_init_cache(struct cache *c) {}
#endif

#endif
