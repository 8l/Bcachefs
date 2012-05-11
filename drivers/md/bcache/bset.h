#ifndef _BCACHE_BSET_H
#define _BCACHE_BSET_H

/* Btree key comparison/iteration */

struct btree_iter {
	size_t size, used;
	struct btree_iter_set {
		struct bkey *k, *end;
	} data[MAX_BSETS];
};

struct bset_tree {
	/*
	 * We construct a binary tree in an array as if the array
	 * started at 1, so that things line up on the same cachelines
	 * better: see comments in bset.c at cacheline_to_bkey() for
	 * details
	 */

	/* size of the binary tree and prev array */
	unsigned	size;

	/* function of size - precalculated for to_inorder() */
	unsigned	extra;

	/* copy of the last key in the set */
	struct bkey	end;
	struct bkey_float *tree;

	/*
	 * The nodes in the bset tree point to specific keys - this
	 * array holds the sizes of the previous key.
	 *
	 * Conceptually it's a member of struct bkey_float, but we want
	 * to keep bkey_float to 4 bytes and prev isn't used in the fast
	 * path.
	 */
	uint8_t		*prev;

	/* The actual btree node, with pointers to each sorted set */
	struct bset	*data;
};

static __always_inline int64_t bkey_cmp(const struct bkey *l,
					const struct bkey *r)
{
	return unlikely(KEY_DEV(l) != KEY_DEV(r))
		? (int64_t) KEY_DEV(l) - (int64_t) KEY_DEV(r)
		: (int64_t) l->key - (int64_t) r->key;
}

static inline size_t bkey_u64s(const struct bkey *k)
{
	BUG_ON(KEY_CSUM(k) > 1);
	return 2 + KEY_PTRS(k) + (KEY_CSUM(k) ? 1 : 0);
}

static inline size_t bkey_bytes(const struct bkey *k)
{
	return bkey_u64s(k) * sizeof(uint64_t);
}

static inline void bkey_copy(struct bkey *dest, const struct bkey *src)
{
	memcpy(dest, src, bkey_bytes(src));
}

static inline void bkey_copy_key(struct bkey *dest, const struct bkey *src)
{
	if (!src)
		src = &KEY(0, 0, 0);

	SET_KEY_DEV(dest, KEY_DEV(src));
	dest->key = src->key;
}

static inline struct bkey *next(const struct bkey *k)
{
	uint64_t *d = (void *) k;
	return (struct bkey *) (d + bkey_u64s(k));
}

/* Keylists */

struct keylist {
	struct bkey		*top;
	union {
		uint64_t		*list;
		struct bkey		*bottom;
	};

	/* Enough room for btree_split's keys without realloc */
#define KEYLIST_INLINE		16
	uint64_t		d[KEYLIST_INLINE];
};

static inline void keylist_init(struct keylist *l)
{
	l->top = (void *) (l->list = l->d);
}

static inline void keylist_push(struct keylist *l)
{
	l->top = next(l->top);
}

static inline void keylist_add(struct keylist *l, struct bkey *k)
{
	bkey_copy(l->top, k);
	keylist_push(l);
}

static inline bool keylist_empty(struct keylist *l)
{
	return l->top == (void *) l->list;
}

static inline void keylist_free(struct keylist *l)
{
	if (l->list != l->d)
		kfree(l->list);
}

void keylist_copy(struct keylist *, struct keylist *);
struct bkey *keylist_pop(struct keylist *);
int keylist_realloc(struct keylist *, int, struct cache_set *);

void bkey_copy_single_ptr(struct bkey *, const struct bkey *, unsigned);
bool __cut_front(const struct bkey *, struct bkey *);
bool __cut_back(const struct bkey *, struct bkey *);

static inline bool cut_front(const struct bkey *where, struct bkey *k)
{
	BUG_ON(bkey_cmp(where, k) > 0);
	return __cut_front(where, k);
}

static inline bool cut_back(const struct bkey *where, struct bkey *k)
{
	BUG_ON(bkey_cmp(where, &START_KEY(k)) < 0);
	return __cut_back(where, k);
}

const char *ptr_status(struct cache_set *, const struct bkey *);
bool __ptr_invalid(struct cache_set *, int level, const struct bkey *);
bool ptr_invalid(struct btree *, const struct bkey *);
bool ptr_bad(struct btree *, const struct bkey *);

static inline uint8_t gen_after(uint8_t a, uint8_t b)
{
	uint8_t r = a - b;
	return r > 128U ? 0 : r;
}

static inline uint8_t ptr_stale(struct cache_set *c, const struct bkey *k,
				unsigned i)
{
	return gen_after(PTR_BUCKET(c, k, i)->gen, PTR_GEN(k, i));
}

static inline bool ptr_available(struct cache_set *c, const struct bkey *k,
				 unsigned i)
{
	return (PTR_DEV(k, i) < MAX_CACHES_PER_SET) && PTR_CACHE(c, k, i);
}

struct bkey *next_recurse_key(struct btree *, struct bkey *);
struct bkey *btree_iter_next(struct btree_iter *);
void btree_iter_push(struct btree_iter *, struct bkey *, struct bkey *);
struct bkey *__btree_iter_init(struct btree *, struct btree_iter *,
			       struct bkey *, struct bset_tree *);

#define btree_iter_init(b, iter, search)			\
	__btree_iter_init(b, iter, search, (b)->sets)

#define BKEY_MID_BITS		3
#define BKEY_MID_MAX		(~(~0 << (BKEY_MID_BITS - 1)))
#define BKEY_MID_MIN		(-1 - BKEY_MID_MAX)

#define BKEY_EXPONENT_BITS	7
#define BKEY_MANTISSA_BITS	22
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)

struct bkey_float {
	unsigned	exponent:BKEY_EXPONENT_BITS;
	unsigned	m:BKEY_MID_BITS;
	unsigned	mantissa:BKEY_MANTISSA_BITS;
} __packed;

#define BSET_CACHELINE		128
#define BSET_CACHELINE_BITS	ilog2(BSET_CACHELINE)

#define bset_tree_space(b)	(btree_data_space(b) >> BSET_CACHELINE_BITS)

#define bset_tree_bytes(b)	(bset_tree_space(b) * sizeof(struct bkey_float))
#define bset_prev_bytes(b)	(bset_tree_bytes(b) >> 2)

void bset_init_next(struct btree *);

void bset_fix_invalidated_key(struct btree *, struct bkey *);
void bset_fix_lookup_table(struct btree *, struct bkey *);

struct bkey *__bset_search(struct btree *, struct bset_tree *,
			   const struct bkey *);
#define bset_search(b, t, search)				\
	((search) ? __bset_search(b, t, search) : (t)->data->start)

bool bkey_try_merge(struct btree *, struct bkey *, struct bkey *);
void btree_sort_lazy(struct btree *);
void btree_sort_into(struct btree *, struct btree *);
void btree_sort_and_fix_extents(struct btree *, struct btree_iter *);
void btree_sort_partial(struct btree *, unsigned);
#define btree_sort(b)	btree_sort_partial(b, 0)

int bset_print_stats(struct cache_set *, char *);

#endif
