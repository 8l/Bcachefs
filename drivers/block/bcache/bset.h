#ifndef _BCACHE_BSET_H
#define _BCACHE_BSET_H

/* Btree key comparison/iteration */

struct btree_iter {
	size_t size, used;
	struct btree_iter_set {
		struct bkey *k, *end;
	} data[5];
	/* Has to be 1 greater than the normal max for coalescing in
	 * btree_gc_recurse() */
};

static inline int64_t bkey_cmp(const struct bkey *l, const struct bkey *r)
{
	return (int64_t) KEY_DEV(l) - (int64_t) KEY_DEV(r)
		?: (int64_t) l->key - (int64_t) r->key;
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

static inline struct bkey *prev(const struct bkey *k)
{
	uint64_t *d = (void *) k;
	do {
		--d;
	} while (!KEY_IS_HEADER((struct bkey *) d));

	return (struct bkey *) d;
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
#ifdef CONFIG_BCACHE_EDEBUG
	uint64_t *i = (uint64_t *) l->top;
	while (++i < (uint64_t *) next(l->top))
		BUG_ON(KEY_IS_HEADER((struct bkey *) i));
#endif
	BUG_ON(!KEY_IS_HEADER(l->top));
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
int keylist_realloc(struct keylist *, int);

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

struct bkey *next_recurse_key(struct btree *, struct bkey *);
struct bkey *btree_iter_next(struct btree_iter *);
void btree_iter_push(struct btree_iter *, struct bkey *, struct bkey *);
struct bkey *__btree_iter_init(struct btree *, struct btree_iter *,
			       struct bkey *, int);

#define btree_iter_init(b, iter, search)			\
	__btree_iter_init(b, iter, search, 0)

void bset_init(struct btree *, struct bset *);
void bset_build_tree_noalloc(struct btree *, unsigned);
void bset_build_tree(struct btree *, unsigned);

struct bkey *__bset_search(struct btree *, unsigned, const struct bkey *);
#define bset_search(b, i, search)				\
	(search ? __bset_search(b, i, search) : b->sets[i]->start)

bool bkey_try_merge(struct btree *, struct bkey *, struct bkey *);
void btree_sort_lazy(struct btree *);
void btree_sort(struct btree *, int, struct bset *);
void __btree_sort(struct btree *, int, struct bset *,
		  struct btree_iter *, bool);

int bset_print_stats(struct cache_set *, char *);

#endif
