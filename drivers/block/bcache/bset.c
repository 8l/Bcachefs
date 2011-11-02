
#include "bcache.h"
#include "btree.h"
#include "debug.h"

#include <linux/random.h>

#define BKEY_MID_BITS		3
#define BKEY_MID_MAX		(~(~0 << (BKEY_MID_BITS - 1)))
#define BKEY_MID_MIN		(-1 - BKEY_MID_MAX)

#define BKEY_EXPONENT_BITS	7
#define BKEY_MANTISSA_BITS	22
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)
#define BKEY_MANTISSA_SHIFT	63

struct bkey_float {
	unsigned	m:BKEY_MID_BITS;
	unsigned	exponent:BKEY_EXPONENT_BITS;
	unsigned	mantissa:BKEY_MANTISSA_BITS;
};

#define bset_tree_space(b)						\
	((PAGE_SIZE << bset_tree_order(b)) / sizeof(struct bkey_float))

/* Keylists */

void keylist_copy(struct keylist *dest, struct keylist *src)
{
	*dest = *src;

	if (src->list == src->d) {
		size_t n = (uint64_t *) src->top - src->d;
		dest->top = (struct bkey *) &dest->d[n];
		dest->list = dest->d;
	}
}

int keylist_realloc(struct keylist *l, int nptrs)
{
	unsigned n = (uint64_t *) l->top - l->list;
	unsigned size = roundup_pow_of_two(n + 2 + nptrs);
	uint64_t *new;

	if (size <= KEYLIST_INLINE ||
	    roundup_pow_of_two(n) == size)
		return 0;

	new = krealloc(l->list == l->d ? NULL : l->list,
		       sizeof(uint64_t) * size, GFP_NOIO);

	if (!new)
		return -ENOMEM;

	if (l->list == l->d)
		memcpy(new, l->list, sizeof(uint64_t) * KEYLIST_INLINE);

	l->list = new;
	l->top = (struct bkey *) (&l->list[n]);

	return 0;
}

struct bkey *keylist_pop(struct keylist *l)
{
	if (l->top == (struct bkey *) l->list)
		return NULL;

	l->top = prev(l->top);
	BUG_ON((uint64_t *) l->top < l->list);

	return l->top;
}

/* Pointer validation */

bool __ptr_invalid(struct cache_set *c, int level, const struct bkey *k)
{
	if (level && (!KEY_PTRS(k) || !KEY_SIZE(k) || KEY_DIRTY(k)))
		return true;

	if (!level && KEY_SIZE(k) > k->key)
		return true;

	if (!KEY_SIZE(k))
		return true;

	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct cache *ca = PTR_CACHE(c, k, i);
		size_t bucket = PTR_BUCKET_NR(c, k, i);
		size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

		if (KEY_SIZE(k) + r > c->sb.bucket_size ||
		    PTR_DEV(k, i) > MAX_CACHES_PER_SET)
			return true;

		if (ca &&
		    (bucket <  ca->sb.first_bucket ||
		     bucket >= ca->sb.nbuckets))
			return true;
	}

	return false;
}

bool ptr_invalid(struct btree *b, const struct bkey *k)
{
	if (!KEY_SIZE(k))
		return true;

	if (!__ptr_invalid(b->c, b->level, k))
		return false;

	btree_bug(b, "spotted bad key %s: %s", pkey(k), ptr_status(b->c, k));
	return true;
}

bool ptr_bad(struct btree *b, const struct bkey *k)
{
	struct bucket *g;
	const char *err;
	unsigned i, stale;

	if (!bkey_cmp(k, &ZERO_KEY) || !KEY_PTRS(k) || ptr_invalid(b, k))
		return true;

	for (i = 0; i < KEY_PTRS(k); i++) {
		if (!PTR_CACHE(b->c, k, i))
			return true;

		g = PTR_BUCKET(b->c, k, i);
		stale = ptr_stale(b->c, k, i);

		btree_bug_on(stale > 96, b, "key too stale: %i, need_gc %u",
			     stale, b->c->need_gc);

		btree_bug_on(stale && KEY_DIRTY(k) && KEY_SIZE(k),
			     b, "stale dirty pointer");

		if (stale)
			return true;

		if (b->level) {
			err = "btree";
			if (KEY_DIRTY(k) ||
			    g->prio != btree_prio ||
			    (b->c->gc_mark_valid &&
			     g->mark != GC_MARK_BTREE))
				goto bug;
		} else {
			err = "data";
			if (g->prio == btree_prio)
				goto bug;

			err = "dirty";
			if (KEY_DIRTY(k) &&
			    b->c->gc_mark_valid &&
			    g->mark != GC_MARK_DIRTY)
				goto bug;
		}
	}

	return false;
bug:
	btree_bug(b, "inconsistent %s pointer %s: bucket %li pin %i "
		  "prio %i gen %i last_gc %i mark %i gc_gen %i", err, pkey(k),
		  PTR_BUCKET_NR(b->c, k, i), atomic_read(&g->pin),
		  g->prio, g->gen, g->last_gc, g->mark, g->gc_gen);
	return true;
}

/* Key/pointer manipulation */

bool __cut_front(const struct bkey *where, struct bkey *k)
{
	unsigned len = 0;

	if (bkey_cmp(where, &START_KEY(k)) <= 0)
		return false;

	if (bkey_cmp(where, k) < 0)
		len = k->key - where->key;
	else
		bkey_copy_key(k, where);

	for (unsigned i = 0; i < KEY_PTRS(k); i++)
		SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + KEY_SIZE(k) - len);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);
	return true;
}

bool __cut_back(const struct bkey *where, struct bkey *k)
{
	unsigned len = 0;

	if (bkey_cmp(where, k) >= 0)
		return false;

	BUG_ON(KEY_DEV(where) != KEY_DEV(k));

	if (bkey_cmp(where, &START_KEY(k)) > 0)
		len = where->key - KEY_START(k);

	bkey_copy_key(k, where);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);
	return true;
}

static uint64_t merge_chksums(struct bkey *l, struct bkey *r)
{
	return (l->ptr[KEY_PTRS(l)] + r->ptr[KEY_PTRS(r)]) &
		~((uint64_t)1 << 63);
}

/* Tries to merge l and r: l should be lower than r
 * Returns true if we were able to merge. If we did merge, l will be the merged
 * key, r will be untouched.
 */
bool bkey_try_merge(struct btree *b, struct bkey *l, struct bkey *r)
{
	if (key_merging_disabled(b->c))
		return false;

	if (KEY_PTRS(l) != KEY_PTRS(r) ||
	    KEY_DIRTY(l) != KEY_DIRTY(r) ||
	    bkey_cmp(l, &START_KEY(r)))
		return false;

	for (unsigned j = 0; j < KEY_PTRS(l); j++)
		if (l->ptr[j] + PTR(0, KEY_SIZE(l), 0) != r->ptr[j] ||
		    PTR_BUCKET(b->c, l, j) != PTR_BUCKET(b->c, r, j))
			return false;

	/* Keys with no pointers aren't restricted to one bucket and could
	 * overflow KEY_SIZE
	 */
	if (KEY_SIZE(l) + KEY_SIZE(r) > USHRT_MAX) {
		l->key += USHRT_MAX - KEY_SIZE(l);
		SET_KEY_SIZE(l, USHRT_MAX);

		cut_front(l, r);
		return false;
	}

	if (KEY_CSUM(l)) {
		if (KEY_CSUM(r))
			l->ptr[KEY_PTRS(l)] = merge_chksums(l, r);
		else
			SET_KEY_CSUM(l, 0);
	}

	SET_KEY_SIZE(l, KEY_SIZE(l) + KEY_SIZE(r));
	l->key += KEY_SIZE(r);

	return true;
}

void bset_init(struct btree *b, struct bset *i)
{
	if (i != b->data) {
		b->sets[++b->nsets] = i;
		i->seq = b->data->seq;
	} else
		get_random_bytes(&b->data->seq, sizeof(uint64_t));

	i->magic	= bset_magic(b->c);
	i->version	= 0;
	i->keys		= 0;
}

/* Bset binary search */

static struct bkey *bset_bsearch(struct bset *i, const struct bkey *search)
{
	unsigned l = 0, r = i->keys;

	/* Returns the smallest key greater than the search key.
	 * This is because we index by the end, not the beginning
	 */
	while (l < r) {
		unsigned m = (l + r) >> 1;
		while (!KEY_IS_HEADER(node(i, m)))
			m--;

		if (m == l && next(node(i, m)) != node(i, r))
			m += bkey_u64s(node(i, m));

		if (bkey_cmp(node(i, m), search) > 0)
			r = m;
		else
			l = m + bkey_u64s(node(i, m));
	}

	return node(i, l);
}

/* Auxiliary search trees */

static unsigned bfloat_mantissa(const struct bkey *k, struct bkey_float *f)
{
	unsigned r;
	BUG_ON(f->exponent == 127);

	if (f->exponent < BKEY_MANTISSA_SHIFT)
		r = (k->key >> f->exponent) |
			(KEY_DEV(k) << (BKEY_MANTISSA_SHIFT - f->exponent));
	else
		r = KEY_DEV(k) >> (f->exponent - BKEY_MANTISSA_SHIFT);

	return r & BKEY_MANTISSA_MASK;
}

static void make_bfloat(struct bkey_float *f,
			struct bkey *l, struct bkey *r,
			struct bkey *m, struct bkey *p)
{
	BUG_ON(m < l || m > r);
	BUG_ON(!KEY_IS_HEADER(m));
	BUG_ON(!KEY_IS_HEADER(p));
	BUG_ON(next(p) != m);

	if (KEY_DEV(l) != KEY_DEV(r))
		f->exponent = fls64(KEY_DEV(r) ^ KEY_DEV(l)) +
			BKEY_MANTISSA_SHIFT;
	else if (l->key != r->key)
		f->exponent = fls64(r->key ^ l->key);

	f->exponent = max_t(int, f->exponent - BKEY_MANTISSA_BITS, 0);

	if (bfloat_mantissa(m, f) !=
	    bfloat_mantissa(p, f))
		f->mantissa = bfloat_mantissa(m, f);
	else
		f->exponent = 127;
}

static unsigned inorder_next(unsigned j, unsigned size)
{
	if (j * 2 + 1 < size) {
		j = j * 2 + 1;

		while (j * 2 < size)
			j *= 2;
	} else
		j >>= ffz(j) + 1;

	return j;
}

static unsigned inorder_prev(unsigned j, unsigned size)
{
	if (j * 2 < size) {
		j = j * 2;

		while (j * 2 + 1 < size)
			j = j * 2 + 1;
	} else
		j >>= ffs(j);

	return j;
}

/* I have no idea why this code works... and I'm the one who wrote it
 *
 * However, I do know what it does:
 * Given a binary tree constructed in an array (i.e. how you normally implement
 * a heap), it converts a node in the tree - referenced by array index - to the
 * index it would have if you did an inorder traversal.
 *
 * The binary tree starts at array index 1, not 0
 * extra is a function of size:
 *   extra = (size - rounddown_pow_of_two(size - 1)) << 1;
 */
static unsigned __to_inorder(unsigned j, unsigned size, unsigned extra)
{
	unsigned b = fls(j);
	unsigned shift = fls(size - 1) - b;

	j  ^= 1U << (b - 1);
	j <<= 1;
	j  |= 1;
	j <<= shift;

	if (j > extra)
		j -= (j - extra) >> 1;

	return j;
}

static unsigned to_inorder(unsigned j, struct bset_tree *t)
{
	return __to_inorder(j, t->size, t->extra);
}

#if 0
void inorder_test(void)
{
	unsigned long done = 0;
	ktime_t start = ktime_get();

	for (unsigned size = 2;
	     size < 65536000;
	     size++) {
		unsigned extra = (size - rounddown_pow_of_two(size - 1)) << 1;
		unsigned i = 1, j = rounddown_pow_of_two(size - 1);

		if (!(size % 4096))
			printk(KERN_NOTICE "loop %u, %llu per us\n", size,
			       done / ktime_us_delta(ktime_get(), start));

		while (1) {
			if (__to_inorder(j, size, extra) != i)
				panic("size %10u j %10u i %10u", size, j, i);

			if (j == rounddown_pow_of_two(size) - 1)
				break;

			BUG_ON(inorder_prev(inorder_next(j, size), size) != j);

			j = inorder_next(j, size);
			i++;
		}

		done += size - 1;
	}
}
#endif

static inline unsigned bset_tree_to_idx(struct bkey_float *f, unsigned i)
{
	return ((i * 64) - sizeof(struct bset)) / sizeof(uint64_t) + f->m;
}

static struct bkey *inorder_to_bkey(struct bset *i, struct bkey_float *f,
				    unsigned inorder)
{
	void *cacheline = ((void *) i) + 64 * inorder;
	return cacheline + f->m * sizeof(uint64_t);
}

static struct bkey *tree_to_bkey(struct bset *i, unsigned j,
				 struct bset_tree *t)
{
	return inorder_to_bkey(i, &t->key[j], to_inorder(j, t));
}

void bset_build_tree_noalloc(struct btree *b, unsigned set)
{
	struct bset_tree *t	= &b->tree[set];
	struct bset *i		= b->sets[set];
	struct bkey *k		= i->start;

	struct {
		unsigned l;
		unsigned r:27;
		unsigned p:5;
	} stack[22], *sp = stack;

	unsigned j, end;
	size_t cacheline = (((size_t) i) >> 6) + 1;

	if (!t->size)
		return;

	j	= rounddown_pow_of_two(t->size - 1);
	end	= rounddown_pow_of_two(t->size) - 1;

	/* Inorder traversal */
	while (1) {
		struct bkey_float *f = &t->key[j];

		while ((((size_t) next(k)) >> 6) != cacheline)
			k = next(k);

		f->exponent = bkey_u64s(k);
		k = next(k);
		cacheline++;
		f->m = ((size_t) k & 63) / sizeof(uint64_t);

		if (j == end)
			break;

		j = inorder_next(j, t->size);
	}

	while (next(k) != end(i))
		k = next(k);

	bkey_copy_key(&t->end, k);

	sp->l = 0;
	sp->r = (uint64_t *) k - i->d;

	j = 1;
	if (is_power_of_2(t->size + 1))
		end = t->size - 1;

	/* Depth first traversal */
	while (1) {
		struct bkey_float *f = &t->key[j];
		unsigned m;

		sp = &stack[ilog2(j)];

		m = bset_tree_to_idx(f, to_inorder(j, t));
		sp->p = f->exponent;

		make_bfloat(f, node(i, sp->l), node(i, sp->r),
			       node(i, m), node(i, m - sp->p));

		if (j == end)
			break;

		if (j * 2 < t->size) {
			sp[1].l = sp->l;
			sp[1].r = m;

			j = j * 2;
		} else {
			if (j == t->size - 1)
				j >>= 1;

			j >>= ffz(j) + 1;

			sp = &stack[ilog2(j)];

			f = &t->key[j];
			m = bset_tree_to_idx(f, to_inorder(j, t));

			sp[1].l = m - sp->p;
			sp[1].r = sp->r;

			j = j * 2 + 1;
		}
	}
}

void bset_build_tree(struct btree *b, unsigned set)
{
	struct bset *i		= b->sets[set];
	struct bset_tree *t	= &b->tree[set];
	struct bkey_float *end	= b->tree->key + bset_tree_space(b);

	BUG_ON(set >= 4);

	for (int j = set; j < 4; j++)
		b->tree[j].size = 0;

	if (!b->tree->key)
		return;

	if (set) {
		struct bset_tree *p = &b->tree[set - 1];
		t->key = p->key + roundup(p->size,
					  64 / sizeof(struct bkey_float));
	}

	t->size = ((size_t) end(i) - (size_t) i) / 64;

	if (t->size < 2)
		t->size = 0;
	else
		t->extra = (t->size - rounddown_pow_of_two(t->size - 1)) << 1;

	if (t->size > (size_t) (end - t->key)) {
		pr_debug("not enough space for tree");
		t->size = end - t->key;
	}

	bset_build_tree_noalloc(b, set);
}

struct bkey *__bset_search(struct btree *b, unsigned set,
			   const struct bkey *search)
{
	struct bset *i		= b->sets[set];
	struct bset_tree *t	= &b->tree[set];

	struct bkey *l, *r;
	unsigned j = 1;

	struct bkey *cur(void)
	{
		return tree_to_bkey(i, j, t);
	}

	if (!t->size)
		return bset_bsearch(i, search);

	BUG_ON(i == write_block(b));

	/* prev(end(i)) won't be in the cache */
	if (bkey_cmp(search, &t->end) >= 0)
		return end(i);

	/* i->start will be in cache since it's right next to the header */
	if (bkey_cmp(search, i->start) < 0)
		return i->start;

	while (1) {
		bool cmp;
		struct bkey_float *f = &t->key[j];

		if (j << 4 < t->size)
			prefetch(&t->key[j << 4]);

		EBUG_ON(!KEY_IS_HEADER(cur()));

		if (f->exponent < 127)
			cmp = f->mantissa > bfloat_mantissa(search, f);
		else
			cmp = bkey_cmp(cur(), search) > 0;

		if (cmp) {
			EBUG_ON(cur() != end(i) &&
				bkey_cmp(cur(), search) <= 0);

			if (j * 2 >= t->size) {
				unsigned inorder = to_inorder(j, t);
				r = inorder_to_bkey(i, f, inorder);

				if (--inorder) {
					f = &t->key[inorder_prev(j, t->size)];
					l = inorder_to_bkey(i, f, inorder);
				} else
					l = i->start;

				break;
			}

			j = j * 2;
		} else {
			EBUG_ON(cur() != i->start &&
				bkey_cmp(prev(cur()), search) > 0);

			if (j * 2 + 1 >= t->size) {
				unsigned inorder = to_inorder(j, t);
				l = inorder_to_bkey(i, f, inorder);

				if (++inorder != t->size) {
					f = &t->key[inorder_next(j, t->size)];
					r = inorder_to_bkey(i, f, inorder);
				} else
					r = end(i);

				break;
			}

			j = j * 2 + 1;
		}
	}

	while (l != r &&
	       bkey_cmp(l, search) <= 0)
		l = next(l);

	return l;
}

/* Btree iterator */

static inline bool btree_iter_cmp(struct btree_iter_set l,
				  struct btree_iter_set r)
{
	int64_t c = bkey_cmp(&START_KEY(l.k), &START_KEY(r.k));

	return c ? c > 0 : l.k < r.k;
}

static inline bool btree_iter_end(struct btree_iter *iter)
{
	return !iter->used;
}

void btree_iter_push(struct btree_iter *iter, struct bkey *k, struct bkey *end)
{
	if (k != end)
		BUG_ON(!heap_add(iter,
				 ((struct btree_iter_set) { k, end }),
				 btree_iter_cmp));
}

struct bkey *__btree_iter_init(struct btree *b, struct btree_iter *iter,
			       struct bkey *search, int start)
{
	struct bkey *ret = NULL;
	iter->size = 8;
	iter->used = 0;

	for (int i = start; i <= b->nsets; i++) {
		ret = bset_search(b, i, search);
		btree_iter_push(iter, ret, end(b->sets[i]));
	}

	return ret;
}

struct bkey *btree_iter_next(struct btree_iter *iter)
{
	struct btree_iter_set unused;
	struct bkey *ret = NULL;

	if (!btree_iter_end(iter)) {
		ret = iter->data->k;
		iter->data->k = next(iter->data->k);

		if (iter->data->k > iter->data->end) {
			__WARN();
			iter->data->k = iter->data->end;
		}

		if (iter->data->k == iter->data->end)
			heap_pop(iter, unused, btree_iter_cmp);
		else
			heap_sift(iter, 0, btree_iter_cmp);
	}

	return ret;
}

struct bkey *next_recurse_key(struct btree *b, struct bkey *search)
{
	struct bkey *k, *ret = NULL;

	for_each_key_after_filter(b, k, search, ptr_bad) {
		if (!ret || bkey_cmp(k, ret) < 0)
			ret = k;
		/* We're actually in two loops here, looping over the sorted
		 * sets and then the keys within each set - break out of the
		 * inner loop and still loop over the sorted sets
		 */
		break;
	}

	return ret;
}

/* Mergesort */

static void btree_sort_fixup(struct btree_iter *iter)
{
	while (iter->used > 1) {
		struct btree_iter_set *top = iter->data, *i = top + 1;
		struct bkey *k;

		if (iter->used > 2 &&
		    btree_iter_cmp(i[0], i[1]))
			i++;

		for (k = i->k;
		     k != i->end && bkey_cmp(top->k, &START_KEY(k)) > 0;
		     k = next(k))
			if (top->k > i->k)
				__cut_front(top->k, k);
			else if (KEY_SIZE(k))
				cut_back(&START_KEY(k), top->k);

		if (top->k < i->k || k == i->k)
			break;

		heap_sift(iter, i - top, btree_iter_cmp);
	}
}

void __btree_sort(struct btree *b, int start, struct bset *new,
		  struct btree_iter *iter, bool fixup)
{
	size_t oldsize = 0, order = b->page_order, keys = 0;
	struct bset *out = new;
	struct bkey *k, *last = NULL;
	bool remove_stale = new || !b->written;

	bool (*bad)(struct btree *, const struct bkey *) = remove_stale
		? ptr_bad
		: ptr_invalid;

	BUG_ON(remove_stale && fixup);

	if (!fixup && !remove_stale)
		oldsize = count_data(b);

	if (start) {
		struct bset *i;
		for_each_sorted_set_start(b, i, start)
			keys += i->keys;

		order = roundup_pow_of_two(__set_bytes(i, keys)) / PAGE_SIZE;
		if (order)
			order = ilog2(order);
	}

	if (!out)
		out = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOIO, order);
	if (!out) {
		mutex_lock(&b->c->sort_lock);
		out = b->c->sort;
		order = ilog2(bucket_pages(b->c));
	}

	while (!btree_iter_end(iter)) {
		if (fixup && !b->level)
			btree_sort_fixup(iter);

		k = btree_iter_next(iter);
		if (bad(b, k))
			continue;

		if (!last) {
			last = out->start;
			bkey_copy(last, k);
		} else if (b->level ||
			   !bkey_try_merge(b, last, k)) {
			last = next(last);
			bkey_copy(last, k);
		}
	}

	out->keys = last ? (uint64_t *) next(last) - out->d : 0;

	if (!fixup && !start && !remove_stale)
		btree_verify(b, out);

	if (new)
		return;

	b->nsets = start;

	if (!start && order == b->page_order) {
		out->magic	= bset_magic(b->c);
		out->seq	= b->data->seq;
		out->version	= b->data->version;
		swap(out, b->data);

		if (b->c->sort == b->data)
			b->c->sort = out;
	} else {
		b->sets[start]->keys = out->keys;
		memcpy(b->sets[start]->start, out->start,
		       (void *) end(out) - (void *) out->start);
	}

	if (out == b->c->sort)
		mutex_unlock(&b->c->sort_lock);
	else
		free_pages((unsigned long) out, order);

	bset_build_tree(b, start);

	pr_debug("sorted %i keys", b->sets[start]->keys);
	check_key_order(b, b->sets[start]);
	EBUG_ON(!fixup && !remove_stale && count_data(b) != oldsize);
}

void btree_sort(struct btree *b, int start, struct bset *new)
{
	struct btree_iter iter;
	__btree_iter_init(b, &iter, NULL, start);

	__btree_sort(b, start, new, &iter, false);
}

bool btree_sort_lazy(struct btree *b)
{
	if (b->nsets) {
		struct bset *i;
		unsigned keys = 0, total;

		for_each_sorted_set(b, i)
			keys += i->keys;
		total = keys;

		for (unsigned j = 0; j < b->nsets; j++) {
			if (keys * 2 < total ||
			    keys < 1000) {
				btree_sort(b, j, NULL);
				return true;
			}

			keys -= b->sets[j]->keys;
		}

		if (b->nsets > 2 - b->level) {
			btree_sort(b, 0, NULL);
			return true;
		}
	}

	return false;
}

/* Sysfs stuff */

struct bset_stats {
	size_t writes, sets, keys, trees, floats, failed, tree_space;
};

static int btree_bset_stats(struct btree *b, struct btree_op *op,
			    struct bset_stats *stats)
{
	struct bkey *k;

	if (write_block(b) == b->sets[b->nsets])
		stats->writes++;
	stats->sets		+= b->nsets + 1;
	stats->tree_space	+= bset_tree_space(b);

	for (int i = 0; i < 4 && b->tree[i].size; i++) {
		stats->trees++;
		stats->keys	+= b->sets[i]->keys * sizeof(uint64_t);
		stats->floats	+= b->tree[i].size - 1;

		for (size_t j = 1; j < b->tree[i].size; j++)
			if (b->tree[i].key[j].exponent == 127)
				stats->failed++;
	}

	if (b->level)
		for_each_key_filter(b, k, ptr_bad) {
			int ret = btree(bset_stats, k, b, op, stats);
			if (ret)
				return ret;
		}

	return 0;
}

int bset_print_stats(struct cache_set *c, char *buf)
{
	struct btree_op op;
	struct bset_stats t;

	btree_op_init_stack(&op);
	memset(&t, 0, sizeof(struct bset_stats));

	btree_root(bset_stats, c, &op, &t);

	return snprintf(buf, PAGE_SIZE,
			"sets:		%zu\n"
			"write sets:	%zu\n"
			"key bytes:	%zu\n"
			"trees:		%zu\n"
			"tree space:	%zu\n"
			"floats:		%zu\n"
			"bytes/float:	%zu\n"
			"failed:		%zu\n",
			t.sets, t.writes, t.keys, t.trees, t.tree_space,
			t.floats, DIV_SAFE(t.keys, t.floats), t.failed);
}
