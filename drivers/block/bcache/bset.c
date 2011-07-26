
#include "bcache.h"

#include <linux/random.h>

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
	if (KEY_PTRS(l) != KEY_PTRS(r) ||
	    KEY_DIRTY(l) != KEY_DIRTY(r) ||
	    bkey_cmp(l, &START_KEY(r)))
		return false;

	/* Keys with no pointers aren't restricted to one bucket, and buckets
	 * could be bigger max key size:
	 */
	if (KEY_SIZE(l) + KEY_SIZE(r) > USHRT_MAX)
		return false;

	for (unsigned j = 0; j < KEY_PTRS(l); j++)
		if (l->ptr[j] + PTR(0, KEY_SIZE(l), 0) != r->ptr[j] ||
		    PTR_BUCKET(b->c, l, j) != PTR_BUCKET(b->c, r, j))
			return false;

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

static unsigned bset_middle(struct bset *i, unsigned l, unsigned r)
{
	unsigned m = (l + r) >> 1;
	while (!KEY_IS_HEADER(node(i, m)))
		m--;

	if (m == l && next(node(i, m)) != node(i, r))
		m += bkey_u64s(node(i, m));

	return m;
}

static struct bkey *bset_bsearch(struct bset *i, const struct bkey *search,
				 unsigned l, unsigned r)
{
	/* Returns the smallest key greater than the search key.
	 * This is because we index by the end, not the beginning
	 */
	while (l < r) {
		unsigned m = bset_middle(i, l, r);

		if (bkey_cmp(node(i, m), search) > 0)
			r = m;
		else
			l = m + bkey_u64s(node(i, m));
	}

	return node(i, l);
}

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

void bset_build_tree_noalloc(struct btree *b, unsigned set)
{
	struct bset *i		= b->sets[set];
	struct bset_tree *t	= &b->tree[set];

	int dif(struct bkey *k, unsigned mid)
	{
		return (((uint64_t *) k) - i->d) - mid;
	}

	bool check(struct bkey *k, struct bkey_float *f, unsigned mid)
	{
		if (bfloat_mantissa(k, f) == bfloat_mantissa(prev(k), f))
			return false;

		f->m = dif(k, mid);
		return true;
	}

	void make_key(struct bkey_float *f, unsigned l, unsigned r)
	{
		struct bkey *kl = node(i, l), *kr = node(i, r);
		unsigned mid = (l + r) >> 1, m = mid;

		if (m != r)
			m = bset_middle(i, l, r);

		if (kr == end(i))
			kr = prev(kr);

		if (kl != i->start)
			kl = prev(kl);

		if (KEY_DEV(kl) != KEY_DEV(kr))
			f->exponent = fls64(KEY_DEV(kr) ^ KEY_DEV(kl)) +
				BKEY_MANTISSA_SHIFT;
		else if (kl->key != kr->key)
			f->exponent = fls64(kr->key ^ kl->key);

		f->exponent = max_t(int, f->exponent - BKEY_MANTISSA_BITS, 0);

		kl = node(i, m);
		kr = next(kl);

		while (1) {
			if (-dif(kl, mid) < dif(kr, mid)) {
				if (dif(kl, mid) * 2 < dif(node(i, l), mid) ||
				    dif(kl, mid) < BKEY_MID_MIN)
					goto no_pivot;

				if (check(kl, f, mid))
					goto pivot;

				kl = prev(kl);
			} else {
				if (dif(kr, mid) * 2 > dif(node(i, r), mid) ||
				    dif(kr, mid) > BKEY_MID_MAX)
					goto no_pivot;

				if (check(kr, f, mid))
					goto pivot;

				kr = next(kr);
			}
		}

		if (0) {
no_pivot:		f->m = m - mid;
			f->exponent = 127;
		} else {
pivot:			m = mid + f->m;
			f->mantissa = bfloat_mantissa(node(i, m), f);
		}

		BUG_ON(m < l || m > r);
		BUG_ON(!KEY_IS_HEADER(node(i, m)));
	}

	struct {
		unsigned l, r;
	} stack[22], *sp = stack;

	size_t j = 1;

	if (!t->size)
		return;

	bkey_copy_key(&t->end, prev(end(i)));

	sp->l = 0;
	sp->r = i->keys;

	/* Depth first traversal */
	while (1) {
		sp = &stack[ilog2(j)];
		make_key(t->key + j, sp->l, sp->r);

		if (j == t->size - 1)
			break;

		if (j * 2 < t->size) {
			sp[1].l = sp->l;
			sp[1].r = ((sp->l + sp->r) >> 1) + t->key[j].m;

			j = j * 2;
		} else {
			j >>= ffz(j) + 1;
			sp = &stack[ilog2(j)];

			sp[1].l = ((sp->l + sp->r) >> 1) + t->key[j].m;
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

	t->size = min_t(size_t, end - t->key,
			roundup_pow_of_two((i->keys * sizeof(uint64_t)) / 96));

	BUG_ON(t->key + t->size > end);

	if (t->size < 2)
		t->size = 0;

	bset_build_tree_noalloc(b, set);
}

struct bkey *__bset_search(struct btree *b, unsigned set,
			   const struct bkey *search)
{
	struct bset *i		= b->sets[set];
	struct bset_tree *t	= &b->tree[set];
	unsigned j = 1, l = 0, r = i->keys;

	if (!t->size)
		goto bsearch;

	BUG_ON(i == write_block(b));

	/* i->start will be in cache since it's right next to the header */
	if (bkey_cmp(search, i->start) < 0)
		return i->start;

	/* prev(end(i)) won't be */
	if (bkey_cmp(search, &t->end) >= 0)
		return node(i, r);

	while (j < t->size) {
		bool cmp;
		struct bkey_float *f = &t->key[j];
		unsigned m = ((l + r) >> 1) + f->m;

		if (j << 4 < t->size)
			prefetch(&t->key[j << 4]);

		EBUG_ON(m < l || m > r);
		EBUG_ON(!KEY_IS_HEADER(node(i, m)));

		if (f->exponent < 127)
			cmp = f->mantissa > bfloat_mantissa(search, f);
		else
			cmp = bkey_cmp(node(i, m), search) > 0;

		if (cmp) {
			EBUG_ON(m != i->keys &&
				bkey_cmp(node(i, m), search) <= 0);

			r = m;
			j = j * 2;
		} else {
			EBUG_ON(m && bkey_cmp(prev(node(i, m)), search) > 0);

			l = m;
			j = j * 2 + 1;
		}
	}
bsearch:
	return bset_bsearch(i, search, l, r);
}

#define bset_search(b, i, search)				\
	(search ? __bset_search(b, i, search) : b->sets[i]->start)

/* Btree iterator */

static inline bool btree_iter_cmp(struct btree_iter_set l,
				  struct btree_iter_set r)
{
	return bkey_cmp(&START_KEY(l.k), &START_KEY(r.k)) > 0;
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
		    (bkey_cmp(&START_KEY(i[0].k), &START_KEY(i[1].k)) > 0 ||
		     (i[0].k < i[1].k &&
		      !bkey_cmp(&START_KEY(i[0].k), &START_KEY(i[1].k)))))
			i++;

		if (top->k < i->k &&
		    !bkey_cmp(&START_KEY(top->k), &START_KEY(i->k)))
			swap(*top, *i);

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

	if (b->level)
		fixup = false;

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
		if (fixup)
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
	BUG_ON(!fixup && !remove_stale && count_data(b) < oldsize);
}

void btree_sort(struct btree *b, int start, struct bset *new)
{
	struct btree_iter iter;
	__btree_iter_init(b, &iter, NULL, start);

	__btree_sort(b, start, new, &iter, false);
}

void btree_sort_lazy(struct btree *b)
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
				return;
			}

			keys -= b->sets[j]->keys;
		}
	}

	if (b->nsets > 2 - b->level)
		btree_sort(b, 0, NULL);
}
