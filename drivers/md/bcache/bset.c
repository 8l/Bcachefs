
#include "bcache.h"
#include "btree.h"
#include "debug.h"

#include <linux/random.h>

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

int keylist_realloc(struct keylist *l, int nptrs, struct cache_set *c)
{
	unsigned oldsize = (uint64_t *) l->top - l->list;
	unsigned newsize = oldsize + 2 + nptrs;
	uint64_t *new;

	/* The journalling code doesn't handle the case where the keys to insert
	 * is bigger than an empty write: If we just return -ENOMEM here,
	 * bio_insert() and bio_invalidate() will insert the keys created so far
	 * and finish the rest when the keylist is empty.
	 */
	if (newsize * sizeof(uint64_t) > block_bytes(c) - sizeof(struct jset))
		return -ENOMEM;

	newsize = roundup_pow_of_two(newsize);

	if (newsize <= KEYLIST_INLINE ||
	    roundup_pow_of_two(oldsize) == newsize)
		return 0;

	new = krealloc(l->list == l->d ? NULL : l->list,
		       sizeof(uint64_t) * newsize, GFP_NOIO);

	if (!new)
		return -ENOMEM;

	if (l->list == l->d)
		memcpy(new, l->list, sizeof(uint64_t) * KEYLIST_INLINE);

	l->list = new;
	l->top = (struct bkey *) (&l->list[oldsize]);

	return 0;
}

struct bkey *keylist_pop(struct keylist *l)
{
	struct bkey *k = l->bottom;

	if (k == l->top)
		return NULL;

	while (next(k) != l->top)
		k = next(k);

	return l->top = k;
}

/* Pointer validation */

bool __ptr_invalid(struct cache_set *c, int level, const struct bkey *k)
{
	if (level && (!KEY_PTRS(k) || !KEY_SIZE(k) || KEY_DIRTY(k)))
		goto bad;

	if (!level && KEY_SIZE(k) > k->key)
		goto bad;

	if (!KEY_SIZE(k))
		return true;

	for (unsigned i = 0; i < KEY_PTRS(k); i++)
		if (ptr_available(c, k, i)) {
			struct cache *ca = PTR_CACHE(c, k, i);
			size_t bucket = PTR_BUCKET_NR(c, k, i);
			size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > c->sb.bucket_size ||
			    bucket <  ca->sb.first_bucket ||
			    bucket >= ca->sb.nbuckets)
				goto bad;
		}

	return false;
bad:
	cache_bug(c, "spotted bad key %s: %s", pkey(k), ptr_status(c, k));
	return true;
}

bool ptr_invalid(struct btree *b, const struct bkey *k)
{
	return __ptr_invalid(b->c, b->level, k);
}

bool ptr_bad(struct btree *b, const struct bkey *k)
{
	struct bucket *g;
	unsigned i, stale;

	if (!bkey_cmp(k, &ZERO_KEY) ||
	    !KEY_PTRS(k) ||
	    ptr_invalid(b, k))
		return true;

	if (KEY_PTRS(k) && PTR_DEV(k, 0) == PTR_CHECK_DEV)
		return true;

	for (i = 0; i < KEY_PTRS(k); i++)
		if (ptr_available(b->c, k, i)) {
			g = PTR_BUCKET(b->c, k, i);
			stale = ptr_stale(b->c, k, i);

			btree_bug_on(stale > 96, b,
				     "key too stale: %i, need_gc %u",
				     stale, b->c->need_gc);

			btree_bug_on(stale && KEY_DIRTY(k) && KEY_SIZE(k),
				     b, "stale dirty pointer");

			if (stale)
				return true;

#ifdef CONFIG_BCACHE_EDEBUG
			if (!mutex_trylock(&b->c->bucket_lock))
				continue;

			if (b->level) {
				if (KEY_DIRTY(k) ||
				    g->prio != btree_prio ||
				    (b->c->gc_mark_valid &&
				     g->mark != GC_MARK_BTREE))
					goto bug;

			} else {
				if (g->prio == btree_prio)
					goto bug;

				if (KEY_DIRTY(k) &&
				    b->c->gc_mark_valid &&
				    g->mark != GC_MARK_DIRTY)
					goto bug;
			}
			mutex_unlock(&b->c->bucket_lock);
#endif
		}

	return false;
#ifdef CONFIG_BCACHE_EDEBUG
bug:
	mutex_unlock(&b->c->bucket_lock);
	btree_bug(b, "inconsistent pointer %s: bucket %li pin %i "
		  "prio %i gen %i last_gc %i mark %i gc_gen %i", pkey(k),
		  PTR_BUCKET_NR(b->c, k, i), atomic_read(&g->pin),
		  g->prio, g->gen, g->last_gc, g->mark, g->gc_gen);
	return true;
#endif
}

/* Key/pointer manipulation */

void bkey_copy_single_ptr(struct bkey *dest, const struct bkey *src, unsigned i)
{
	BUG_ON(i > KEY_PTRS(src));

	/* Only copy the header, key, and one pointer. */
	memcpy(dest, src, 2 * sizeof(uint64_t));
	dest->ptr[0] = src->ptr[i];
	SET_KEY_PTRS(dest, 1);
	/* We didn't copy the checksum so clear that bit. */
	SET_KEY_CSUM(dest, 0);
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
	if (key_merging_disabled(b->c))
		return false;

	if (KEY_PTRS(l) != KEY_PTRS(r) ||
	    KEY_DIRTY(l) != KEY_DIRTY(r) ||
	    bkey_cmp(l, &START_KEY(r)))
		return false;

	for (unsigned j = 0; j < KEY_PTRS(l); j++)
		if (l->ptr[j] + PTR(0, KEY_SIZE(l), 0) != r->ptr[j] ||
		    PTR_BUCKET_NR(b->c, l, j) != PTR_BUCKET_NR(b->c, r, j))
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

/* Binary tree stuff for auxiliary search trees */

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
 * Also tested for every j, size up to size somewhere around 6 million.
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

static unsigned __inorder_to_tree(unsigned j, unsigned size, unsigned extra)
{
	unsigned shift;

	if (j > extra)
		j += j - extra;

	shift = ffs(j);

	j >>= shift;
	j  |= roundup_pow_of_two(size) >> shift;

	return j;
}

static unsigned inorder_to_tree(unsigned j, struct bset_tree *t)
{
	return __inorder_to_tree(j, t->size, t->extra);
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
			if (__inorder_to_tree(i, size, extra) != j)
				panic("size %10u j %10u i %10u", size, j, i);

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

/*
 * Cacheline/offset <-> bkey pointer arithmatic:
 *
 * t->tree is a binary search tree in an array; each node corresponds to a key
 * in one cacheline in t->set (BSET_CACHELINE bytes).
 *
 * This means we don't have to store the full index of the key that a node in
 * the binary tree points to; to_inorder() gives us the cacheline, and then
 * bkey_float->m gives us the offset within that cacheline, in units of 8 bytes.
 *
 * cacheline_to_bkey() and friends abstract out all the pointer arithmatic to
 * make this work.
 *
 * To construct the bfloat for an arbitrary key we need to know what the key
 * immediately preceding it is: we have to check if the two keys differ in the
 * bits we're going to store in bkey_float->mantissa. t->prev[j] stores the size
 * of the previous key so we can walk backwards to it from t->tree[j]'s key.
 */

static struct bkey *cacheline_to_bkey(struct bset_tree *t, unsigned cacheline,
				      unsigned offset)
{
	return ((void *) t->data) + cacheline * BSET_CACHELINE + offset * 8;
}

static unsigned bkey_to_cacheline(struct bset_tree *t, struct bkey *k)
{
	return ((void *) k - (void *) t->data) / BSET_CACHELINE;
}

static unsigned bkey_to_cacheline_offset(struct bkey *k)
{
	return ((size_t) k & (BSET_CACHELINE - 1)) / sizeof(uint64_t);
}

static struct bkey *tree_to_bkey(struct bset_tree *t, unsigned j)
{
	return cacheline_to_bkey(t, to_inorder(j, t), t->tree[j].m);
}

static struct bkey *tree_to_prev_bkey(struct bset_tree *t, unsigned j)
{
	return (void *) (((uint64_t *) tree_to_bkey(t, j)) - t->prev[j]);
}

/*
 * For the write set - the one we're currently inserting keys into - we don't
 * maintain a full search tree, we just keep a simple lookup table in t->prev.
 */
struct bkey *table_to_bkey(struct bset_tree *t, unsigned cacheline)
{
	return cacheline_to_bkey(t, cacheline, t->prev[cacheline]);
}

/* Auxiliary search trees */

static inline uint64_t shrd128(uint64_t high, uint64_t low, uint8_t shift)
{
#ifdef CONFIG_X86_64
	asm("shrd %[shift],%[high],%[low]"
	    : [low] "+Rm" (low)
	    : [high] "R" (high),
	    [shift] "ci" (shift)
	    : "cc");
#else
	low >>= shift;
	low  |= (high << 1) << (63U - shift);
#endif
	return low;
}

static inline unsigned bfloat_mantissa(const struct bkey *k,
				       struct bkey_float *f)
{
	const uint64_t *p = &k->key - (f->exponent >> 6);
	return shrd128(p[-1], p[0], f->exponent & 63) & BKEY_MANTISSA_MASK;
}

static void make_bfloat(struct bset_tree *t, unsigned j)
{
	struct bkey_float *f = &t->tree[j];
	struct bkey *m = tree_to_bkey(t, j);
	struct bkey *p = tree_to_prev_bkey(t, j);

	struct bkey *l = is_power_of_2(j)
		? t->data->start
		: tree_to_prev_bkey(t, j >> ffs(j));

	struct bkey *r = is_power_of_2(j + 1)
		? node(t->data, t->data->keys - bkey_u64s(&t->end))
		: tree_to_bkey(t, j >> (ffz(j) + 1));

	BUG_ON(m < l || m > r);
	BUG_ON(next(p) != m);

	if (KEY_DEV(l) != KEY_DEV(r))
		f->exponent = fls64(KEY_DEV(r) ^ KEY_DEV(l)) + 64;
	else
		f->exponent = fls64(r->key ^ l->key);

	f->exponent = max_t(int, f->exponent - BKEY_MANTISSA_BITS, 0);

	if (bfloat_mantissa(m, f) != bfloat_mantissa(p, f))
		f->mantissa = bfloat_mantissa(m, f) - 1;
	else
		f->exponent = 127;
}

static void bset_alloc_tree(struct btree *b, struct bset_tree *t)
{
	if (t != b->sets) {
		unsigned j = roundup(t[-1].size,
				     64 / sizeof(struct bkey_float));

		t->tree = t[-1].tree + j;
		t->prev = t[-1].prev + j;
	}

	while (t < b->sets + MAX_BSETS)
		t++->size = 0;
}

static void bset_build_unwritten_tree(struct btree *b)
{
	struct bset_tree *t = b->sets + b->nsets;

	bset_alloc_tree(b, t);

	if (t->tree != b->sets->tree + bset_tree_space(b)) {
		t->prev[0] = bkey_to_cacheline_offset(t->data->start);
		t->size = 1;
	}
}

static void bset_build_written_tree(struct btree *b)
{
	struct bset_tree *t = b->sets + b->nsets;
	struct bkey *k = t->data->start;
	unsigned j, cacheline = 1;

	bset_alloc_tree(b, t);

	t->size = min_t(unsigned,
			bkey_to_cacheline(t, end(t->data)),
			b->sets->tree + bset_tree_space(b) - t->tree);

	if (t->size < 2) {
		t->size = 0;
		return;
	}

	t->extra = (t->size - rounddown_pow_of_two(t->size - 1)) << 1;

	/* First we figure out where the first key in each cacheline is */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size)) {
		while (bkey_to_cacheline(t, k) != cacheline)
			k = next(k);

		t->prev[j] = bkey_u64s(k);
		k = next(k);
		cacheline++;
		t->tree[j].m = bkey_to_cacheline_offset(k);
	}

	while (next(k) != end(t->data))
		k = next(k);

	t->end = *k;

	/* Then we build the tree */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size))
		make_bfloat(t, j);
}

void bset_fix_invalidated_key(struct btree *b, struct bkey *k)
{
	struct bset_tree *t;
	unsigned inorder, j = 1;

	for (t = b->sets; t <= &b->sets[b->nsets]; t++)
		if (k < end(t->data))
			goto found_set;

	BUG();
found_set:
	if (!t->size || !bset_written(b, t))
		return;

	inorder = bkey_to_cacheline(t, k);

	if (k == t->data->start)
		goto fix_left;

	if (next(k) == end(t->data)) {
		t->end = *k;
		goto fix_right;
	}

	j = inorder_to_tree(inorder, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_bkey(t, j))
fix_left:	do {
			make_bfloat(t, j);
			j = j * 2;
		} while (j < t->size);

	j = inorder_to_tree(inorder + 1, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_prev_bkey(t, j))
fix_right:	do {
			make_bfloat(t, j);
			j = j * 2 + 1;
		} while (j < t->size);
}

void bset_fix_lookup_table(struct btree *b, struct bkey *k)
{
	struct bset_tree *t = &b->sets[b->nsets];
	unsigned shift = bkey_u64s(k);
	unsigned j = bkey_to_cacheline(t, k);

	/* We're getting called from btree_split() or btree_gc, just bail out */
	if (!t->size)
		return;

	/* k is the key we just inserted; we need to find the entry in the
	 * lookup table for the first key that is strictly greater than k:
	 * it's either k's cacheline or the next one
	 */
	if (j < t->size &&
	    table_to_bkey(t, j) <= k)
		j++;

	/* Adjust all the lookup table entries, and find a new key for any that
	 * have gotten too big
	 */
	for (; j < t->size; j++) {
		t->prev[j] += shift;

		if (t->prev[j] > 7) {
			k = table_to_bkey(t, j - 1);

			while (k < cacheline_to_bkey(t, j, 0))
				k = next(k);

			t->prev[j] = bkey_to_cacheline_offset(k);
		}
	}

	if (t->size == b->sets->tree + bset_tree_space(b) - t->tree)
		return;

	/* Possibly add a new entry to the end of the lookup table */

	for (k = table_to_bkey(t, t->size - 1);
	     k != end(t->data);
	     k = next(k))
		if (t->size == bkey_to_cacheline(t, k)) {
			t->prev[t->size] = bkey_to_cacheline_offset(k);
			t->size++;
		}
}

void bset_init_next(struct btree *b)
{
	struct bset *i = write_block(b);

	if (i != b->sets[0].data) {
		b->sets[++b->nsets].data = i;
		i->seq = b->sets[0].data->seq;
	} else
		get_random_bytes(&i->seq, sizeof(uint64_t));

	i->magic	= bset_magic(b->c);
	i->version	= 0;
	i->keys		= 0;

	bset_build_unwritten_tree(b);
}

struct bset_search_iter {
	struct bkey *l, *r;
};

static struct bset_search_iter bset_search_write_set(struct btree *b,
						     struct bset_tree *t,
						     const struct bkey *search)
{
	unsigned li = 0, ri = t->size;

	BUG_ON(!b->nsets &&
	       t->size < bkey_to_cacheline(t, end(t->data)));

	while (li + 1 != ri) {
		unsigned m = (li + ri) >> 1;

		if (bkey_cmp(table_to_bkey(t, m), search) > 0)
			ri = m;
		else
			li = m;
	}

	return (struct bset_search_iter) {
		table_to_bkey(t, li),
		ri < t->size ? table_to_bkey(t, ri) : end(t->data)
	};
}

static struct bset_search_iter bset_search_tree(struct btree *b,
						struct bset_tree *t,
						const struct bkey *search)
{
	struct bkey *l, *r;
	struct bkey_float *f;
	unsigned inorder, j, n = 1;

	do {
		unsigned p = n << 4;
		p &= ((int) (p - t->size)) >> 31;

		prefetch(&t->tree[p]);

		j = n;
		f = &t->tree[j];

		/*
		 * n = (f->mantissa > bfloat_mantissa())
		 *	? j * 2
		 *	: j * 2 + 1;
		 *
		 * We need to subtract 1 from f->mantissa for the sign bit trick
		 * to work  - that's done in make_bfloat()
		 */
		if (likely(f->exponent != 127))
			n = j * 2 + (((unsigned)
				      (f->mantissa -
				       bfloat_mantissa(search, f))) >> 31);
		else
			n = (bkey_cmp(tree_to_bkey(t, j), search) > 0)
				? j * 2
				: j * 2 + 1;
	} while (n < t->size);

	inorder = to_inorder(j, t);

	/*
	 * n would have been the node we recursed to - the low bit tells us if
	 * we recursed left or recursed right.
	 */
	if (n & 1) {
		l = cacheline_to_bkey(t, inorder, f->m);

		if (++inorder != t->size) {
			f = &t->tree[inorder_next(j, t->size)];
			r = cacheline_to_bkey(t, inorder, f->m);
		} else
			r = end(t->data);
	} else {
		r = cacheline_to_bkey(t, inorder, f->m);

		if (--inorder) {
			f = &t->tree[inorder_prev(j, t->size)];
			l = cacheline_to_bkey(t, inorder, f->m);
		} else
			l = t->data->start;
	}

	return (struct bset_search_iter) {l, r};
}

struct bkey *__bset_search(struct btree *b, struct bset_tree *t,
			   const struct bkey *search)
{
	struct bset_search_iter i;

	/*
	 * First, we search for a cacheline, then lastly we do a linear search
	 * within that cacheline.
	 *
	 * To search for the cacheline, there's three different possibilities:
	 *  * The set is too small to have a search tree, so we just do a linear
	 *    search over the whole set.
	 *  * The set is the one we're currently inserting into; keeping a full
	 *    auxiliary search tree up to date would be too expensive, so we
	 *    use a much simpler lookup table to do a binary search -
	 *    bset_search_write_set().
	 *  * Or we use the auxiliary search tree we constructed earlier -
	 *    bset_search_tree()
	 */

	if (unlikely(!t->size)) {
		i.l = t->data->start;
		i.r = end(t->data);
	} else if (bset_written(b, t)) {
		/*
		 * Each node in the auxiliary search tree covers a certain range
		 * of bits, and keys above and below the set it covers might
		 * differ outside those bits - so we have to special case the
		 * start and end - handle that here:
		 */

		if (unlikely(bkey_cmp(search, &t->end) >= 0))
			return end(t->data);

		if (unlikely(bkey_cmp(search, t->data->start) < 0))
			return t->data->start;

		i = bset_search_tree(b, t, search);
	} else
		i = bset_search_write_set(b, t, search);

#ifdef CONFIG_BCACHE_EDEBUG
	BUG_ON(bset_written(b, t) &&
	       i.l != t->data->start &&
	       bkey_cmp(tree_to_prev_bkey(t,
		  inorder_to_tree(bkey_to_cacheline(t, i.l), t)),
			search) > 0);

	BUG_ON(i.r != end(t->data) &&
	       bkey_cmp(i.r, search) <= 0);
#endif

	while (likely(i.l != i.r) &&
	       bkey_cmp(i.l, search) <= 0)
		i.l = next(i.l);

	return i.l;
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
			       struct bkey *search, struct bset_tree *start)
{
	struct bkey *ret = NULL;
	iter->size = ARRAY_SIZE(iter->data);
	iter->used = 0;

	for (; start <= &b->sets[b->nsets]; start++) {
		ret = bset_search(b, start, search);
		btree_iter_push(iter, ret, end(start->data));
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
	struct bkey *ret;
	struct btree_iter iter;
	btree_iter_init(b, &iter, search);

	do
		ret = btree_iter_next(&iter);
	while (ret && ptr_bad(b, ret));

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

static void btree_mergesort(struct btree *b, struct bset *out,
			    struct btree_iter *iter,
			    bool fixup, bool remove_stale)
{
	struct bkey *k, *last = NULL;
	bool (*bad)(struct btree *, const struct bkey *) = remove_stale
		? ptr_bad
		: ptr_invalid;

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

	pr_debug("sorted %i keys", out->keys);
	check_key_order(b, out);
}

static void __btree_sort(struct btree *b, struct btree_iter *iter,
			 unsigned start, unsigned order, bool fixup)
{
	uint64_t start_time;
	bool remove_stale = !b->written;
	struct bset *out = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOIO,
						     order);
	if (!out) {
		mutex_lock(&b->c->sort_lock);
		out = b->c->sort;
		order = ilog2(bucket_pages(b->c));
	}

	start_time = local_clock();

	btree_mergesort(b, out, iter, fixup, remove_stale);
	b->nsets = start;

	if (!fixup && !start && b->written)
		btree_verify(b, out);

	if (!start && order == b->page_order) {
		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */

		out->magic	= bset_magic(b->c);
		out->seq	= b->sets[0].data->seq;
		out->version	= b->sets[0].data->version;
		swap(out, b->sets[0].data);

		if (b->c->sort == b->sets[0].data)
			b->c->sort = out;
	} else {
		b->sets[start].data->keys = out->keys;
		memcpy(b->sets[start].data->start, out->start,
		       (void *) end(out) - (void *) out->start);
	}

	if (out == b->c->sort)
		mutex_unlock(&b->c->sort_lock);
	else
		free_pages((unsigned long) out, order);

	if (b->written)
		bset_build_written_tree(b);

	if (!start) {
		spin_lock(&b->c->sort_time_lock);
		time_stats_update(&b->c->sort_time, start_time);
		spin_unlock(&b->c->sort_time_lock);
	}
}

void btree_sort_partial(struct btree *b, unsigned start)
{
	size_t oldsize = 0, order = b->page_order, keys = 0;
	struct btree_iter iter;
	__btree_iter_init(b, &iter, NULL, &b->sets[start]);

	BUG_ON(b->sets[b->nsets].data == write_block(b) &&
	       (b->sets[b->nsets].size || b->nsets));

	if (b->written)
		oldsize = count_data(b);

	if (start) {
		struct bset *i;
		for_each_sorted_set_start(b, i, start)
			keys += i->keys;

		order = roundup_pow_of_two(__set_bytes(i, keys)) / PAGE_SIZE;
		if (order)
			order = ilog2(order);
	}

	__btree_sort(b, &iter, start, order, false);

	EBUG_ON(b->written && count_data(b) != oldsize);
}

void btree_sort_and_fix_extents(struct btree *b, struct btree_iter *iter)
{
	BUG_ON(!b->written);
	__btree_sort(b, iter, 0, b->page_order, true);
}

void btree_sort_into(struct btree *b, struct btree *new)
{
	uint64_t start_time = local_clock();

	struct btree_iter iter;
	btree_iter_init(b, &iter, NULL);

	btree_mergesort(b, new->sets->data, &iter, false, true);

	spin_lock(&b->c->sort_time_lock);
	time_stats_update(&b->c->sort_time, start_time);
	spin_unlock(&b->c->sort_time_lock);

	bkey_copy_key(&new->key, &b->key);
	new->sets->size = 0;
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
				btree_sort_partial(b, j);
				return;
			}

			keys -= b->sets[j].data->keys;
		}

		/* Must sort if b->nsets == 3 or we'll overflow */
		if (b->nsets >= (MAX_BSETS - 1) - b->level) {
			btree_sort(b);
			return;
		}
	}

	bset_build_written_tree(b);
}

/* Sysfs stuff */

struct bset_stats {
	size_t writes, sets, keys, trees, floats, failed, tree_space;
};

static int btree_bset_stats(struct btree *b, struct btree_op *op,
			    struct bset_stats *stats)
{
	struct bkey *k;

	if (btree_node_dirty(b))
		stats->writes++;
	stats->sets		+= b->nsets + 1;
	stats->tree_space	+= bset_tree_space(b);

	for (int i = 0; i < MAX_BSETS && b->sets[i].size; i++) {
		stats->trees++;
		stats->keys	+= b->sets[i].data->keys * sizeof(uint64_t);
		stats->floats	+= b->sets[i].size - 1;

		for (size_t j = 1; j < b->sets[i].size; j++)
			if (b->sets[i].tree[j].exponent == 127)
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
