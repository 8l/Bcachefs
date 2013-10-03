/*
 * Code for working with individual keys, and sorted sets of keys with in a
 * btree node
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"

#include <linux/random.h>
#include <linux/prefetch.h>

/* Keylists */

int bch_keylist_realloc(struct keylist *l, int nptrs, struct cache_set *c)
{
	size_t oldsize = bch_keylist_nkeys(l);
	size_t newsize = oldsize + 2 + nptrs;
	uint64_t *old_keys = l->keys_p == l->inline_keys ? NULL : l->keys_p;
	uint64_t *new_keys;

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

	new_keys = krealloc(old_keys, sizeof(uint64_t) * newsize, GFP_NOIO);

	if (!new_keys)
		return -ENOMEM;

	if (!old_keys)
		memcpy(new_keys, l->inline_keys, sizeof(uint64_t) * oldsize);

	l->keys_p = new_keys;
	l->top_p = new_keys + oldsize;

	return 0;
}

struct bkey *bch_keylist_pop(struct keylist *l)
{
	struct bkey *k = l->keys;

	if (k == l->top)
		return NULL;

	while (bkey_next(k) != l->top)
		k = bkey_next(k);

	return l->top = k;
}

void bch_keylist_pop_front(struct keylist *l)
{
	l->top_p -= bkey_u64s(l->keys);

	memmove(l->keys,
		bkey_next(l->keys),
		bch_keylist_bytes(l));
}

/* Key/pointer manipulation */

void bch_bkey_copy_single_ptr(struct bkey *dest, const struct bkey *src,
			      unsigned i)
{
	BUG_ON(i > KEY_PTRS(src));

	/* Only copy the header, key, and one pointer. */
	memcpy(dest, src, 2 * sizeof(uint64_t));
	dest->ptr[0] = src->ptr[i];
	SET_KEY_PTRS(dest, 1);
	/* We didn't copy the checksum so clear that bit. */
	SET_KEY_CSUM(dest, 0);
}

bool __bch_cut_front(const struct bkey *where, struct bkey *k)
{
	unsigned i, len = 0;

	if (bkey_cmp(where, &START_KEY(k)) <= 0)
		return false;

	if (bkey_cmp(where, k) < 0)
		len = KEY_OFFSET(k) - KEY_OFFSET(where);
	else
		bkey_copy_key(k, where);

	for (i = 0; i < KEY_PTRS(k); i++)
		SET_PTR_OFFSET(k, i, PTR_OFFSET(k, i) + KEY_SIZE(k) - len);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);
	return true;
}

bool __bch_cut_back(const struct bkey *where, struct bkey *k)
{
	unsigned len = 0;

	if (bkey_cmp(where, k) >= 0)
		return false;

	BUG_ON(KEY_INODE(where) != KEY_INODE(k));

	if (bkey_cmp(where, &START_KEY(k)) > 0)
		len = KEY_OFFSET(where) - KEY_START(k);

	bkey_copy_key(k, where);

	BUG_ON(len > KEY_SIZE(k));
	SET_KEY_SIZE(k, len);
	return true;
}

/* Auxiliary search trees */

/* 32 bits total: */
#define BKEY_MID_BITS		3
#define BKEY_EXPONENT_BITS	7
#define BKEY_MANTISSA_BITS	(32 - BKEY_MID_BITS - BKEY_EXPONENT_BITS)
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)

struct bkey_float {
	unsigned	exponent:BKEY_EXPONENT_BITS;
	unsigned	m:BKEY_MID_BITS;
	unsigned	mantissa:BKEY_MANTISSA_BITS;
} __packed;

/*
 * BSET_CACHELINE was originally intended to match the hardware cacheline size -
 * it used to be 64, but I realized the lookup code would touch slightly less
 * memory if it was 128.
 *
 * It definites the number of bytes (in struct bset) per struct bkey_float in
 * the auxiliar search tree - when we're done searching the bset_float tree we
 * have this many bytes left that we do a linear search over.
 *
 * Since (after level 5) every level of the bset_tree is on a new cacheline,
 * we're touching one fewer cacheline in the bset tree in exchange for one more
 * cacheline in the linear search - but the linear search might stop before it
 * gets to the second cacheline.
 */

#define BSET_CACHELINE		128

/* Space required for the btree node keys */
static inline size_t btree_keys_bytes(struct btree_keys *b)
{
	return PAGE_SIZE << b->page_order;
}

static inline size_t btree_keys_cachelines(struct btree_keys *b)
{
	return btree_keys_bytes(b) / BSET_CACHELINE;
}

/* Space required for the auxiliary search trees */
static inline size_t bset_tree_bytes(struct btree_keys *b)
{
	return btree_keys_cachelines(b) * sizeof(struct bkey_float);
}

/* Space required for the prev pointers */
static inline size_t bset_prev_bytes(struct btree_keys *b)
{
	return btree_keys_cachelines(b) * sizeof(uint8_t);
}

/* Memory allocation */

void bch_btree_keys_free(struct btree_keys *b)
{
	struct bset_tree *t = b->set;

	if (bset_prev_bytes(b) < PAGE_SIZE)
		kfree(t->prev);
	else
		free_pages((unsigned long) t->prev,
			   get_order(bset_prev_bytes(b)));

	if (bset_tree_bytes(b) < PAGE_SIZE)
		kfree(t->tree);
	else
		free_pages((unsigned long) t->tree,
			   get_order(bset_tree_bytes(b)));

	free_pages((unsigned long) t->data, b->page_order);

	t->prev = NULL;
	t->tree = NULL;
	t->data = NULL;
}

int bch_btree_keys_alloc(struct btree_keys *b, unsigned page_order, gfp_t gfp)
{
	struct bset_tree *t = b->set;

	BUG_ON(t->data);

	b->page_order = page_order;

	t->data = (void *) __get_free_pages(gfp, b->page_order);
	if (!t->data)
		goto err;

	t->tree = bset_tree_bytes(b) < PAGE_SIZE
		? kmalloc(bset_tree_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_tree_bytes(b)));
	if (!t->tree)
		goto err;

	t->prev = bset_prev_bytes(b) < PAGE_SIZE
		? kmalloc(bset_prev_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_prev_bytes(b)));
	if (!t->prev)
		goto err;

	return 0;
err:
	bch_btree_keys_free(b);
	return -ENOMEM;
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
 * Cacheline/offset <-> bkey pointer arithmetic:
 *
 * t->tree is a binary search tree in an array; each node corresponds to a key
 * in one cacheline in t->set (BSET_CACHELINE bytes).
 *
 * This means we don't have to store the full index of the key that a node in
 * the binary tree points to; to_inorder() gives us the cacheline, and then
 * bkey_float->m gives us the offset within that cacheline, in units of 8 bytes.
 *
 * cacheline_to_bkey() and friends abstract out all the pointer arithmetic to
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
static struct bkey *table_to_bkey(struct bset_tree *t, unsigned cacheline)
{
	return cacheline_to_bkey(t, cacheline, t->prev[cacheline]);
}

static inline uint64_t shrd128(uint64_t high, uint64_t low, uint8_t shift)
{
	low >>= shift;
	low  |= (high << 1) << (63U - shift);
	return low;
}

static inline unsigned bfloat_mantissa(const struct bkey *k,
				       struct bkey_float *f)
{
	const uint64_t *p = &k->low - (f->exponent >> 6);
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
		? bset_bkey_idx(t->data, t->data->keys - bkey_u64s(&t->end))
		: tree_to_bkey(t, j >> (ffz(j) + 1));

	BUG_ON(m < l || m > r);
	BUG_ON(bkey_next(p) != m);

	if (KEY_INODE(l) != KEY_INODE(r))
		f->exponent = fls64(KEY_INODE(r) ^ KEY_INODE(l)) + 64;
	else
		f->exponent = fls64(r->low ^ l->low);

	f->exponent = max_t(int, f->exponent - BKEY_MANTISSA_BITS, 0);

	/*
	 * Setting f->exponent = 127 flags this node as failed, and causes the
	 * lookup code to fall back to comparing against the original key.
	 */

	if (bfloat_mantissa(m, f) != bfloat_mantissa(p, f))
		f->mantissa = bfloat_mantissa(m, f) - 1;
	else
		f->exponent = 127;
}

static void bset_alloc_tree(struct btree_keys *b, struct bset_tree *t)
{
	if (t != b->set) {
		unsigned j = roundup(t[-1].size,
				     64 / sizeof(struct bkey_float));

		t->tree = t[-1].tree + j;
		t->prev = t[-1].prev + j;
	}

	while (t < b->set + MAX_BSETS)
		t++->size = 0;
}

static void bch_bset_build_unwritten_tree(struct btree_keys *b)
{
	struct bset_tree *t = bset_tree_last(b);

	BUG_ON(b->last_set_unwritten);
	b->last_set_unwritten = 1;

	bset_alloc_tree(b, t);

	if (t->tree != b->set->tree + btree_keys_cachelines(b)) {
		t->prev[0] = bkey_to_cacheline_offset(t->data->start);
		t->size = 1;
	}
}

void bch_bset_init_next(struct btree_keys *b, struct bset *i, uint64_t magic)
{
	if (i != b->set->data) {
		b->set[++b->nsets].data = i;
		i->seq = b->set->data->seq;
	} else
		get_random_bytes(&i->seq, sizeof(uint64_t));

	i->magic	= magic;
	i->version	= 0;
	i->keys		= 0;

	bch_bset_build_unwritten_tree(b);
}

static void bset_build_written_tree(struct btree_keys *b)
{
	struct bset_tree *t = bset_tree_last(b);
	struct bkey *k = t->data->start;
	unsigned j, cacheline = 1;

	BUG_ON(b->last_set_unwritten);

	bset_alloc_tree(b, t);

	t->size = min_t(unsigned,
			bkey_to_cacheline(t, bset_bkey_last(t->data)),
			b->set->tree + btree_keys_cachelines(b) - t->tree);

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
			k = bkey_next(k);

		t->prev[j] = bkey_u64s(k);
		k = bkey_next(k);
		cacheline++;
		t->tree[j].m = bkey_to_cacheline_offset(k);
	}

	while (bkey_next(k) != bset_bkey_last(t->data))
		k = bkey_next(k);

	t->end = *k;

	/* Then we build the tree */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size))
		make_bfloat(t, j);
}

void bch_bset_fix_invalidated_key(struct btree_keys *b, struct bkey *k)
{
	struct bset_tree *t;
	unsigned inorder, j = 1;

	for (t = b->set; t <= bset_tree_last(b); t++)
		if (k < bset_bkey_last(t->data))
			goto found_set;

	BUG();
found_set:
	if (!t->size || !bset_written(b, t))
		return;

	inorder = bkey_to_cacheline(t, k);

	if (k == t->data->start)
		goto fix_left;

	if (bkey_next(k) == bset_bkey_last(t->data)) {
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

static void bch_bset_fix_lookup_table(struct btree_keys *b,
				      struct bset_tree *t,
				      struct bkey *k)
{
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
				k = bkey_next(k);

			t->prev[j] = bkey_to_cacheline_offset(k);
		}
	}

	if (t->size == b->set->tree + btree_keys_cachelines(b) - t->tree)
		return;

	/* Possibly add a new entry to the end of the lookup table */

	for (k = table_to_bkey(t, t->size - 1);
	     k != bset_bkey_last(t->data);
	     k = bkey_next(k))
		if (t->size == bkey_to_cacheline(t, k)) {
			t->prev[t->size] = bkey_to_cacheline_offset(k);
			t->size++;
		}
}

void bch_bset_insert(struct btree_keys *b, struct bkey *where,
		     struct bkey *insert)
{
	struct bset_tree *t = bset_tree_last(b);

	BUG_ON(!b->last_set_unwritten);
	BUG_ON(bset_byte_offset(b, t->data) +
	       __set_bytes(t->data, t->data->keys + bkey_u64s(insert)) >
	       PAGE_SIZE << b->page_order);

	memmove((uint64_t *) where + bkey_u64s(insert),
		where,
		(void *) bset_bkey_last(t->data) - (void *) where);

	t->data->keys += bkey_u64s(insert);
	bkey_copy(where, insert);
	bch_bset_fix_lookup_table(b, t, where);
}

struct bset_search_iter {
	struct bkey *l, *r;
};

static struct bset_search_iter bset_search_write_set(struct bset_tree *t,
						     const struct bkey *search)
{
	unsigned li = 0, ri = t->size;

	while (li + 1 != ri) {
		unsigned m = (li + ri) >> 1;

		if (bkey_cmp(table_to_bkey(t, m), search) > 0)
			ri = m;
		else
			li = m;
	}

	return (struct bset_search_iter) {
		table_to_bkey(t, li),
		ri < t->size ? table_to_bkey(t, ri) : bset_bkey_last(t->data)
	};
}

static struct bset_search_iter bset_search_tree(struct bset_tree *t,
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
			r = bset_bkey_last(t->data);
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

struct bkey *__bch_bset_search(struct btree_keys *b, struct bset_tree *t,
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
		i.r = bset_bkey_last(t->data);
	} else if (bset_written(b, t)) {
		/*
		 * Each node in the auxiliary search tree covers a certain range
		 * of bits, and keys above and below the set it covers might
		 * differ outside those bits - so we have to special case the
		 * start and end - handle that here:
		 */

		if (unlikely(bkey_cmp(search, &t->end) >= 0))
			return bset_bkey_last(t->data);

		if (unlikely(bkey_cmp(search, t->data->start) < 0))
			return t->data->start;

		i = bset_search_tree(t, search);
	} else {
		BUG_ON(!b->nsets &&
		       t->size < bkey_to_cacheline(t, bset_bkey_last(t->data)));

		i = bset_search_write_set(t, search);
	}
#if 0
	if (expensive_debug_checks(b->c)) {
		BUG_ON(bset_written(b, t) &&
		       i.l != t->data->start &&
		       bkey_cmp(tree_to_prev_bkey(t,
			  inorder_to_tree(bkey_to_cacheline(t, i.l), t)),
				search) > 0);

		BUG_ON(i.r != bset_bkey_last(t->data) &&
		       bkey_cmp(i.r, search) <= 0);
	}
#endif
	while (likely(i.l != i.r) &&
	       bkey_cmp(i.l, search) <= 0)
		i.l = bkey_next(i.l);

	return i.l;
}

/* Btree iterator */

typedef bool (btree_iter_cmp_fn)(struct btree_iter_set,
				 struct btree_iter_set);

static inline bool btree_iter_cmp(struct btree_iter_set l,
				  struct btree_iter_set r)
{
	return bkey_cmp(l.k, r.k) > 0;
}

static inline bool btree_iter_end(struct btree_iter *iter)
{
	return !iter->used;
}

void bch_btree_iter_push(struct btree_iter *iter, struct bkey *k,
			 struct bkey *end)
{
	if (k != end)
		BUG_ON(!heap_add(iter,
				 ((struct btree_iter_set) { k, end }),
				 btree_iter_cmp));
}

static struct bkey *__bch_btree_iter_init(struct btree_keys *b,
					  struct btree_iter *iter,
					  struct bkey *search,
					  struct bset_tree *start)
{
	struct bkey *ret = NULL;
	iter->size = ARRAY_SIZE(iter->data);
	iter->used = 0;

#ifdef CONFIG_BCACHE_DEBUG
	iter->b = b;
#endif

	for (; start <= bset_tree_last(b); start++) {
		ret = bch_bset_search(b, start, search);
		bch_btree_iter_push(iter, ret, bset_bkey_last(start->data));
	}

	return ret;
}

struct bkey *bch_btree_iter_init(struct btree_keys *b,
				 struct btree_iter *iter,
				 struct bkey *search)
{
	return __bch_btree_iter_init(b, iter, search, b->set);
}

static inline struct bkey *__bch_btree_iter_next(struct btree_iter *iter,
						 btree_iter_cmp_fn *cmp)
{
	struct btree_iter_set unused;
	struct bkey *ret = NULL;

	if (!btree_iter_end(iter)) {
		bch_btree_iter_next_check(iter);

		ret = iter->data->k;
		iter->data->k = bkey_next(iter->data->k);

		if (iter->data->k > iter->data->end) {
			WARN_ONCE(1, "bset was corrupt!\n");
			iter->data->k = iter->data->end;
		}

		if (iter->data->k == iter->data->end)
			heap_pop(iter, unused, cmp);
		else
			heap_sift(iter, 0, cmp);
	}

	return ret;
}

struct bkey *bch_btree_iter_next(struct btree_iter *iter)
{
	return __bch_btree_iter_next(iter, btree_iter_cmp);

}

struct bkey *bch_btree_iter_next_filter(struct btree_iter *iter,
					struct btree_keys *b, ptr_filter_fn fn)
{
	struct bkey *ret;

	do {
		ret = bch_btree_iter_next(iter);
	} while (ret && fn(b, ret));

	return ret;
}

/* Mergesort */

int bch_bset_sort_state_init(struct bset_sort_state *state, unsigned page_order)
{
	mutex_init(&state->lock);
	spin_lock_init(&state->time.lock);

	state->page_order = page_order;
	state->crit_factor = int_sqrt(1 << page_order);

	state->sort = (void *) __get_free_pages(GFP_KERNEL, page_order);
	if (!state->sort)
		return -ENOMEM;

	return 0;
}

static void btree_mergesort(struct btree_keys *b, struct bset *out,
			    struct btree_iter *iter,
			    bool fixup, bool remove_stale)
{
	int i;
	struct bkey *k, *last = NULL;
	bool (*bad)(struct btree_keys *, const struct bkey *) = remove_stale
		? bch_ptr_bad
		: bch_ptr_invalid;

	/* Heapify the iterator, using our comparison function */
	for (i = iter->used / 2 - 1; i >= 0; --i)
		heap_sift(iter, i, b->sort_cmp);

	while (!btree_iter_end(iter)) {
		if (b->sort_fixup && fixup)
			b->sort_fixup(iter);

		k = __bch_btree_iter_next(iter, b->sort_cmp);
		if (bad(b, k))
			continue;

		if (!last) {
			last = out->start;
			bkey_copy(last, k);
		} else if (!bch_bkey_try_merge(b, last, k)) {
			last = bkey_next(last);
			bkey_copy(last, k);
		}
	}

	out->keys = last ? (uint64_t *) bkey_next(last) - out->d : 0;

	pr_debug("sorted %i keys", out->keys);
}

static void __btree_sort(struct btree_keys *b, struct btree_iter *iter,
			 unsigned start, unsigned order, bool fixup,
			 struct bset_sort_state *state)
{
	uint64_t start_time;
	struct bset *out = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOIO,
						     order);
	if (!out) {
		BUG_ON(order > state->page_order);

		mutex_lock(&state->lock);
		out = state->sort;
		order = state->page_order;
	}

	start_time = local_clock();

	btree_mergesort(b, out, iter, fixup, false);
	b->nsets = start;

	if (!start && order == b->page_order) {
		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */

		out->magic	= b->set->data->magic;
		out->seq	= b->set->data->seq;
		out->version	= b->set->data->version;
		swap(out, b->set->data);

		if (state->sort == b->set->data)
			state->sort = out;
	} else {
		b->set[start].data->keys = out->keys;
		memcpy(b->set[start].data->start, out->start,
		       (void *) bset_bkey_last(out) - (void *) out->start);
	}

	if (out == state->sort)
		mutex_unlock(&state->lock);
	else
		free_pages((unsigned long) out, order);

	bset_build_written_tree(b);

	if (!start)
		bch_time_stats_update(&state->time, start_time);
}

void bch_btree_sort_partial(struct btree *b, unsigned start,
			    struct bset_sort_state *state)
{
	size_t order = b->keys.page_order, keys = 0;
	struct btree_iter iter;
	int oldsize = bch_count_data(b);

	__bch_btree_iter_init(&b->keys, &iter, NULL, &b->keys.set[start]);

	BUG_ON(!bset_written(&b->keys, bset_tree_last(&b->keys)) &&
	       (bset_tree_last(&b->keys)->size || b->keys.nsets));

	if (start) {
		unsigned i;

		for (i = start; i <= b->keys.nsets; i++)
			keys += b->keys.set[i].data->keys;

		order = roundup_pow_of_two(__set_bytes(b->keys.set->data,
						       keys)) / PAGE_SIZE;
		if (order)
			order = ilog2(order);
	}

	__btree_sort(&b->keys, &iter, start, order, false, state);

	EBUG_ON(b->written && oldsize >= 0 && bch_count_data(b) != oldsize);
}

void bch_btree_sort_and_fix_extents(struct btree_keys *b,
				    struct btree_iter *iter,
				    struct bset_sort_state *state)
{
	__btree_sort(b, iter, 0, b->page_order, true, state);
}

void bch_btree_sort_into(struct btree *b, struct btree *new,
			 struct bset_sort_state *state)
{
	uint64_t start_time = local_clock();

	struct btree_iter iter;
	bch_btree_iter_init(&b->keys, &iter, NULL);

	btree_mergesort(&b->keys, new->keys.set->data, &iter, false, true);

	bch_time_stats_update(&state->time, start_time);

	new->keys.set->size = 0; // XXX: why?
}

#define SORT_CRIT	(4096 / sizeof(uint64_t))

void bch_btree_sort_lazy(struct btree *b, struct bset_sort_state *state)
{
	unsigned crit = SORT_CRIT;
	int i;

	b->keys.last_set_unwritten = 0;

	/* Don't sort if nothing to do */
	if (!b->keys.nsets)
		goto out;

	for (i = b->keys.nsets - 1; i >= 0; --i) {
		crit *= state->crit_factor;

		if (b->keys.set[i].data->keys < crit) {
			bch_btree_sort_partial(b, i, state);
			return;
		}
	}

	/* Sort if we'd overflow */
	if (b->keys.nsets + 1 == MAX_BSETS) {
		bch_btree_sort(b, state);
		return;
	}

out:
	bset_build_written_tree(&b->keys);
}

/* Sysfs stuff */

struct bset_stats {
	struct btree_op op;
	size_t nodes;
	size_t sets_written, sets_unwritten;
	size_t bytes_written, bytes_unwritten;
	size_t floats, failed;
};

static int btree_bset_stats(struct btree_op *op, struct btree *b)
{
	struct bset_stats *stats = container_of(op, struct bset_stats, op);
	unsigned i;

	stats->nodes++;

	for (i = 0; i <= b->keys.nsets; i++) {
		struct bset_tree *t = &b->keys.set[i];
		size_t bytes = t->data->keys * sizeof(uint64_t);
		size_t j;

		if (bset_written(&b->keys, t)) {
			stats->sets_written++;
			stats->bytes_written += bytes;

			stats->floats += t->size - 1;

			for (j = 1; j < t->size; j++)
				if (t->tree[j].exponent == 127)
					stats->failed++;
		} else {
			stats->sets_unwritten++;
			stats->bytes_unwritten += bytes;
		}
	}

	return MAP_CONTINUE;
}

int bch_bset_print_stats(struct cache_set *c, char *buf)
{
	struct bset_stats t;
	int ret;

	memset(&t, 0, sizeof(struct bset_stats));
	bch_btree_op_init(&t.op, -1);

	ret = bch_btree_map_nodes(&t.op, c, &ZERO_KEY, btree_bset_stats);
	if (ret < 0)
		return ret;

	return snprintf(buf, PAGE_SIZE,
			"btree nodes:		%zu\n"
			"written sets:		%zu\n"
			"unwritten sets:		%zu\n"
			"written key bytes:	%zu\n"
			"unwritten key bytes:	%zu\n"
			"floats:			%zu\n"
			"failed:			%zu\n",
			t.nodes,
			t.sets_written, t.sets_unwritten,
			t.bytes_written, t.bytes_unwritten,
			t.floats, t.failed);
}
