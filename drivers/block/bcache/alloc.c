
#include "bcache.h"

#include <linux/random.h>

/*
 * Allocation in bcache is done in terms of buckets:
 *
 * Each bucket has associated an 8 bit gen; this gen corresponds to the gen in
 * btree pointers - they must match for the pointer to be considered valid.
 *
 * Thus (assuming a bucket has no dirty data or metadata in it) we can reuse a
 * bucket simply by incrementing its gen.
 *
 * The gens (along with the priorities; it's really the gens are important but
 * the code is named as if it's the priorities) are written in an arbitrary list
 * of buckets on disk, with a pointer to them in the journal header.
 *
 * When we invalidate a bucket, we have to write its new gen to disk and wait
 * for that write to complete before we use it - otherwise after a crash we
 * could have pointers that appeared to be good but pointed to data that had
 * been overwritten.
 *
 * Since the gens and priorities are all stored contiguously on disk, we can
 * batch this up: We fill up the free_inc list with freshly invalidated buckets,
 * call prio_write() - and when prio_write() eventually finishes it toggles
 * c->prio_written and the buckets in free_inc are now ready to be used. When
 * the free_inc list empties, we toggle c->prio_written and the cycle repeats.
 *
 * free_inc isn't the only freelist - if it was, we'd often to sleep while
 * priorities and gens were being written before we could allocate. c->free is a
 * smaller freelist, and buckets on that list are always ready to be used.
 *
 * If we've got discards enabled, that happens when a bucket moves from the
 * free_inc list to the free list.
 *
 * There is another freelist, because sometimes we have buckets that we know
 * have nothing pointing into them - these we can reuse without waiting for
 * priorities to be rewritten. These come from freed btree nodes and buckets
 * that garbage collection discovered no longer had valid keys pointing into
 * them (because they were overwritten). That's the unused list - buckets on the
 * unused list move to the free list, optionally being discarded in the process.
 *
 * It's also important to ensure that gens don't wrap around - with respect to
 * either the oldest gen in the btree or the gen on disk. This is quite
 * difficult to do in practice, but we explicitly guard against it anyways - if
 * a bucket is in danger of wrapping around we simply skip invalidating it that
 * time around, and we garbage collect or rewrite the priorities sooner than we
 * would have otherwise.
 *
 * pop_bucket() allocates a single bucket from a specific cache.
 *
 * pop_bucket_set() allocates one or more buckets from different caches out of a
 * cache set.
 *
 * free_some_buckets() drives all the processes described above. It's called
 * from pop_bucket() and a few other places that need to make sure free buckets
 * are ready.
 *
 * invalidate_buckets_(lru|fifo)() find buckets that are available to be
 * invalidated, and then invalidate them and stick them on the free_inc list -
 * in either lru or fifo order.
 */

static void do_discard(struct cache *);

/* Bucket heap / gen */

uint8_t inc_gen(struct cache *c, struct bucket *b)
{
	uint8_t ret = ++b->gen;

	c->set->need_gc = max(c->set->need_gc, bucket_gc_gen(b));
	BUG_ON(c->set->need_gc > 97);

	if (CACHE_SYNC(&c->set->sb)) {
		c->need_save_prio = max(c->need_save_prio, bucket_disk_gen(b));
		BUG_ON(c->need_save_prio > 96);
	}

	return ret;
}

void rescale_priorities(struct cache_set *c, int sectors)
{
	struct cache *ca;
	struct bucket *b;
	unsigned next = c->nbuckets * c->sb.bucket_size / 1024;
	int r;

	atomic_sub(sectors, &c->rescale);

	do {
		r = atomic_read(&c->rescale);

		if (r >= 0)
			return;
	} while (atomic_cmpxchg(&c->rescale, r, r + next) != r);

	mutex_lock(&c->bucket_lock);

	for_each_cache(ca, c)
		for_each_bucket(b, ca)
			if (b->prio &&
			    b->prio != btree_prio &&
			    !atomic_read(&b->pin)) {
				b->prio--;
				c->min_prio = min(c->min_prio, b->prio);
			}

	mutex_unlock(&c->bucket_lock);
}

static long pop_freed(struct cache *c)
{
	long r;

	if ((!CACHE_SYNC(&c->set->sb) ||
	     !atomic_read(&c->set->prio_blocked)) &&
	    fifo_pop(&c->unused, r))
		return r;

	if ((!CACHE_SYNC(&c->set->sb) ||
	     atomic_read(&c->prio_written) > 0) &&
	    fifo_pop(&c->free_inc, r))
		return r;

	return -1;
}

/* Discard/TRIM */

struct discard {
	struct list_head	list;
	struct work_struct	work;
	struct cache		*c;
	long			bucket;

	struct bio		bio;
	struct bio_vec		bv;
};

static void discard_put(struct cache *c)
{
	atomic_dec_bug(&c->discards_pin);
	smp_mb();
	if (atomic_read(&c->set->closing))
		closure_wake_up(&c->set->bucket_wait);
}

static void discard_finish(struct work_struct *w)
{
	struct discard *d = container_of(w, struct discard, work);
	struct cache *c = d->c;
	char buf[BDEVNAME_SIZE];
	bool run = false;

	if (!test_bit(BIO_UPTODATE, &d->bio.bi_flags)) {
		printk(KERN_NOTICE "bcache: discard error on %s, disabling\n",
		       bdevname(c->bdev, buf));
		d->c->discard = 0;
	}

	mutex_lock(&c->set->bucket_lock);
	if (fifo_empty(&c->free) ||
	    fifo_used(&c->free) == 8)
		run = true;

	fifo_push(&c->free, d->bucket);

	list_add(&d->list, &c->discards);
	discard_put(c);

	do_discard(c);
	mutex_unlock(&c->set->bucket_lock);

	if (run)
		closure_wake_up(&c->set->bucket_wait);
}

static void discard_endio(struct bio *bio, int error)
{
	struct discard *d = container_of(bio, struct discard, bio);

	PREPARE_WORK(&d->work, discard_finish);
	schedule_work(&d->work);
}

static void discard_work(struct work_struct *w)
{
	struct discard *d = container_of(w, struct discard, work);
	submit_bio(0, &d->bio);
}

static void do_discard(struct cache *c)
{
	struct request_queue *q = bdev_get_queue(c->bdev);
	int s = q->limits.logical_block_size;

	atomic_inc(&c->discards_pin);
	smp_mb();
	/* Between getting discards_pin and the c->set->closing check */

	while (c->discard &&
	       !atomic_read(&c->set->closing) &&
	       !list_empty(&c->discards) &&
	       fifo_free(&c->free) >= 8) {
		struct discard *d = list_first_entry(&c->discards,
						     struct discard, list);

		d->bucket = pop_freed(c);
		if (d->bucket == -1)
			break;

		list_del(&d->list);
		atomic_inc(&c->discards_pin);

		bio_init(&d->bio);
		memset(&d->bv, 0, sizeof(struct bio_vec));
		bio_set_prio(&d->bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

		d->bio.bi_sector	= bucket_to_sector(c->set, d->bucket);
		d->bio.bi_bdev		= c->bdev;
		d->bio.bi_rw		= REQ_WRITE|(1 << BIO_RW_DISCARD);
		d->bio.bi_max_vecs	= 1;
		d->bio.bi_io_vec	= d->bio.bi_inline_vecs;
		d->bio.bi_end_io	= discard_endio;

		if (bio_add_pc_page(q, &d->bio, c->discard_page, s, 0) < s) {
			printk(KERN_DEBUG "bcache: bio_add_pc_page failed\n");
			c->discard = 0;
			fifo_push(&c->free, d->bucket);
			list_add(&d->list, &c->discards);
			break;
		}

		d->bio.bi_size = bucket_bytes(c);

		schedule_work(&d->work);
	}

	discard_put(c);
}

void free_discards(struct cache *ca)
{
	struct discard *d;

	while (!list_empty(&ca->discards)) {
		d = list_first_entry(&ca->discards, struct discard, list);
		cancel_work_sync(&d->work);
		list_del(&d->list);
		kfree(d);
	}
}

int alloc_discards(struct cache *ca)
{
	for (int i = 0; i < 8; i++) {
		struct discard *d = kzalloc(sizeof(*d), GFP_KERNEL);
		if (!d)
			return -ENOMEM;

		d->c = ca;
		INIT_WORK(&d->work, discard_work);
		list_add(&d->list, &ca->discards);
	}

	return 0;
}

/* Allocation */

bool bucket_add_unused(struct cache *c, struct bucket *b)
{
	if (c->prio_alloc == prio_buckets(c) &&
	    CACHE_REPLACEMENT(&c->sb) == CACHE_REPLACEMENT_FIFO)
		return false;

	b->prio = 0;

	if (bucket_gc_gen(b) < 96U &&
	    bucket_disk_gen(b) < 64U &&
	    fifo_push(&c->unused, b - c->buckets)) {
		atomic_inc(&b->pin);
		return true;
	}

	return false;
}

static bool can_invalidate_bucket(struct cache *c, struct bucket *b)
{
	return b->mark >= 0 &&
		!atomic_read(&b->pin) &&
		bucket_gc_gen(b) < 96U &&
		bucket_disk_gen(b) < 64U;
}

static void invalidate_one_bucket(struct cache *c, struct bucket *b)
{
	inc_gen(c, b);
	b->prio = initial_prio;
	atomic_inc(&b->pin);
	fifo_push(&c->free_inc, b - c->buckets);
}

static void invalidate_buckets_lru(struct cache *c)
{
	unsigned bucket_prio(struct bucket *b)
	{
		return ((unsigned) (b->prio - c->set->min_prio)) * b->mark;
	}

	bool bucket_max_cmp(struct bucket *l, struct bucket *r)
	{
		return bucket_prio(l) < bucket_prio(r);
	}

	bool bucket_min_cmp(struct bucket *l, struct bucket *r)
	{
		return bucket_prio(l) > bucket_prio(r);
	}

	struct bucket *b;

	c->heap.used = 0;

	for_each_bucket(b, c) {
		if (!can_invalidate_bucket(c, b))
			continue;

		if (!b->mark) {
			if (!bucket_add_unused(c, b))
				return;
		} else {
			if (!heap_full(&c->heap))
				heap_add(&c->heap, b, bucket_max_cmp);
			else if (bucket_max_cmp(b, heap_peek(&c->heap))) {
				c->heap.data[0] = b;
				heap_sift(&c->heap, 0, bucket_max_cmp);
			}
		}
	}

	if (c->heap.used * 2 < c->heap.size)
		queue_work(bcache_wq, &c->set->gc_work);

	for (ssize_t i = c->heap.used / 2 - 1; i >= 0; --i)
		heap_sift(&c->heap, i, bucket_min_cmp);

	while (!fifo_full(&c->free_inc)) {
		if (!heap_pop(&c->heap, b, bucket_min_cmp)) {
			/* We don't want to be calling invalidate_buckets()
			 * multiple times when it can't do anything
			 */
			c->invalidate_needs_gc = 1;
			queue_work(bcache_wq, &c->set->gc_work);
			return;
		}

		invalidate_one_bucket(c, b);
	}
}

static void invalidate_buckets_fifo(struct cache *c)
{
	struct bucket *b;
	size_t checked = 0;

	while (!fifo_full(&c->free_inc)) {
		if (c->fifo_last_bucket <  c->sb.first_bucket ||
		    c->fifo_last_bucket >= c->sb.nbuckets)
			c->fifo_last_bucket = c->sb.first_bucket;

		b = c->buckets + c->fifo_last_bucket++;

		if (can_invalidate_bucket(c, b))
			invalidate_one_bucket(c, b);

		if (++checked >= c->sb.nbuckets) {
			c->invalidate_needs_gc = 1;
			queue_work(bcache_wq, &c->set->gc_work);
			return;
		}
	}
}

static void invalidate_buckets_random(struct cache *c)
{
	struct bucket *b;
	size_t checked = 0;

	while (!fifo_full(&c->free_inc)) {
		size_t n;
		get_random_bytes(&n, sizeof(n));

		n %= (size_t) (c->sb.nbuckets - c->sb.first_bucket);
		n += c->sb.first_bucket;

		b = c->buckets + n;

		if (can_invalidate_bucket(c, b))
			invalidate_one_bucket(c, b);

		if (++checked >= c->sb.nbuckets / 2) {
			c->invalidate_needs_gc = 1;
			queue_work(bcache_wq, &c->set->gc_work);
			return;
		}
	}
}

static void invalidate_buckets(struct cache *c)
{
	/* free_some_buckets() may just need to write priorities to keep gens
	 * from wrapping around
	 */
	if (!c->set->gc_mark_valid ||
	    c->invalidate_needs_gc)
		return;

	switch (CACHE_REPLACEMENT(&c->sb)) {
	case CACHE_REPLACEMENT_LRU:
		invalidate_buckets_lru(c);
		break;
	case CACHE_REPLACEMENT_FIFO:
		invalidate_buckets_fifo(c);
		break;
	case CACHE_REPLACEMENT_RANDOM:
		invalidate_buckets_random(c);
		break;
	}
}

bool can_save_prios(struct cache *c)
{
	return ((c->need_save_prio > 64 ||
		 (c->set->gc_mark_valid &&
		  !c->invalidate_needs_gc)) &&
		!atomic_read(&c->prio_written) &&
		!atomic_read(&c->set->prio_blocked));
}

void free_some_buckets(struct cache *c)
{
	long r;

	do_discard(c);

	while (!fifo_full(&c->free) &&
	       (fifo_used(&c->free) <= 8 ||
		!c->discard) &&
	       (r = pop_freed(c)) != -1)
		fifo_push(&c->free, r);

	while (c->prio_alloc != prio_buckets(c) &&
	       fifo_pop(&c->free, r)) {
		struct bucket *b = c->buckets + r;
		c->prio_next[c->prio_alloc++] = r;

		b->mark = GC_MARK_BTREE;
		atomic_dec_bug(&b->pin);
	}

	if (!CACHE_SYNC(&c->set->sb)) {
		if (fifo_empty(&c->free_inc))
			invalidate_buckets(c);
		return;
	}

	/* XXX: tracepoint for when c->need_save_prio > 64 */

	if (c->need_save_prio <= 64 &&
	    fifo_used(&c->unused) > c->unused.size / 2)
		return;

	if (atomic_read(&c->prio_written) > 0 &&
	    (fifo_empty(&c->free_inc) ||
	     c->need_save_prio > 64))
		atomic_set(&c->prio_written, 0);

	if (!can_save_prios(c))
		return;

	invalidate_buckets(c);

	if (!fifo_empty(&c->free_inc) ||
	    c->need_save_prio > 64)
		prio_write(c, NULL);
}

static long pop_bucket(struct cache *c, uint16_t priority, struct closure *cl)
{
	long r = -1;
again:
	free_some_buckets(c);

	if ((priority == btree_prio ||
	     fifo_used(&c->free) > 8) &&
	    fifo_pop(&c->free, r)) {
		struct bucket *b = c->buckets + r;
#ifdef CONFIG_BCACHE_EDEBUG
		long i;
		for (unsigned j = 0; j < prio_buckets(c); j++)
			BUG_ON(c->prio_buckets[j] == (uint64_t) r);
		for (unsigned j = 0; j < c->prio_alloc; j++)
			BUG_ON(c->prio_next[j] == (uint64_t) r);

		fifo_for_each(i, &c->free)
			BUG_ON(i == r);
		fifo_for_each(i, &c->free_inc)
			BUG_ON(i == r);
		fifo_for_each(i, &c->unused)
			BUG_ON(i == r);
#endif
		BUG_ON(atomic_read(&b->pin) != 1);

		b->prio = priority;
		b->mark = priority == btree_prio
			? GC_MARK_BTREE
			: c->sb.bucket_size;
		return r;
	}

	pr_debug("no free buckets, prio_written %i, blocked %i, "
		 "free %zu, free_inc %zu, unused %zu",
		 atomic_read(&c->prio_written),
		 atomic_read(&c->set->prio_blocked), fifo_used(&c->free),
		 fifo_used(&c->free_inc), fifo_used(&c->unused));

	if (cl) {
		if (closure_blocking(cl))
			mutex_unlock(&c->set->bucket_lock);

		closure_wait_event(&c->set->bucket_wait, cl,
				   atomic_read(&c->prio_written) > 0 ||
				   can_save_prios(c));

		if (closure_blocking(cl)) {
			mutex_lock(&c->set->bucket_lock);
			goto again;
		}
	}

	return -1;
}

void unpop_bucket(struct cache_set *c, struct bkey *k)
{
	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bucket *b = PTR_BUCKET(c, k, i);

		b->mark = 0;
		bucket_add_unused(PTR_CACHE(c, k, i), b);
	}
}

int __pop_bucket_set(struct cache_set *c, uint16_t prio,
		     struct bkey *k, int n, struct closure *cl)
{
	lockdep_assert_held(&c->bucket_lock);
	BUG_ON(!n || n > c->caches_loaded || n > 8);

	k->header = KEY_HEADER(0, 0);

	/* sort by free space/prio of oldest data in caches */

	for (int i = 0; i < n; i++) {
		struct cache *ca = c->cache_by_alloc[i];
		long b = pop_bucket(ca, prio, cl);

		if (b == -1)
			goto err;

		k->ptr[i] = PTR(ca->buckets[b].gen,
				bucket_to_sector(c, b),
				ca->sb.nr_this_dev);

		SET_KEY_PTRS(k, i + 1);
	}

	return 0;
err:
	unpop_bucket(c, k);
	__bkey_put(c, k);
	return -1;
}

int pop_bucket_set(struct cache_set *c, uint16_t prio,
		   struct bkey *k, int n, struct closure *cl)
{
	int ret;
	mutex_lock(&c->bucket_lock);
	ret = __pop_bucket_set(c, prio, k, n, cl);
	mutex_unlock(&c->bucket_lock);
	return ret;
}
