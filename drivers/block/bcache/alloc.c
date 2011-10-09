
#include "bcache.h"

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

	spin_lock(&c->bucket_lock);

	for_each_cache(ca, c)
		for_each_bucket(b, ca)
			if (b->prio &&
			    b->prio != btree_prio &&
			    !atomic_read(&b->pin)) {
				b->prio--;
				c->min_prio = min(c->min_prio, b->prio);
			}

	spin_unlock(&c->bucket_lock);
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

static void discard_finish(struct work_struct *w)
{
	struct discard *d = container_of(w, struct discard, work);
	struct cache *c = d->c;
	bool run = false;

	spin_lock(&c->set->bucket_lock);
	if (fifo_empty(&c->free) ||
	    fifo_used(&c->free) == 8)
		run = true;

	fifo_push(&c->free, d->bucket);

	list_add(&d->list, &c->discards);

	do_discard(c);
	spin_unlock(&c->set->bucket_lock);

	if (run)
		closure_run_wait(&c->set->bucket_wait, NULL);
}

static void discard_endio(struct bio *bio, int error)
{
	struct discard *d = container_of(bio, struct discard, bio);

	if (error) {
		printk(KERN_NOTICE "bcache: discard error, disabling\n");
		d->c->discard = 0;
	}

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

	while (c->discard &&
	       !list_empty(&c->discards) &&
	       fifo_free(&c->free) >= 8) {
		struct discard *d = list_first_entry(&c->discards,
						     struct discard, list);

		d->bucket = pop_freed(c);
		if (d->bucket == -1)
			break;

		list_del(&d->list);

		bio_init(&d->bio);
		memset(&d->bv, 0, sizeof(struct bio_vec));
		bio_set_prio(&d->bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

		d->bio.bi_sector	= bucket_to_sector(c->set, d->bucket);
		d->bio.bi_bdev		= c->bdev;
		d->bio.bi_rw		= DISCARD_NOBARRIER;
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
	b->prio = 0;

	if (bucket_gc_gen(b) < 96U &&
	    bucket_disk_gen(b) < 64U &&
	    fifo_push(&c->unused, b - c->buckets)) {
		atomic_inc(&b->pin);
		return true;
	}

	return false;
}

static void invalidate_buckets(struct cache *c)
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
	size_t pinned = 0, gc_gen = 0, disk_gen = 0;

	/* free_some_buckets() may just need to write priorities to keep gens
	 * from wrapping around
	 */
	if (!c->set->gc_mark_valid ||
	    c->invalidate_needs_gc)
		return;

	c->heap.used = 0;

	for_each_bucket(b, c) {
		if (b->mark < 0)
			continue;

		if (atomic_read(&b->pin))
			pinned++;
		else if (bucket_gc_gen(b) >= 96U)
			gc_gen++;
		else if (bucket_disk_gen(b) >= 64U)
			disk_gen++;
		else if (!b->mark) {
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

	if (c->heap.used * 2 < c->heap.size) {
		queue_work(bcache_wq, &c->set->gc_work);
		pr_debug("heap %zu/%llu: pinned %zu gc_gen %zu disk_gen %zu",
			 c->heap.used, c->sb.nbuckets,
			 pinned, gc_gen, disk_gen);
	}

	for (ssize_t i = c->heap.used / 2 - 1; i >= 0; --i)
		heap_sift(&c->heap, i, bucket_min_cmp);

	while (!fifo_full(&c->free_inc)) {
		if (!heap_pop(&c->heap, b, bucket_min_cmp)) {
			/* We don't want to be calling invalidate_buckets()
			 * multiple times when it can't do anything
			 */
			c->invalidate_needs_gc = 1;
			return;
		}

		inc_gen(c, b);
		smp_mb();

		if (atomic_read(&b->pin))
			continue;

		b->prio = initial_prio;
		atomic_inc(&b->pin);
		fifo_push(&c->free_inc, b - c->buckets);
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
		if (test_bit(CLOSURE_BLOCK, &cl->flags))
			spin_unlock(&c->set->bucket_lock);

		closure_wait_on(&c->set->bucket_wait, bcache_wq, cl,
				atomic_read(&c->prio_written) > 0 ||
				can_save_prios(c));

		if (test_bit(CLOSURE_BLOCK, &cl->flags)) {
			spin_lock(&c->set->bucket_lock);
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
	spin_lock(&c->bucket_lock);
	ret = __pop_bucket_set(c, prio, k, n, cl);
	spin_unlock(&c->bucket_lock);
	return ret;
}
