/*
 * Primary bucket allocation code
 *
 * Copyright 2012 Google, Inc.
 *
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
 * call prio_write(), and when prio_write() finishes we pull buckets off the
 * free_inc list and optionally discard them.
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
 * bch_bucket_alloc() allocates a single bucket from a specific cache.
 *
 * bch_bucket_alloc_set() allocates one or more buckets from different caches
 * out of a cache set.
 *
 * free_some_buckets() drives all the processes described above. It's called
 * from bch_bucket_alloc() and a few other places that need to make sure free
 * buckets are ready.
 *
 * invalidate_buckets_(lru|fifo)() find buckets that are available to be
 * invalidated, and then invalidate them and stick them on the free_inc list -
 * in either lru or fifo order.
 */

#include "bcache.h"
#include "alloc.h"
#include "btree.h"
#include "extents.h"

#include <linux/blkdev.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <trace/events/bcache.h>

static void alloc_failed(struct cache *ca)
{
	struct cache_set *c = ca->set;
	unsigned i;

	for (i = CACHE_TIER(&ca->sb) + 1;
	     i < ARRAY_SIZE(c->cache_by_alloc);
	     i++)
		if (c->cache_by_alloc[i].nr_devices) {
			c->tiering_pd.rate.rate = UINT_MAX;
			bch_ratelimit_reset(&c->tiering_pd.rate);
		}

	trace_bcache_alloc_wait(ca);

	mutex_unlock(&c->bucket_lock);
	bch_wait_for_next_gc(c, true);
	mutex_lock(&c->bucket_lock);
}

/* Bucket heap / gen */

void bch_recalc_min_prio(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket *b;
	unsigned i;

	/* Determine min prio for this particular cache */
	u16 max_read_delta = 0;
	u16 max_write_delta = 0;

	for_each_bucket(b, ca) {
		max_read_delta = max(max_read_delta,
			(u16)(c->read_clock.hand - b->read_prio));

		max_write_delta = max(max_write_delta,
			(u16)(c->write_clock.hand - b->write_prio));
	}
	ca->min_read_prio = c->read_clock.hand - max_read_delta;
	ca->min_write_prio = c->write_clock.hand - max_write_delta;

	/* This may possibly increase the min prio for the whole
	 * cache, check that as well. */
	max_read_delta = 0;
	max_write_delta = 0;
	for_each_cache(ca, c, i) {
		max_read_delta = max(max_read_delta,
			(u16)(c->read_clock.hand - ca->min_read_prio));

		max_write_delta = max(max_write_delta,
			(u16)(c->write_clock.hand - ca->min_write_prio));
	}
	c->read_clock.min_prio = c->read_clock.hand - max_read_delta;
	c->write_clock.min_prio = c->write_clock.hand - max_write_delta;
}

static void bch_rescale_prios(struct cache_set *c, int rw)
{
	struct cache *ca;
	struct bucket *b;
	unsigned i;

	for_each_cache(ca, c, i) {
		for_each_bucket(b, ca) {
			if (rw)
				b->write_prio = c->write_clock.hand -
					(c->write_clock.hand - b->write_prio)/2;
			else
				b->read_prio = c->read_clock.hand -
					(c->read_clock.hand - b->read_prio)/2;
		}

		bch_recalc_min_prio(ca);
	}
}

void bch_increment_clock(struct cache_set *c, int sectors, int rw)
{
	long next = (c->nbuckets * c->sb.bucket_size) / 1024;
	struct prio_clock *clock = rw ? &c->write_clock : &c->read_clock;
	long r;

	/*
	 * we only increment when 0.1% of the cache_set has been read
	 * or written too, this determines if it's time
	 */
	atomic_long_sub(sectors, &clock->rescale);

	do {
		r = atomic_long_read(&clock->rescale);

		if (r >= 0)
			return;
	} while (atomic_long_cmpxchg(&clock->rescale, r, r + next) != r);

	mutex_lock(&c->bucket_lock);

	clock->hand++;

	/* if clock cannot be advanced more, rescale prio */
	if (clock->hand == (u16)(clock->min_prio - 1))
		bch_rescale_prios(c, rw);

	mutex_unlock(&c->bucket_lock);
}

/*
 * Background allocation thread: scans for buckets to be invalidated,
 * invalidates them, rewrites prios/gens (marking them as invalidated on disk),
 * then optionally issues discard commands to the newly free buckets, then puts
 * them on the various freelists.
 */

static inline bool can_inc_bucket_gen(struct bucket *b)
{
	return bucket_gc_gen(b) < BUCKET_GC_GEN_MAX;
}

bool bch_can_invalidate_bucket(struct cache *ca, struct bucket *b)
{
	BUG_ON(!ca->set->gc_mark_valid);

	return (!GC_MARK(b) ||
		GC_MARK(b) == GC_MARK_RECLAIMABLE) &&
		can_inc_bucket_gen(b);
}

void __bch_invalidate_one_bucket(struct cache *ca, struct bucket *b)
{
	lockdep_assert_held(&ca->set->bucket_lock);
	BUG_ON(GC_MARK(b) && GC_MARK(b) != GC_MARK_RECLAIMABLE);
	BUG_ON(!ca->buckets_free);

	if (GC_SECTORS_USED(b))
		trace_bcache_invalidate(ca, b - ca->buckets);

	b->gen++;
	/* this is what makes ptrs to the bucket invalid */

	b->read_prio = ca->set->read_clock.hand;
	b->write_prio = ca->set->write_clock.hand;
	SET_GC_MARK(b, GC_MARK_DIRTY);
	SET_GC_GEN(b, 0);
	SET_GC_SECTORS_USED(b, min_t(unsigned, ca->sb.bucket_size,
				     MAX_GC_SECTORS_USED));

	ca->buckets_free--;
}

static void bch_invalidate_one_bucket(struct cache *ca, struct bucket *b)
{
	__bch_invalidate_one_bucket(ca, b);

	fifo_push(&ca->free_inc, b - ca->buckets);
}

/*
 * Determines what order we're going to reuse buckets, smallest bucket_prio()
 * first: we also take into account the number of sectors of live data in that
 * bucket, and in order for that multiply to make sense we have to scale bucket
 *
 * Thus, we scale the bucket priorities so that the prio farthest from the clock
 * is worth 1/8th of the closest.
 */

#define bucket_prio(b)							\
({									\
	u16 prio = b->read_prio - ca->min_read_prio;			\
	prio = (prio * 7) / (ca->set->read_clock.hand -			\
			     ca->min_read_prio);			\
									\
	(prio+1) * GC_SECTORS_USED(b);					\
})

#define bucket_max_cmp(l, r)	(bucket_prio(l) < bucket_prio(r))
#define bucket_min_cmp(l, r)	(bucket_prio(l) > bucket_prio(r))

static void invalidate_buckets_lru(struct cache *ca)
{
	struct bucket *b;

	ca->heap.used = 0;

	bch_recalc_min_prio(ca);

	for_each_bucket(b, ca) {
		if (!bch_can_invalidate_bucket(ca, b))
			continue;

		if (!heap_full(&ca->heap))
			heap_add(&ca->heap, b, bucket_max_cmp);
		else if (bucket_max_cmp(b, heap_peek(&ca->heap))) {
			ca->heap.data[0] = b;
			heap_sift(&ca->heap, 0, bucket_max_cmp);
		}
	}

	heap_resort(&ca->heap, bucket_min_cmp);

	while (!fifo_full(&ca->free_inc)) {
		if (!heap_pop(&ca->heap, b, bucket_min_cmp)) {
			/*
			 * We don't want to be calling invalidate_buckets()
			 * multiple times when it can't do anything
			 */
			alloc_failed(ca);
			return;
		}

		bch_invalidate_one_bucket(ca, b);
	}
}

static void invalidate_buckets_fifo(struct cache *ca)
{
	struct bucket *b;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		if (ca->fifo_last_bucket <  ca->sb.first_bucket ||
		    ca->fifo_last_bucket >= ca->sb.nbuckets)
			ca->fifo_last_bucket = ca->sb.first_bucket;

		b = ca->buckets + ca->fifo_last_bucket++;

		if (bch_can_invalidate_bucket(ca, b))
			bch_invalidate_one_bucket(ca, b);

		if (++checked >= ca->sb.nbuckets) {
			alloc_failed(ca);
			return;
		}
	}
}

static void invalidate_buckets_random(struct cache *ca)
{
	struct bucket *b;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n;
		get_random_bytes(&n, sizeof(n));

		n %= (size_t) (ca->sb.nbuckets - ca->sb.first_bucket);
		n += ca->sb.first_bucket;

		b = ca->buckets + n;

		if (bch_can_invalidate_bucket(ca, b))
			bch_invalidate_one_bucket(ca, b);

		if (++checked >= ca->sb.nbuckets / 2) {
			alloc_failed(ca);
			return;
		}
	}
}

static void invalidate_buckets(struct cache *ca)
{
	size_t dirty = 0, meta = 0, gen = 0;
	struct bucket *b;

	BUG_ON(!ca->set->gc_mark_valid);

	for_each_bucket(b, ca) {
		if (GC_MARK(b) == GC_MARK_DIRTY)
			dirty++;
		if (GC_MARK(b) == GC_MARK_METADATA)
			meta++;
		if (!can_inc_bucket_gen(b))
			gen++;
	}

	pr_debug("dirty %zu meta %zu gen %zu total %llu",
		 dirty, meta, gen, ca->sb.nbuckets - ca->sb.first_bucket);

	switch (CACHE_REPLACEMENT(&ca->sb)) {
	case CACHE_REPLACEMENT_LRU:
		invalidate_buckets_lru(ca);
		break;
	case CACHE_REPLACEMENT_FIFO:
		invalidate_buckets_fifo(ca);
		break;
	case CACHE_REPLACEMENT_RANDOM:
		invalidate_buckets_random(ca);
		break;
	}
}

#define allocator_wait(c, x, cond)					\
do {									\
	DEFINE_WAIT(__wait);						\
	while (1) {							\
		prepare_to_wait(&x, &__wait, TASK_INTERRUPTIBLE);	\
		if (cond)						\
			break;						\
									\
		mutex_unlock(&c->bucket_lock);				\
		if (kthread_should_stop())				\
			return 0;					\
		try_to_freeze();					\
		schedule();						\
		mutex_lock(&c->bucket_lock);				\
	}								\
	finish_wait(&x, &__wait);					\
} while (0)

static int bch_allocator_push(struct cache *ca, long bucket)
{
	unsigned i;

	/* Prios/gens are actually the most important reserve */
	if (fifo_push(&ca->free[RESERVE_PRIO], bucket))
		return true;

	for (i = 0; i < RESERVE_NR; i++)
		if (fifo_push(&ca->free[i], bucket))
			return true;

	return false;
}

static int bch_allocator_thread(void *arg)
{
	struct cache *ca = arg;
	struct cache_set *c = ca->set;

	mutex_lock(&c->bucket_lock);

	while (1) {
		/*
		 * First, we pull buckets off of the free_inc lists, possibly
		 * issue discards to them, then we add the bucket to the
		 * free list:
		 */
		while (!fifo_empty(&ca->free_inc)) {
			long bucket = fifo_peek(&ca->free_inc);

			/*
			 * Don't remove from free_inc until after it's added
			 * to freelist, so gc doesn't miss it while we've
			 * dropped bucket lock
			 */

			if (ca->discard) {
				mutex_unlock(&c->bucket_lock);
				blkdev_issue_discard(ca->bdev,
					bucket_to_sector(c, bucket),
					ca->sb.bucket_size, GFP_KERNEL, 0);
				mutex_lock(&c->bucket_lock);
			}

			allocator_wait(c, ca->fifo_wait,
					bch_allocator_push(ca, bucket));
			fifo_pop(&ca->free_inc, bucket);

			wake_up(&c->btree_cache_wait);
			wake_up(&c->bucket_wait);
		}

		/*
		 * We've run out of free buckets, we need to find some buckets
		 * we can invalidate. First, invalidate them in memory and add
		 * them to the free_inc list:
		 */

retry_invalidate:
		allocator_wait(c, c->gc_wait, c->gc_mark_valid);

		invalidate_buckets(ca);

		if (CACHE_SYNC(&ca->set->sb)) {
			/*
			 * This could deadlock if an allocation with a btree
			 * node locked ever blocked - having the btree node
			 * locked would block garbage collection, but here we're
			 * waiting on garbage collection before we invalidate
			 * and free anything.
			 *
			 * But this should be safe since the btree code always
			 * uses btree_check_reserve() before allocating now, and
			 * if it fails it blocks without btree nodes locked.
			 */
			trace_bcache_alloc_batch(ca,
						fifo_used(&ca->free_inc),
						ca->free_inc.size);

			if (!fifo_full(&ca->free_inc))
				goto retry_invalidate;

			bch_prio_write(ca);
		}
	}
}

/* Allocation */

long bch_bucket_alloc(struct cache *ca, enum alloc_reserve reserve, bool wait)
{
	DEFINE_WAIT(w);
	struct bucket *b;
	long r;

	lockdep_assert_held(&ca->set->bucket_lock);

	/* fastpath */
	if (fifo_pop(&ca->free[RESERVE_NONE], r) ||
	    fifo_pop(&ca->free[reserve], r))
		goto out;

	if (!wait) {
		trace_bcache_alloc_fail(ca, reserve);
		return -1;
	}

	do {
		prepare_to_wait(&ca->set->bucket_wait, &w,
				TASK_UNINTERRUPTIBLE);

		mutex_unlock(&ca->set->bucket_lock);
		schedule();
		mutex_lock(&ca->set->bucket_lock);
	} while (!fifo_pop(&ca->free[RESERVE_NONE], r) &&
		 !fifo_pop(&ca->free[reserve], r));

	finish_wait(&ca->set->bucket_wait, &w);
out:
	wake_up(&ca->fifo_wait);

	trace_bcache_alloc(ca, reserve);

	if (expensive_debug_checks(ca->set)) {
		size_t iter;
		long i;
		unsigned j;

		for (iter = 0; iter < prio_buckets(ca) * 2; iter++)
			BUG_ON(ca->prio_buckets[iter] == (uint64_t) r);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each(i, &ca->free[j], iter)
				BUG_ON(i == r);
		fifo_for_each(i, &ca->free_inc, iter)
			BUG_ON(i == r);
	}

	b = ca->buckets + r;

	BUG_ON(ca->set->gc_mark_valid &&
	       GC_MARK(b) != GC_MARK_DIRTY);

	if (reserve <= RESERVE_MOVINGGC_BTREE)
		SET_GC_MARK(b, GC_MARK_METADATA);

	b->read_prio = ca->set->read_clock.hand;
	b->write_prio = ca->set->write_clock.hand;

	return r;
}

void __bch_bucket_free(struct cache *ca, struct bucket *b)
{
	lockdep_assert_held(&ca->set->bucket_lock);

	if ((GC_MARK(b) &&
	     GC_MARK(b) != GC_MARK_RECLAIMABLE) ||
	    !ca->set->gc_mark_valid)
		ca->buckets_free++;

	SET_GC_MARK(b, 0);
	SET_GC_SECTORS_USED(b, 0);
	b->read_prio = ca->set->read_clock.hand;
	b->write_prio = ca->set->write_clock.hand;
}

void bch_bucket_free(struct cache_set *c, struct bkey *k)
{
	unsigned i;

	mutex_lock(&c->bucket_lock);

	for (i = 0; i < bch_extent_ptrs(k); i++)
		__bch_bucket_free(PTR_CACHE(c, k, i),
				  PTR_BUCKET(c, k, i));

	mutex_unlock(&c->bucket_lock);
}

static struct cache *bch_next_cache(struct cache_set *c,
				    enum alloc_reserve reserve,
				    int tier_idx, bool wait,
				    long *cache_used)
{
	DEFINE_WAIT(w);

	struct cache **devices;
	size_t sectors_count = 0, rand;
	int i, nr_devices;

	/* first ptr allocation will always go to the specified tier,
	 * 2nd and greater can go to any. If one tier is significantly larger
	 * it is likely to go that tier. */

	if (tier_idx == -1) {
		devices = c->cache;
		nr_devices = c->sb.nr_in_set;
	} else {
		struct cache_tier *tier = &c->cache_by_alloc[tier_idx];

		devices = tier->devices;
		nr_devices = tier->nr_devices;
	}

	while (1) {
		for (i = 0; i < nr_devices; i++) {
			if (test_bit(devices[i]->sb.nr_this_dev, cache_used))
				continue;

			sectors_count +=
				buckets_free_cache(devices[i], reserve);
		}

		/* fast path */
		if (sectors_count)
			break;

		if (!wait)
			return NULL;

		prepare_to_wait(&c->bucket_wait, &w, TASK_UNINTERRUPTIBLE);
		mutex_unlock(&c->bucket_lock);
		schedule();
		mutex_lock(&c->bucket_lock);
	}

	finish_wait(&c->bucket_wait, &w);

	/*
	 * We create a weighted selection by using the number of free buckets
	 * in each cache. You can think of this like lining up the caches
	 * linearly so each as a given range, corresponding to the number of
	 * free buckets in that cache, and then randomly picking a number
	 * within that range.
	 */

	get_random_bytes(&rand, sizeof(rand));
	rand %= sectors_count;

	for (i = 0; i < nr_devices; i++) {
		if (test_bit(devices[i]->sb.nr_this_dev, cache_used))
			continue;

		sectors_count -= buckets_free_cache(devices[i], reserve);

		if (rand >= sectors_count) {
			__set_bit(devices[i]->sb.nr_this_dev, cache_used);
			return devices[i];
		}
	}

	BUG(); /* off by one error? */

	return NULL;
}

int bch_bucket_alloc_set(struct cache_set *c, enum alloc_reserve reserve,
			 struct bkey *k, int n,
			 unsigned tier_idx, bool wait)
{
	long caches_used[BITS_TO_LONGS(MAX_CACHES_PER_SET)];
	int i;

	mutex_lock(&c->bucket_lock);
	BUG_ON(!n || n > c->sb.nr_in_set || n > MAX_CACHES_PER_SET);

	bkey_init(k);
	memset(caches_used, 0, sizeof(caches_used));

	/* sort by free space/prio of oldest data in caches */

	for (i = 0; i < n; i++) {
		struct cache *ca;
		long b;

		/* first ptr goes to the specified tier, the rest to any */
		ca = bch_next_cache(c, reserve, i == 0 ? tier_idx : -1,
				    wait, caches_used);

		if (!ca)
			goto err;

		b = bch_bucket_alloc(ca, reserve, wait);

		if (b == -1)
			goto err;

		k->val[i] = PTR(ca->buckets[b].gen,
				bucket_to_sector(c, b),
				ca->sb.nr_this_dev);

		bch_set_extent_ptrs(k, i + 1);
	}

	mutex_unlock(&c->bucket_lock);
	return 0;
err:
	mutex_unlock(&c->bucket_lock);
	bch_bucket_free(c, k);
	return -1;
}

static void __bch_open_bucket_put(struct cache_set *c, struct open_bucket *b)
{
	lockdep_assert_held(&c->open_buckets_lock);

	list_move(&b->list, &c->open_buckets_free);
	c->open_buckets_nr_free++;
	wake_up(&c->open_buckets_wait);
}

void bch_open_bucket_put(struct cache_set *c, struct open_bucket *b)
{
	if (atomic_dec_and_test(&b->pin)) {
		spin_lock(&c->open_buckets_lock);
		__bch_open_bucket_put(c, b);
		spin_unlock(&c->open_buckets_lock);
	}
}

static struct open_bucket *__bch_open_bucket_get(struct cache_set *c,
						 bool moving_gc)
{
	struct open_bucket *ret = NULL;
	unsigned reserve = (moving_gc ? 0 : OPEN_BUCKETS_MOVING_GC_RESERVE);

	spin_lock(&c->open_buckets_lock);

	if (c->open_buckets_nr_free > reserve) {
		BUG_ON(list_empty(&c->open_buckets_free));
		ret = list_first_entry(&c->open_buckets_free,
				       struct open_bucket, list);
		list_move(&ret->list, &c->open_buckets_open);
		atomic_set(&ret->pin, 1);
		ret->sectors_free = c->sb.bucket_size;
		bkey_init(&ret->key);
		c->open_buckets_nr_free--;
	}

	spin_unlock(&c->open_buckets_lock);

	return ret;
}

static struct open_bucket *bch_open_bucket_get(struct cache_set *c,
					       bool moving_gc)
{
	struct open_bucket *ret;

	ret = __bch_open_bucket_get(c, moving_gc);
	if (!ret) {
		trace_bcache_open_bucket_wait_start(c, moving_gc);
		wait_event(c->open_buckets_wait,
			(ret = __bch_open_bucket_get(c, moving_gc)));
		trace_bcache_open_bucket_wait_end(c, moving_gc);
	}

	return ret;
}

static struct open_bucket *bch_open_bucket_alloc(struct cache_set *c,
						 enum alloc_reserve reserve,
						 int n, unsigned tier,
						 bool wait)
{
	int ret;
	struct open_bucket *b;

	b = bch_open_bucket_get(c, false);

	ret = bch_bucket_alloc_set(c, reserve, &b->key, n, tier, wait);
	if (ret) {
		bch_open_bucket_put(c, b);
		b = NULL;
	}

	return b;
}

/* Sector allocator */

/*
 * We keep multiple buckets open for writes, and try to segregate different
 * write streams for better cache utilization: first we look for a bucket where
 * the last write to it was sequential with the current write, and failing that
 * we look for a bucket that was last used by the same task.
 *
 * The ideas is if you've got multiple tasks pulling data into the cache at the
 * same time, you'll get better cache utilization if you try to segregate their
 * data and preserve locality.
 *
 * For example, say you've starting Firefox at the same time you're copying a
 * bunch of files. Firefox will likely end up being fairly hot and stay in the
 * cache awhile, but the data you copied might not be; if you wrote all that
 * data to the same buckets it'd get invalidated at the same time.
 *
 * Both of those tasks will be doing fairly random IO so we can't rely on
 * detecting sequential IO to segregate their data, but going off of the task
 * should be a sane heuristic.
 */
static struct open_bucket *pick_data_bucket(struct cache_set *c,
					    const struct bkey *search,
					    unsigned write_point,
					    unsigned tier_idx,
					    bool wait)
	__releases(c->open_buckets_lock)
	__acquires(c->open_buckets_lock)
{
	struct cache_tier *tier = &c->cache_by_alloc[tier_idx];
	struct open_bucket *b;
	int i, wp = -1;
retry:
	for (i = 0;
	     i < ARRAY_SIZE(tier->data_buckets) &&
	     (b = tier->data_buckets[i]); i++) {
		if (!bkey_cmp(&b->key, &START_KEY(search)))
			goto found;
		else if (b->last_write_point == write_point)
			wp = i;
	}

	i = wp;
	if (i >= 0)
		goto found;

	i = ARRAY_SIZE(tier->data_buckets) - 1;
	if (tier->data_buckets[i])
		goto found;

	spin_unlock(&c->open_buckets_lock);
	b = bch_open_bucket_alloc(c, RESERVE_NONE, c->data_replicas,
				  tier_idx, wait);
	spin_lock(&c->open_buckets_lock);

	if (!b)
		return NULL;

	if (tier->data_buckets[i]) {
		/* we raced - and we must unlock to call bch_bucket_free()... */
		spin_unlock(&c->open_buckets_lock);
		bch_bucket_free(c, &b->key);
		spin_lock(&c->open_buckets_lock);

		__bch_open_bucket_put(c, b);
		goto retry;
	} else {
		tier->data_buckets[i] = b;
	}
found:
	b = tier->data_buckets[i];

	/*
	 * Move b to the end of the lru, and keep track of what
	 * this bucket was last used for:
	 */
	memmove(&tier->data_buckets[1],
		&tier->data_buckets[0],
		sizeof(struct open_bucket *) * i);

	tier->data_buckets[0] = b;

	b->last_write_point = write_point;
	bkey_copy_key(&b->key, search);

	return b;
}

/*
 * Allocates some space in the cache to write to, and k to point to the newly
 * allocated space, and updates KEY_SIZE(k) and KEY_OFFSET(k) (to point to the
 * end of the newly allocated space).
 *
 * May allocate fewer sectors than @sectors, KEY_SIZE(k) indicates how many
 * sectors were actually allocated.
 *
 * If s->writeback is true, will not fail
 *
 * @write_point - opaque identifier of where this write came from.
 *		  bcache uses ptr address of the task struct
 * @tier - which tier this write is destined towards
 * @wait - should the write wait for a bucket or fail if there isn't
 */
struct open_bucket *bch_alloc_sectors(struct cache_set *c, struct bkey *k,
				      unsigned write_point, unsigned tier_idx,
				      bool wait, unsigned long *ptrs_to_write)
{
	struct cache_tier *tier = &c->cache_by_alloc[tier_idx];
	struct open_bucket *b;
	unsigned i, sectors;

	spin_lock(&c->open_buckets_lock);

	b = pick_data_bucket(c, k, write_point, tier_idx, wait);
	if (!b) {
		spin_unlock(&c->open_buckets_lock);
		return NULL;
	}

	BUG_ON(b != tier->data_buckets[0]);

	for (i = 0; i < bch_extent_ptrs(&b->key); i++)
		EBUG_ON(ptr_stale(c, &b->key, i));

	/* Set up the pointer to the space we're allocating: */

	for (i = 0; i < bch_extent_ptrs(&b->key); i++) {
		unsigned ptrs = bch_extent_ptrs(k);

		k->val[ptrs] = b->key.val[i];
		__set_bit(ptrs, ptrs_to_write);
		bch_set_extent_ptrs(k, ptrs + 1);
	}

	sectors = min_t(unsigned, KEY_SIZE(k), b->sectors_free);

	SET_KEY_OFFSET(k, KEY_START(k) + sectors);
	SET_KEY_SIZE(k, sectors);

	/* update open bucket for next time: */

	b->sectors_free	-= sectors;
	for (i = 0; i < bch_extent_ptrs(&b->key); i++) {
		if (b->sectors_free)
			SET_PTR_OFFSET(&b->key, i,
				       PTR_OFFSET(&b->key, i) + sectors);

		atomic_long_add(sectors,
				&PTR_CACHE(c, &b->key, i)->sectors_written);
	}

	/*
	 * k takes refcounts on the buckets it points to until it's inserted
	 * into the btree, but if we're done with this bucket we just transfer
	 * get_data_bucket()'s refcount.
	 */

	if (b->sectors_free) {
		atomic_inc(&b->pin);
	} else {
		memmove(&tier->data_buckets[0],
			&tier->data_buckets[1],
			sizeof(struct open_bucket *) *
			(ARRAY_SIZE(tier->data_buckets) - 1));
		tier->data_buckets[ARRAY_SIZE(tier->data_buckets) - 1] = NULL;
	}

	spin_unlock(&c->open_buckets_lock);

	return b;
}

struct open_bucket *bch_gc_alloc_sectors(struct cache_set *c, struct bkey *k,
					 unsigned long *ptrs_to_write)
{
	unsigned i, gen, sectors = KEY_SIZE(k);
	struct cache *ca;
	struct open_bucket *b;
	long bucket;

	mutex_lock(&c->bucket_lock);
retry:
	for (i = 0; i < bch_extent_ptrs(k); i++)
		if (ptr_available(c, k, i) &&
		    GC_GEN(PTR_BUCKET(c, k, i)))
			goto found;

	mutex_unlock(&c->bucket_lock);
	return NULL;
found:
	ca = PTR_CACHE(c, k, i);
	gen = GC_GEN(PTR_BUCKET(c, k, i)) - 1;

	b = ca->gc_buckets[gen];
	if (!b) {
		mutex_unlock(&c->bucket_lock);

		b = bch_open_bucket_get(c, true);

		mutex_lock(&c->bucket_lock);

		bucket = bch_bucket_alloc(ca, RESERVE_MOVINGGC, true);
		b->key.val[0] = PTR(ca->buckets[bucket].gen,
				    bucket_to_sector(ca->set, bucket),
				    ca->sb.nr_this_dev);
		bch_set_extent_ptrs(&b->key, 1);

		/* we dropped bucket_lock, might've raced */
		if (ca->gc_buckets[gen]) {
			/* we raced */
			bch_bucket_free(c, &b->key);
			bch_open_bucket_put(c, b);
		} else {
			ca->gc_buckets[gen] = b;
		}

		/*
		 * GC_GEN() might also have been reset... don't strictly need to
		 * recheck though
		 */
		goto retry;
	}

	/* check to make sure bucket wasn't used while pinned */
	EBUG_ON(ptr_stale(c, &b->key, 0));

	k->val[i] = b->key.val[0];
	__set_bit(i, ptrs_to_write);

	sectors = min_t(unsigned, sectors, b->sectors_free);

	SET_KEY_OFFSET(k, KEY_START(k) + sectors);
	SET_KEY_SIZE(k, sectors);

	/* update open bucket for next time: */

	b->sectors_free	-= sectors;
	if (b->sectors_free) {
		SET_PTR_OFFSET(&b->key, 0, PTR_OFFSET(&b->key, 0) + sectors);
		atomic_inc(&b->pin);
	} else
		ca->gc_buckets[gen] = NULL;

	mutex_unlock(&c->bucket_lock);

	atomic_long_add(sectors, &ca->sectors_written);

	return b;
}

static void alloc_mark_bucket(struct cache *ca, size_t b)
{
	SET_GC_MARK(&ca->buckets[b], GC_MARK_DIRTY);
	SET_GC_SECTORS_USED(&ca->buckets[b],
			    min_t(unsigned, ca->sb.bucket_size,
				  MAX_GC_SECTORS_USED));
}

void bch_mark_open_buckets(struct cache_set *c)
{
	struct cache *ca;
	struct open_bucket *b;
	size_t ci, i, j, iter;

	for_each_cache(ca, c, ci) {
		for (i = 0; i < prio_buckets(ca) * 2; i++)
			if (ca->prio_buckets[i])
				alloc_mark_bucket(ca, ca->prio_buckets[i]);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each(i, &ca->free[j], iter)
				alloc_mark_bucket(ca, i);

		fifo_for_each(i, &ca->free_inc, iter)
			alloc_mark_bucket(ca, i);
	}

	spin_lock(&c->open_buckets_lock);

	list_for_each_entry(b, &c->open_buckets_open, list)
		for (i = 0; i < bch_extent_ptrs(&b->key); i++)
			alloc_mark_bucket(PTR_CACHE(c, &b->key, i),
					  PTR_BUCKET_NR(c, &b->key, i));

	spin_unlock(&c->open_buckets_lock);
}

/* Init */

void bch_open_buckets_init(struct cache_set *c)
{
	unsigned i;

	INIT_LIST_HEAD(&c->open_buckets_open);
	INIT_LIST_HEAD(&c->open_buckets_free);
	init_waitqueue_head(&c->open_buckets_wait);
	spin_lock_init(&c->open_buckets_lock);

	for (i = 0; i < ARRAY_SIZE(c->open_buckets); i++) {
		c->open_buckets_nr_free++;
		list_add(&c->open_buckets[i].list, &c->open_buckets_free);
	}
}

int bch_cache_allocator_start(struct cache *ca)
{
	struct task_struct *k = kthread_run(bch_allocator_thread,
					    ca, "bcache_allocator");
	if (IS_ERR(k))
		return PTR_ERR(k);

	ca->alloc_thread = k;
	return 0;
}
