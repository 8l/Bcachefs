/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"

#include <trace/events/bcache.h>
#include <linux/freezer.h>
#include <linux/kthread.h>

/* Moving GC - IO loop */

static bool moving_pred(struct scan_keylist *kl, struct bkey_s_c k)
{
	struct cache *ca = container_of(kl, struct cache,
					moving_gc_queue.keys);
	struct cache_set *c = ca->set;
	const struct bch_extent_ptr *ptr;
	bool ret = false;

	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

		rcu_read_lock();
		extent_for_each_ptr(e, ptr)
			if (PTR_CACHE(c, ptr) == ca &&
			    PTR_BUCKET(ca, ptr)->copygc_gen)
				ret = true;
		rcu_read_unlock();
	}

	return ret;
}

static int issue_moving_gc_move(struct moving_queue *q,
				struct moving_context *ctxt,
				struct bkey_i *k)
{
	struct cache *ca = container_of(q, struct cache, moving_gc_queue);
	struct cache_set *c = ca->set;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct moving_io *io;
	unsigned gen;

	io = moving_io_alloc(bkey_i_to_s_c(k));
	if (!io) {
		trace_bcache_moving_gc_alloc_fail(c, k->k.size);
		return -ENOMEM;
	}

	bch_write_op_init(&io->op, c, &io->bio.bio, NULL,
			  bkey_i_to_s_c(k), bkey_i_to_s_c(k),
			  bkey_extent_is_cached(&k->k)
			  ? BCH_WRITE_CACHED : 0);

	e = bkey_i_to_s_extent(&io->op.insert_key);

	extent_for_each_ptr(e, ptr)
		if ((ca->sb.nr_this_dev == ptr->dev) &&
		    (gen = PTR_BUCKET(ca, ptr)->copygc_gen)) {
			gen--;
			BUG_ON(gen > ARRAY_SIZE(ca->gc_buckets));
			io->op.wp = &ca->gc_buckets[gen];
			io->sort_key = ptr->offset;
			bch_extent_drop_ptr(e, ptr);
			goto found;
		}

	/* We raced - bucket's been reused */
	moving_io_free(io);
	goto out;
found:
	trace_bcache_gc_copy(&k->k);

	/*
	 * IMPORTANT: We must call bch_data_move before we dequeue so
	 * that the key can always be found in either the pending list
	 * in the moving queue or in the scan keylist list in the
	 * moving queue.
	 * If we reorder, there is a window where a key is not found
	 * by btree gc marking.
	 */
	bch_data_move(q, ctxt, io);
out:
	bch_scan_keylist_dequeue(&q->keys);
	return 0;
}

static void read_moving(struct cache *ca, struct moving_context *ctxt)
{
	struct bkey_i *k;
	bool again;

	bch_ratelimit_reset(&ca->moving_gc_pd.rate);

	do {
		again = false;

		while (!bch_moving_context_wait(ctxt)) {
			if (bch_queue_full(&ca->moving_gc_queue)) {
				if (ca->moving_gc_queue.rotational) {
					again = true;
					break;
				} else {
					bch_moving_wait(ctxt);
					continue;
				}
			}

			k = bch_scan_keylist_next_rescan(
				ca->set,
				&ca->moving_gc_queue.keys,
				&ctxt->last_scanned,
				POS_MAX,
				moving_pred);

			if (k == NULL)
				break;

			if (issue_moving_gc_move(&ca->moving_gc_queue,
						 ctxt, k)) {
				/*
				 * Memory allocation failed; we will wait for
				 * all queued moves to finish and continue
				 * scanning starting from the same key
				 */
				again = true;
				break;
			}
		}

		bch_queue_run(&ca->moving_gc_queue, ctxt);
	} while (again);
}

static bool bch_moving_gc(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket *g;
	bool moved = false;

	u64 sectors_to_move, sectors_gen, gen_current, sectors_total;
	size_t buckets_to_move, buckets_unused = 0;
	struct bucket_heap_entry e;
	unsigned sectors_used, i;
	int reserve_sectors;

	struct moving_context ctxt;

	bch_moving_context_init(&ctxt, &ca->moving_gc_pd.rate,
				MOVING_PURPOSE_COPY_GC);

	/*
	 * We won't fill up the moving GC reserve completely if the data
	 * being copied is from different generations. In the worst case,
	 * there will be NUM_GC_GENS buckets of internal fragmentation
	 */

	spin_lock(&ca->freelist_lock);
	reserve_sectors = ca->mi.bucket_size *
		(fifo_used(&ca->free[RESERVE_MOVINGGC]) - NUM_GC_GENS);
	spin_unlock(&ca->freelist_lock);

	if (reserve_sectors < (int) ca->sb.block_size) {
		trace_bcache_moving_gc_reserve_empty(ca);
		return false;
	}

	trace_bcache_moving_gc_start(ca);

	/*
	 * Find buckets with lowest sector counts, skipping completely
	 * empty buckets, by building a maxheap sorted by sector count,
	 * and repeatedly replacing the maximum element until all
	 * buckets have been visited.
	 */

	mutex_lock(&ca->heap_lock);
	ca->heap.used = 0;
	for_each_bucket(g, ca) {
		g->copygc_gen = 0;

		if (bucket_unused(g)) {
			buckets_unused++;
			continue;
		}

		if (g->mark.owned_by_allocator ||
		    g->mark.is_metadata)
			continue;

		sectors_used = bucket_sectors_used(g);

		if (sectors_used >= ca->mi.bucket_size)
			continue;

		bucket_heap_push(ca, g, sectors_used);
	}

	sectors_to_move = 0;
	for (i = 0; i < ca->heap.used; i++)
		sectors_to_move += ca->heap.data[i].val;

	/* XXX: calculate this threshold rigorously */

	if (ca->heap.used < ca->free_inc.size / 2 &&
	    sectors_to_move < reserve_sectors) {
		mutex_unlock(&ca->heap_lock);
		trace_bcache_moving_gc_no_work(ca);
		return false;
	}

	while (sectors_to_move > reserve_sectors) {
		BUG_ON(!heap_pop(&ca->heap, e, bucket_min_cmp));
		sectors_to_move -= e.val;
	}

	buckets_to_move = ca->heap.used;

	if (sectors_to_move)
		moved = true;

	/*
	 * resort by write_prio to group into generations, attempts to
	 * keep hot and cold data in the same locality.
	 */

	mutex_lock(&ca->set->bucket_lock);
	for (i = 0; i < ca->heap.used; i++) {
		struct bucket_heap_entry *e = &ca->heap.data[i];

		e->val = (c->prio_clock[WRITE].hand - e->g->write_prio);
	}

	heap_resort(&ca->heap, bucket_max_cmp);

	sectors_gen = sectors_to_move / NUM_GC_GENS;
	gen_current = 1;
	sectors_total = 0;

	while (heap_pop(&ca->heap, e, bucket_max_cmp)) {
		sectors_total += bucket_sectors_used(e.g);
		e.g->copygc_gen = gen_current;
		if (gen_current < NUM_GC_GENS &&
		    sectors_total >= sectors_gen * gen_current)
			gen_current++;
	}
	mutex_unlock(&ca->set->bucket_lock);

	mutex_unlock(&ca->heap_lock);

	read_moving(ca, &ctxt);

	trace_bcache_moving_gc_end(ca, ctxt.sectors_moved, ctxt.keys_moved,
				buckets_to_move);

	return moved;
}

static int bch_moving_gc_thread(void *arg)
{
	struct cache *ca = arg;
	struct cache_set *c = ca->set;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last;
	bool moved;

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->copy_gc_enabled))
			break;

		last = atomic_long_read(&clock->now);

		moved = bch_moving_gc(ca);

		/*
		 * This really should be a library code, but it has to be
		 * kthread specific... ugh
		 */
		if (!moved)
			bch_kthread_io_clock_wait(clock,
					last + ca->free_inc.size / 2);
	}

	return 0;
}

#define MOVING_GC_KEYS_MAX_SIZE	DFLT_SCAN_KEYLIST_MAX_SIZE
#define MOVING_GC_NR 64
#define MOVING_GC_READ_NR 32
#define MOVING_GC_WRITE_NR 32

void bch_moving_init_cache(struct cache *ca)
{
	bool rotational = !blk_queue_nonrot(bdev_get_queue(ca->disk_sb.bdev));

	bch_pd_controller_init(&ca->moving_gc_pd);
	bch_queue_init(&ca->moving_gc_queue,
		       ca->set,
		       MOVING_GC_KEYS_MAX_SIZE,
		       MOVING_GC_NR,
		       MOVING_GC_READ_NR,
		       MOVING_GC_WRITE_NR,
		       rotational);
	ca->moving_gc_pd.d_term = 0;
}

int bch_moving_gc_thread_start(struct cache *ca)
{
	struct task_struct *t;
	int ret;

	/* The moving gc read thread must be stopped */
	BUG_ON(ca->moving_gc_read != NULL);

	ret = bch_queue_start(&ca->moving_gc_queue,
			      "bch_copygc_write");
	if (ret)
		return ret;

	if (cache_set_init_fault("moving_gc_start"))
		return -ENOMEM;

	t = kthread_create(bch_moving_gc_thread, ca, "bch_copygc_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ca->moving_gc_read = t;
	wake_up_process(ca->moving_gc_read);

	return 0;
}

void bch_moving_gc_stop(struct cache *ca)
{
	bch_queue_stop(&ca->moving_gc_queue);
	ca->moving_gc_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&ca->moving_gc_pd.rate);
	if (ca->moving_gc_read)
		kthread_stop(ca->moving_gc_read);
	ca->moving_gc_read = NULL;
}

void bch_moving_gc_destroy(struct cache *ca)
{
	bch_queue_destroy(&ca->moving_gc_queue);
}
