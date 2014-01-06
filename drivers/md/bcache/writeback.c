/*
 * background writeback - scan btree for dirty data and write it to the backing
 * device
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "writeback.h"

#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <trace/events/bcache.h>

/* Rate limiting */

static void __update_writeback_rate(struct cached_dev *dc)
{
	struct cache_set *c = dc->disk.c;
	uint64_t cache_sectors = c->nbuckets * c->sb.bucket_size;
	uint64_t cache_dirty_target =
		div_u64(cache_sectors * dc->writeback_percent, 100);

	int64_t target = div64_u64(cache_dirty_target * bdev_sectors(dc->bdev),
				   c->cached_dev_sectors);

	/* PD controller */

	int64_t dirty = bcache_dev_sectors_dirty(&dc->disk);
	int64_t derivative = dirty - dc->disk.sectors_dirty_last;
	int64_t proportional = dirty - target;
	int64_t change;

	dc->disk.sectors_dirty_last = dirty;

	/* Scale to sectors per second */

	proportional *= dc->writeback_rate_update_seconds;
	proportional = div_s64(proportional, dc->writeback_rate_p_term_inverse);

	derivative = div_s64(derivative, dc->writeback_rate_update_seconds);

	derivative = ewma_add(dc->disk.sectors_dirty_derivative, derivative,
			      (dc->writeback_rate_d_term /
			       dc->writeback_rate_update_seconds) ?: 1, 0);

	derivative *= dc->writeback_rate_d_term;
	derivative = div_s64(derivative, dc->writeback_rate_p_term_inverse);

	change = proportional + derivative;

	/* Don't increase writeback rate if the device isn't keeping up */
	if (change > 0 &&
	    time_after64(local_clock(),
			 dc->writeback_rate.next + NSEC_PER_MSEC))
		change = 0;

	dc->writeback_rate.rate =
		clamp_t(int64_t, (int64_t) dc->writeback_rate.rate + change,
			1, NSEC_PER_MSEC);

	dc->writeback_rate_proportional = proportional;
	dc->writeback_rate_derivative = derivative;
	dc->writeback_rate_change = change;
	dc->writeback_rate_target = target;
}

static void update_writeback_rate(struct work_struct *work)
{
	struct cached_dev *dc = container_of(to_delayed_work(work),
					     struct cached_dev,
					     writeback_rate_update);

	down_read(&dc->writeback_lock);

	if (atomic_read(&dc->has_dirty) &&
	    dc->writeback_percent)
		__update_writeback_rate(dc);

	up_read(&dc->writeback_lock);

	schedule_delayed_work(&dc->writeback_rate_update,
			      dc->writeback_rate_update_seconds * HZ);
}

static unsigned writeback_delay(struct cached_dev *dc, unsigned sectors)
{
	if (atomic_read(&dc->disk.detaching) ||
	    !dc->writeback_percent)
		return 0;

	return bch_next_delay(&dc->writeback_rate, sectors);
}

struct dirty_io {
	struct closure		cl;
	struct cached_dev	*dc;
	struct bio		bio;
};

static void dirty_init(struct keybuf_key *w)
{
	struct dirty_io *io = w->private;
	struct bio *bio = &io->bio;

	bio_init(bio);
	if (!io->dc->writeback_percent)
		bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_size		= KEY_SIZE(&w->key) << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS);
	bio->bi_private		= w;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

static void dirty_io_destructor(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	kfree(io);
}

static void write_dirty_finish(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct keybuf_key *w = io->bio.bi_private;
	struct cached_dev *dc = io->dc;
	struct bio_vec *bv = bio_iovec_idx(&io->bio, io->bio.bi_vcnt);

	while (bv-- != io->bio.bi_io_vec)
		__free_page(bv->bv_page);

	/* This is kind of a dumb way of signalling errors. */
	if (KEY_DIRTY(&w->key)) {
		unsigned i;
		struct btree_op op;
		bch_btree_op_init_stack(&op);

		op.type = BTREE_REPLACE;
		bkey_copy(&op.replace, &w->key);

		SET_KEY_DIRTY(&w->key, false);
		bch_keylist_add(&op.keys, &w->key);

		for (i = 0; i < KEY_PTRS(&w->key); i++)
			atomic_inc(&PTR_BUCKET(dc->disk.c, &w->key, i)->pin);

		pr_debug("clearing %s", pkey(&w->key));
		bch_btree_insert(&op, dc->disk.c);
		closure_sync(&op.cl);

		atomic_long_inc(op.insert_collision
				? &dc->disk.c->writeback_keys_failed
				: &dc->disk.c->writeback_keys_done);
	}

	bch_keybuf_del(&dc->writeback_keys, w);
	up(&dc->in_flight);

	closure_return_with_destructor(cl, dirty_io_destructor);
}

static void dirty_endio(struct bio *bio, int error)
{
	struct keybuf_key *w = bio->bi_private;
	struct dirty_io *io = w->private;

	if (error)
		SET_KEY_DIRTY(&w->key, false);

	closure_put(&io->cl);
}

static void write_dirty(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct keybuf_key *w = io->bio.bi_private;

	dirty_init(w);
	io->bio.bi_rw		= WRITE;
	io->bio.bi_sector	= KEY_START(&w->key);
	io->bio.bi_bdev		= io->dc->bdev;
	io->bio.bi_end_io	= dirty_endio;

	trace_bcache_write_dirty(&io->bio);
	closure_bio_submit(&io->bio, cl, &io->dc->disk);

	continue_at(cl, write_dirty_finish, system_wq);
}

static void read_dirty_endio(struct bio *bio, int error)
{
	struct keybuf_key *w = bio->bi_private;
	struct dirty_io *io = w->private;

	bch_count_io_errors(PTR_CACHE(io->dc->disk.c, &w->key, 0),
			    error, "reading dirty data from cache");

	dirty_endio(bio, error);
}

static void read_dirty_submit(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);

	trace_bcache_read_dirty(&io->bio);
	closure_bio_submit(&io->bio, cl, &io->dc->disk);

	continue_at(cl, write_dirty, system_wq);
}

static void read_dirty(struct cached_dev *dc)
{
	unsigned delay = 0;
	struct keybuf_key *w;
	struct dirty_io *io;
	struct closure cl;

	closure_init_stack(&cl);

	/*
	 * XXX: if we error, background writeback just spins. Should use some
	 * mempools.
	 */

	while (!kthread_should_stop()) {
		try_to_freeze();

		w = bch_keybuf_next(&dc->writeback_keys);
		if (!w)
			break;

		BUG_ON(ptr_stale(dc->disk.c, &w->key, 0));

		if (KEY_START(&w->key) != dc->last_read ||
		    jiffies_to_msecs(delay) > 50)
			while (!kthread_should_stop() && delay)
				delay = schedule_timeout_interruptible(delay);

		dc->last_read	= KEY_OFFSET(&w->key);

		io = kzalloc(sizeof(struct dirty_io) + sizeof(struct bio_vec)
			     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
			     GFP_KERNEL);
		if (!io)
			goto err;

		w->private	= io;
		io->dc		= dc;

		dirty_init(w);
		io->bio.bi_sector	= PTR_OFFSET(&w->key, 0);
		io->bio.bi_bdev		= PTR_CACHE(dc->disk.c,
						    &w->key, 0)->bdev;
		io->bio.bi_rw		= READ;
		io->bio.bi_end_io	= read_dirty_endio;

		if (bch_bio_alloc_pages(&io->bio, GFP_KERNEL))
			goto err_free;

		pr_debug("%s", pkey(&w->key));

		down(&dc->in_flight);
		closure_call(&io->cl, read_dirty_submit, NULL, &cl);

		delay = writeback_delay(dc, KEY_SIZE(&w->key));
	}

	if (0) {
err_free:
		kfree(w->private);
err:
		bch_keybuf_del(&dc->writeback_keys, w);
	}

	/*
	 * Wait for outstanding writeback IOs to finish (and keybuf slots to be
	 * freed) before refilling again
	 */
	closure_sync(&cl);
}

/* Scan for dirty data */

void bcache_dev_sectors_dirty_add(struct cache_set *c, unsigned inode,
				  uint64_t offset, int nr_sectors)
{
	struct bcache_device *d = c->devices[inode];
	unsigned stripe_size, stripe_offset;
	uint64_t stripe;

	if (!d)
		return;

	stripe_size = 1 << d->stripe_size_bits;
	stripe = offset >> d->stripe_size_bits;
	stripe_offset = offset & (stripe_size - 1);

	while (nr_sectors) {
		int s = min_t(unsigned, abs(nr_sectors),
			      stripe_size - stripe_offset);

		if (nr_sectors < 0)
			s = -s;

		atomic_add(s, d->stripe_sectors_dirty + stripe);
		nr_sectors -= s;
		stripe_offset = 0;
		stripe++;
	}
}

static bool dirty_pred(struct keybuf *buf, struct bkey *k)
{
	return KEY_DIRTY(k);
}

static bool refill_dirty(struct cached_dev *dc)
{
	struct keybuf *buf = &dc->writeback_keys;
	bool searched_from_start = false;
	struct bkey end = KEY(dc->disk.id, MAX_KEY_OFFSET, 0);

	if (bkey_cmp(&buf->last_scanned, &end) >= 0) {
		buf->last_scanned = KEY(dc->disk.id, 0, 0);
		searched_from_start = true;
	}

	bch_refill_keybuf(dc->disk.c, buf, &end);

	return bkey_cmp(&buf->last_scanned, &end) >= 0 && searched_from_start;
}

static int bch_writeback_thread(void *arg)
{
	struct cached_dev *dc = arg;
	bool searched_full_index;

	while (!kthread_should_stop()) {
		down_write(&dc->writeback_lock);
		if (!atomic_read(&dc->has_dirty) ||
		    (!atomic_read(&dc->disk.detaching) &&
		     !dc->writeback_running)) {
			up_write(&dc->writeback_lock);
			set_current_state(TASK_INTERRUPTIBLE);

			if (kthread_should_stop())
				return 0;

			try_to_freeze();
			schedule();
			continue;
		}

		searched_full_index = refill_dirty(dc);

		if (searched_full_index &&
		    RB_EMPTY_ROOT(&dc->writeback_keys.keys)) {
			atomic_set(&dc->has_dirty, 0);
			cached_dev_put(dc);
			SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);
			bch_write_bdev_super(dc, NULL);
		}

		up_write(&dc->writeback_lock);

		bch_ratelimit_reset(&dc->writeback_rate);
		read_dirty(dc);

		if (searched_full_index) {
			unsigned delay = dc->writeback_delay * HZ;

			while (delay &&
			       !kthread_should_stop() &&
			       !atomic_read(&dc->disk.detaching))
				delay = schedule_timeout_interruptible(delay);
		}
	}

	return 0;
}

/* Init */

static int bch_btree_sectors_dirty_init(struct btree *b, struct btree_op *op,
					struct cached_dev *dc)
{
	struct bkey *k;
	struct btree_iter iter;

	bch_btree_iter_init(b, &iter, &KEY(dc->disk.id, 0, 0));
	while ((k = bch_btree_iter_next_filter(&iter, b, bch_ptr_bad)))
		if (!b->level) {
			if (KEY_INODE(k) > dc->disk.id)
				break;

			if (KEY_DIRTY(k))
				bcache_dev_sectors_dirty_add(b->c, dc->disk.id,
							     KEY_START(k),
							     KEY_SIZE(k));
		} else {
			btree(sectors_dirty_init, k, b, op, dc);
			if (KEY_INODE(k) > dc->disk.id)
				break;

			cond_resched();
		}

	return 0;
}

void bch_sectors_dirty_init(struct cached_dev *dc)
{
	struct btree_op op;

	bch_btree_op_init_stack(&op);
	btree_root(sectors_dirty_init, dc->disk.c, &op, dc);

	dc->disk.sectors_dirty_last = bcache_dev_sectors_dirty(&dc->disk);
}

int bch_cached_dev_writeback_init(struct cached_dev *dc)
{
	sema_init(&dc->in_flight, 64);
	init_rwsem(&dc->writeback_lock);

	bch_keybuf_init(&dc->writeback_keys, dirty_pred);

	dc->writeback_metadata		= true;
	dc->writeback_running		= true;
	dc->writeback_percent		= 10;
	dc->writeback_delay		= 30;
	dc->writeback_rate.rate		= 1024;

	dc->writeback_rate_update_seconds = 5;
	dc->writeback_rate_d_term	= 30;
	dc->writeback_rate_p_term_inverse = 6000;

	dc->writeback_thread = kthread_create(bch_writeback_thread, dc,
					      "bcache_writeback");
	if (IS_ERR(dc->writeback_thread))
		return PTR_ERR(dc->writeback_thread);

	set_task_state(dc->writeback_thread, TASK_INTERRUPTIBLE);

	INIT_DELAYED_WORK(&dc->writeback_rate_update, update_writeback_rate);
	schedule_delayed_work(&dc->writeback_rate_update,
			      dc->writeback_rate_update_seconds * HZ);

	return 0;
}
