#include "bcache.h"
#include "btree.h"
#include "debug.h"

static struct workqueue_struct *dirty_wq;

static void read_dirty(struct work_struct *);

struct dirty_io {
	struct closure		cl;
	struct cached_dev	*dc;
	struct bio		bio;
};

/* Background writeback */

static bool dirty_pred(struct keybuf *buf, struct bkey *k)
{
	return KEY_DIRTY(k);
}

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
	bio_map(bio, NULL);
}

static void refill_dirty(struct work_struct *work)
{
	struct cached_dev *dc = container_of(to_delayed_work(work),
					     struct cached_dev, refill_dirty);
	struct keybuf *buf = &dc->writeback_keys;
	bool searched_from_start = false;
	struct bkey end = MAX_KEY;
	SET_KEY_INODE(&end, dc->disk.id);

	if (!atomic_read(&dc->disk.detaching) &&
	    !dc->writeback_running)
		return;

	down_write(&dc->writeback_lock);

	if (!atomic_read(&dc->has_dirty)) {
		SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);
		bch_write_bdev_super(dc, NULL);
		up_write(&dc->writeback_lock);
		return;
	}

	if (bkey_cmp(&buf->last_scanned, &end) >= 0) {
		buf->last_scanned = KEY(dc->disk.id, 0, 0);
		searched_from_start = true;
	}

	bch_refill_keybuf(dc->disk.c, buf, &end);

	if (bkey_cmp(&buf->last_scanned, &end) >= 0 && searched_from_start) {
		/* Searched the entire btree - delay for awhile */
		queue_delayed_work(dirty_wq, &dc->refill_dirty,
				   dc->writeback_delay * HZ);

		if (RB_EMPTY_ROOT(&buf->keys)) {
			atomic_set(&dc->has_dirty, 0);
			cached_dev_put(dc);
		}
	}

	up_write(&dc->writeback_lock);

	dc->next_writeback_io = local_clock();

	read_dirty(&dc->read_dirty.work);
}

void bch_writeback_queue(struct cached_dev *dc)
{
	queue_delayed_work(dirty_wq, &dc->refill_dirty, 0);
}

void bch_writeback_add(struct cached_dev *dc, unsigned sectors)
{
	atomic_long_add(sectors, &dc->disk.sectors_dirty);

	if (!atomic_read(&dc->has_dirty) &&
	    !atomic_xchg(&dc->has_dirty, 1)) {
		if (BDEV_STATE(&dc->sb) != BDEV_STATE_DIRTY) {
			SET_BDEV_STATE(&dc->sb, BDEV_STATE_DIRTY);
			/* XXX: should do this synchronously */
			bch_write_bdev_super(dc, NULL);
		}

		atomic_inc(&dc->count);
		queue_delayed_work(dirty_wq, &dc->refill_dirty,
				   dc->writeback_delay * HZ);

		if (dc->writeback_percent)
			schedule_delayed_work(&dc->writeback_rate_update,
				      dc->writeback_rate_update_seconds * HZ);
	}
}

static void __update_writeback_rate(struct cached_dev *dc)
{
	struct cache_set *c = dc->disk.c;
	uint64_t cache_sectors = c->nbuckets * c->sb.bucket_size;
	uint64_t cache_dirty_target =
		div_u64(cache_sectors * dc->writeback_percent, 100);

	int64_t target = div64_u64(cache_dirty_target * bdev_sectors(dc->bdev),
				   c->cached_dev_sectors);

	/* PD controller */

	int change = 0;
	int64_t error;
	int64_t dirty = atomic_long_read(&dc->disk.sectors_dirty);
	int64_t derivative = dirty - dc->disk.sectors_dirty_last;

	dc->disk.sectors_dirty_last = dirty;

	derivative *= dc->writeback_rate_d_term;
	derivative = clamp(derivative, -dirty, dirty);

	derivative = ewma_add(dc->disk.sectors_dirty_derivative, derivative,
			      dc->writeback_rate_d_smooth, 0);

	/* Avoid divide by zero */
	if (!target)
		goto out;

	error = div64_s64((dirty + derivative - target) << 8, target);

	change = div_s64((dc->writeback_rate * error) >> 8,
			 dc->writeback_rate_p_term_inverse);

	/* Don't increase writeback rate if the device isn't keeping up */
	if (change > 0 &&
	    time_after64(local_clock(),
			 dc->next_writeback_io + 10 * NSEC_PER_MSEC))
		change = 0;

	dc->writeback_rate = clamp_t(int64_t, dc->writeback_rate + change,
				     1, NSEC_PER_MSEC);
out:
	dc->writeback_rate_derivative = derivative;
	dc->writeback_rate_change = change;
	dc->writeback_rate_target = target;

	schedule_delayed_work(&dc->writeback_rate_update,
			      dc->writeback_rate_update_seconds * HZ);
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
}

static unsigned writeback_delay(struct cached_dev *dc, unsigned sectors)
{
	uint64_t now = local_clock();

	if (atomic_read(&dc->disk.detaching) ||
	    !dc->writeback_percent)
		return 0;

	/* writeback_rate = sectors per 10 ms */
	dc->next_writeback_io += div_u64(sectors * 10000000ULL,
					 dc->writeback_rate);

	return time_after64(dc->next_writeback_io, now)
		? div_u64(dc->next_writeback_io - now, NSEC_PER_SEC / HZ)
		: 0;
}

/* Background writeback - IO loop */

static void write_dirty_finish(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct keybuf_key *w = io->bio.bi_private;
	struct cached_dev *dc = io->dc;
	struct bio_vec *bv = bio_iovec_idx(&io->bio, io->bio.bi_vcnt);

	while (bv-- != io->bio.bi_io_vec)
		__free_page(bv->bv_page);

	closure_debug_destroy(cl);
	kfree(io);

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
	atomic_dec_bug(&dc->in_flight);

	read_dirty(&dc->read_dirty.work);
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
	closure_bio_submit(&io->bio, cl);

	continue_at(cl, write_dirty_finish, dirty_wq);
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
	closure_bio_submit(&io->bio, cl);

	continue_at(cl, write_dirty, dirty_wq);
}

static void read_dirty(struct work_struct *work)
{
	struct cached_dev *dc = container_of(to_delayed_work(work),
					     struct cached_dev, read_dirty);
	unsigned delay = writeback_delay(dc, 0);
	struct keybuf_key *w;
	struct dirty_io *io;

	/* XXX: if we error, background writeback could stall indefinitely */

	while (1) {
		w = bch_keybuf_next(&dc->writeback_keys);
		if (!w)
			break;

		BUG_ON(ptr_stale(dc->disk.c, &w->key, 0));

		if (delay > 0 &&
		    (KEY_START(&w->key) != dc->last_read ||
		     jiffies_to_msecs(delay) > 50)) {
			w->private = NULL;
			queue_delayed_work(dirty_wq, &dc->read_dirty, delay);
			return;
		}

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

		if (bio_alloc_pages(&io->bio, GFP_KERNEL))
			goto err_free;

		pr_debug("%s", pkey(&w->key));

		closure_call(read_dirty_submit, &io->cl, NULL);

		delay = writeback_delay(dc, KEY_SIZE(&w->key));

		if (atomic_inc_return(&dc->in_flight) >= 64)
			return;
	}

	if (0) {
err_free:
		kfree(w->private);
err:
		bch_keybuf_del(&dc->writeback_keys, w);
	}

	if (RB_EMPTY_ROOT(&dc->writeback_keys.keys))
		queue_delayed_work(dirty_wq, &dc->refill_dirty, 0);
}

void bch_writeback_init_cached_dev(struct cached_dev *dc)
{
	INIT_DELAYED_WORK(&dc->refill_dirty, refill_dirty);
	INIT_DELAYED_WORK(&dc->read_dirty, read_dirty);
	init_rwsem(&dc->writeback_lock);

	bch_keybuf_init(&dc->writeback_keys, dirty_pred);

	dc->writeback_metadata		= true;
	dc->writeback_running		= true;
	dc->writeback_delay		= 30;
	dc->writeback_rate		= 1024;

	dc->writeback_rate_update_seconds = 30;
	dc->writeback_rate_d_term	= 16;
	dc->writeback_rate_p_term_inverse = 64;
	dc->writeback_rate_d_smooth	= 8;

	INIT_DELAYED_WORK(&dc->writeback_rate_update, update_writeback_rate);
	schedule_delayed_work(&dc->writeback_rate_update,
			      dc->writeback_rate_update_seconds * HZ);
}

void bch_writeback_exit(void)
{
	if (dirty_wq)
		destroy_workqueue(dirty_wq);
}

int __init bch_writeback_init(void)
{
	dirty_wq = create_singlethread_workqueue("bcache_writeback");
	if (!dirty_wq)
		return -ENOMEM;

	return 0;
}
