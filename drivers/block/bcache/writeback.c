#include "bcache.h"
#include "btree.h"
#include "debug.h"

static struct workqueue_struct *dirty_wq;

static void read_dirty(struct cached_dev *);

/* Background writeback */

static void dirty_init(struct dirty *w)
{
	struct bio *bio = &w->io->bio;

	bio_init(bio);
	bio_get(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_size		= KEY_SIZE(&w->key) << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS);
	bio->bi_private		= w;
	bio_map(bio, NULL);
}

static int dirty_cmp(struct dirty *r, struct dirty *l)
{
	/* Overlapping keys must compare equal */
	if (KEY_START(&r->key) >= l->key.key)
		return 1;
	if (KEY_START(&l->key) >= r->key.key)
		return -1;
	return 0;
}

static int btree_refill_dirty_leaf(struct btree *b, struct btree_op *op,
				   struct cached_dev *dc)
{
	struct dirty *w;
	struct btree_iter iter;
	btree_iter_init(b, &iter, &KEY(op->d->id, dc->last_found, 0));

	/* To protect rb tree access vs. read_dirty() */
	spin_lock(&dc->dirty_lock);

	while (!array_freelist_empty(&dc->dirty_freelist)) {
		struct bkey *k = btree_iter_next(&iter);
		if (!k || KEY_DEV(k) != op->d->id)
			break;

		if (ptr_bad(b, k))
			continue;

		if (KEY_DIRTY(k)) {
			w = array_alloc(&dc->dirty_freelist);

			dc->last_found = k->key;
			pr_debug("%s", pkey(k));
			w->io = NULL;
			bkey_copy(&w->key, k);
			SET_KEY_DIRTY(&w->key, false);

			if (RB_INSERT(&dc->dirty, w, node, dirty_cmp))
				array_free(&dc->dirty_freelist, w);
		}
	}

	spin_unlock(&dc->dirty_lock);

	return 0;
}

static int btree_refill_dirty(struct btree *b, struct btree_op *op,
			      struct cached_dev *dc)
{
	int r;
	struct btree_iter iter;
	btree_iter_init(b, &iter, &KEY(op->d->id, dc->last_found, 0));

	if (!b->level)
		return btree_refill_dirty_leaf(b, op, dc);

	while (!array_freelist_empty(&dc->dirty_freelist)) {
		struct bkey *k = btree_iter_next(&iter);
		if (!k)
			break;

		if (ptr_bad(b, k))
			continue;

		r = btree(refill_dirty, k, b, op, dc);
		if (r) {
			char buf[BDEVNAME_SIZE];
			bdevname(dc->bdev, buf);

			printk(KERN_WARNING "Error trying to read the btree "
			       "for background writeback on %s: "
			       "dirty data may have been lost!\n", buf);
		}

		if (KEY_DEV(k) != op->d->id)
			break;

		cond_resched();
	}

	return 0;
}

static void refill_dirty(struct work_struct *work)
{
	struct cached_dev *dc = container_of(to_delayed_work(work),
					     struct cached_dev, refill_dirty);
	uint64_t start;

	struct btree_op op;
	btree_op_init_stack(&op);
	op.d = &dc->disk;

	if (!atomic_read(&dc->closing) &&
	    (!dc->writeback_running ||
	     dc->disk.c->gc_stats.in_use < dc->writeback_percent))
		return;

	down_write(&dc->writeback_lock);
	start = dc->last_found;

	if (!atomic_read(&dc->has_dirty)) {
		SET_BDEV_STATE(&dc->sb, BDEV_STATE_CLEAN);
		write_bdev_super(dc, NULL);
		up_write(&dc->writeback_lock);
		return;
	}

	btree_root(refill_dirty, dc->disk.c, &op, dc);
	closure_sync(&op.cl);

	pr_debug("found %s keys on %i from %llu to %llu, %i%% used",
		 RB_EMPTY_ROOT(&dc->dirty) ? "no" :
		 array_freelist_empty(&dc->dirty_freelist) ? "some" : "a few",
		 dc->disk.id, start, (uint64_t) dc->last_found,
		 dc->disk.c->gc_stats.in_use);

	/* Got to the end of the btree */
	if (!array_freelist_empty(&dc->dirty_freelist))
		dc->last_found = 0;

	/* Searched the entire btree - delay for awhile */
	if (!array_freelist_empty(&dc->dirty_freelist) && !start)
		queue_delayed_work(dirty_wq, &dc->refill_dirty,
				   dc->writeback_delay * HZ);

	spin_lock(&dc->dirty_lock);

	if (!RB_EMPTY_ROOT(&dc->dirty)) {
		struct dirty *w;
		w = RB_FIRST(&dc->dirty, struct dirty, node);
		dc->writeback_start	= KEY_START(&w->key);

		w = RB_LAST(&dc->dirty, struct dirty, node);
		dc->writeback_end	= w->key.key;
	} else {
		dc->writeback_start	= 0;
		dc->writeback_end	= 0;

		if (!start) {
			atomic_set(&dc->has_dirty, 0);
			cached_dev_put(dc);
		}
	}

	up_write(&dc->writeback_lock);
	read_dirty(dc);
}

bool bcache_in_writeback(struct cached_dev *dc, sector_t offset, unsigned len)
{
	struct dirty *w, s;
	s.key = KEY(dc->disk.id, offset + len, len);

	if (offset	 >= dc->writeback_end ||
	    offset + len <= dc->writeback_start)
		return false;

	spin_lock(&dc->dirty_lock);
	w = RB_SEARCH(&dc->dirty, s, node, dirty_cmp);
	if (w && !w->io) {
		rb_erase(&w->node, &dc->dirty);
		array_free(&dc->dirty_freelist, w);
		w = NULL;
	}

	spin_unlock(&dc->dirty_lock);
	return w != NULL;
}

void bcache_writeback_queue(struct cached_dev *d)
{
	queue_delayed_work(dirty_wq, &d->refill_dirty, 0);
}

void bcache_writeback_add(struct cached_dev *d, unsigned sectors)
{
	atomic_long_add(sectors, &d->disk.sectors_dirty);

	if (!atomic_read(&d->has_dirty) &&
	    !atomic_xchg(&d->has_dirty, 1)) {
		if (BDEV_STATE(&d->sb) != BDEV_STATE_DIRTY) {
			SET_BDEV_STATE(&d->sb, BDEV_STATE_DIRTY);
			/* XXX: should do this synchronously */
			write_bdev_super(d, NULL);
		}

		atomic_inc(&d->count);
		queue_delayed_work(dirty_wq, &d->refill_dirty,
				   d->writeback_delay * HZ);
	}
}

static void write_dirty_finish(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct dirty *w = io->bio.bi_private;
	struct cached_dev *dc = io->d;
	struct bio_vec *bv = bio_iovec_idx(&io->bio, io->bio.bi_vcnt);

	while (bv-- != w->io->bio.bi_io_vec)
		__free_page(bv->bv_page);

	closure_debug_destroy(cl);
	kfree(io);

	if (!KEY_DIRTY(&w->key)) {
		struct btree_op op;
		btree_op_init_stack(&op);

		op.insert_type = INSERT_UNDIRTY;
		keylist_add(&op.keys, &w->key);

		pr_debug("clearing %s", pkey(&w->key));
		bcache_btree_insert(&op, dc->disk.c);
		closure_sync(&op.cl);
	}

	spin_lock(&dc->dirty_lock);
	rb_erase(&w->node, &dc->dirty);
	array_free(&dc->dirty_freelist, w);
	atomic_dec_bug(&dc->in_flight);

	read_dirty(dc);
}

static void dirty_endio(struct bio *bio, int error)
{
	struct dirty *w = bio->bi_private;

	if (error)
		SET_KEY_DIRTY(&w->key, true);

	bio_put(bio);
	closure_put(&w->io->cl);
}

static void write_dirty(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct dirty *w = io->bio.bi_private;

	dirty_init(w);
	set_closure_fn(&io->cl, write_dirty_finish, dirty_wq);
	io->bio.bi_rw		= WRITE|REQ_UNPLUG;
	io->bio.bi_sector	= KEY_START(&w->key);
	io->bio.bi_bdev		= io->d->bdev;
	io->bio.bi_end_io	= dirty_endio;

	trace_bcache_write_dirty(&w->io->bio);
	closure_bio_submit(&w->io->bio, cl, io->d->disk.bio_split);
}

static void read_dirty_endio(struct bio *bio, int error)
{
	struct dirty *w = bio->bi_private;

	count_io_errors(PTR_CACHE(w->io->d->disk.c, &w->key, 0),
			error, "reading dirty data from cache");

	dirty_endio(bio, error);
}

static void read_dirty(struct cached_dev *dc)
{
	struct dirty *w;
	struct dirty_io *io;

	/* XXX: if we error, background writeback could stall indefinitely */

	while (1) {
		w = RB_FIRST(&dc->dirty, struct dirty, node);

		while (w && w->io)
			w = RB_NEXT(w, node);

		if (!w)
			break;

		BUG_ON(ptr_stale(dc->disk.c, &w->key, 0));

		dc->last_read	= w->key.key;
		w->io		= ERR_PTR(-EINTR);
		spin_unlock(&dc->dirty_lock);

		io = kzalloc(sizeof(struct dirty_io) + sizeof(struct bio_vec)
			     * DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
			     GFP_KERNEL);
		if (!io)
			goto err;

		w->io = io;
		closure_init(&w->io->cl, NULL);
		set_closure_fn(&w->io->cl, write_dirty, dirty_wq);
		w->io->d		= dc;

		dirty_init(w);
		w->io->bio.bi_sector	= PTR_OFFSET(&w->key, 0);
		w->io->bio.bi_bdev	= PTR_CACHE(dc->disk.c,
						    &w->key, 0)->bdev;
		w->io->bio.bi_rw	= READ|REQ_UNPLUG;
		w->io->bio.bi_end_io	= read_dirty_endio;

		if (bio_alloc_pages(&w->io->bio, GFP_KERNEL))
			goto err;

		pr_debug("%s", pkey(&w->key));

		trace_bcache_read_dirty(&w->io->bio);
		closure_bio_submit(&w->io->bio, &w->io->cl, dc->disk.bio_split);
		if (atomic_inc_return(&dc->in_flight) >= 8)
			return;

		spin_lock(&dc->dirty_lock);
	}

	if (0) {
err:		spin_lock(&dc->dirty_lock);
		if (!IS_ERR_OR_NULL(w->io))
			kfree(w->io);
		rb_erase(&w->node, &dc->dirty);
		array_free(&dc->dirty_freelist, w);
	}

	if (RB_EMPTY_ROOT(&dc->dirty))
		queue_delayed_work(dirty_wq, &dc->refill_dirty, 0);

	spin_unlock(&dc->dirty_lock);
}

static void read_dirty_work(struct work_struct *work)
{
	struct cached_dev *dc = container_of(to_delayed_work(work),
					     struct cached_dev, read_dirty);

	spin_lock(&dc->dirty_lock);
	read_dirty(dc);
}

void bcache_writeback_init_cached_dev(struct cached_dev *d)
{
	INIT_DELAYED_WORK(&d->refill_dirty, refill_dirty);
	INIT_DELAYED_WORK(&d->read_dirty, read_dirty_work);
	init_rwsem(&d->writeback_lock);
	array_allocator_init(&d->dirty_freelist);

	d->dirty			= RB_ROOT;
	d->writeback_metadata		= true;
	d->writeback_running		= true;
	d->writeback_delay		= 30;
}

void bcache_writeback_exit(void)
{
	if (dirty_wq)
		destroy_workqueue(dirty_wq);
}

int __init bcache_writeback_init(void)
{
	dirty_wq = create_singlethread_workqueue("bcache_writeback");
	if (!dirty_wq)
		return -ENOMEM;

	return 0;
}
