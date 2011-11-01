
#include "bcache.h"
#include "btree.h"

struct dirty_io {
	struct closure		cl;
	struct cached_dev	*d;
	struct bio		bio;
};

struct dirty {
	struct rb_node		node;
	BKEY_PADDED(key);
	struct dirty_io		*io;
};

static struct kmem_cache *dirty_cache;
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

#define WRITEBACK_SLURP	100

static int btree_refill_dirty(struct btree *b, struct btree_op *op, int *count)
{
	struct dirty *w;
	struct btree_iter iter;
	btree_iter_init(b, &iter, &KEY(op->d->id, op->d->last_found, 0));

	/* To protect rb tree access vs. read_dirty() */
	if (!b->level)
		spin_lock(&op->d->lock);

	while (*count < WRITEBACK_SLURP) {
		struct bkey *k = btree_iter_next(&iter);
		if (!k || KEY_DEV(k) != op->d->id)
			break;

		if (ptr_bad(b, k))
			continue;

		if (b->level) {
			int ret = btree(refill_dirty, k, b, op, count);
			if (ret)
				return ret;

		} else if (KEY_DIRTY(k)) {
			w = kmem_cache_alloc(dirty_cache, GFP_NOWAIT);
			if (!w) {
				spin_unlock(&op->d->lock);

				w = kmem_cache_alloc(dirty_cache, GFP_NOIO);
				if (!w)
					return -ENOMEM;

				spin_lock(&op->d->lock);
			}

			op->d->last_found = k->key;
			pr_debug("%s", pkey(k));
			w->io = NULL;
			bkey_copy(&w->key, k);
			SET_KEY_DIRTY(&w->key, false);

			if (RB_INSERT(&op->d->dirty, w, node, dirty_cmp))
				kmem_cache_free(dirty_cache, w);
			else
				(*count)++;
		}
	}

	if (!b->level)
		spin_unlock(&op->d->lock);

	return 0;
}

static bool refill_dirty(struct cached_dev *d)
{
	bool put = false;
	int r, count = 0;
	uint64_t l;

	struct btree_op op;
	btree_op_init_stack(&op);
	op.d = d;

	down_write(&d->writeback_lock);
again:
	l = d->last_found;
	r = btree_root(refill_dirty, d->c, &op, &count);

	pr_debug("found %i keys on %i from %llu to %llu, %i%% used",
		 count, d->id, l, d->last_found, d->c->gc_stats.in_use);

	if (!r && count < WRITEBACK_SLURP) {
		/* Got to the end of the btree */
		d->last_found = 0;

		if (l)
			goto again;

		/* Scanned the whole thing */
		if (!count && !atomic_read(&d->in_flight)) {
			if (!d->writeback &&
			    BDEV_STATE(&d->sb) == BDEV_STATE_DIRTY) {
				SET_BDEV_STATE(&d->sb, BDEV_STATE_CLEAN);
				write_bdev_super(d, NULL);
			}

			atomic_long_set(&d->last_refilled, 0);
			put = true;
		} else
			atomic_long_set(&d->last_refilled, jiffies ?: 1);
	}

	if (!RB_EMPTY_ROOT(&d->dirty)) {
		struct dirty *w;
		w = RB_FIRST(&d->dirty, struct dirty, node);
		d->writeback_start	= KEY_START(&w->key);

		w = RB_LAST(&d->dirty, struct dirty, node);
		d->writeback_end	= w->key.key;
	} else {
		d->writeback_start	= 0;
		d->writeback_end	= 0;
	}

	up_write(&d->writeback_lock);
	closure_sync(&op.cl);

	if (put)
		cached_dev_put(d);

	return count;
}

bool in_writeback(struct cached_dev *d, sector_t offset, unsigned len)
{
	struct dirty *ret, s;
	s.key = KEY(d->id, offset + len, len);

	if (offset >= d->writeback_end ||
	    offset + len <= d->writeback_start)
		return false;

	spin_lock(&d->lock);
	ret = RB_SEARCH(&d->dirty, s, node, dirty_cmp);
	if (ret && !ret->io) {
		rb_erase(&ret->node, &d->dirty);
		kmem_cache_free(dirty_cache, ret);
		ret = NULL;
	}

	spin_unlock(&d->lock);
	return ret;
}

static bool should_refill_dirty(struct cached_dev *d)
{
	long t = atomic_long_read(&d->last_refilled);
	unsigned ms = d->writeback_delay * 1000;

	return t &&
		((d->writeback_running &&
		  ((jiffies_to_msecs(jiffies - t) > ms &&
		    d->c->gc_stats.in_use > d->writeback_percent) ||
		   !d->writeback)) ||
		 atomic_read(&d->closing));
}

void queue_writeback(struct cached_dev *d)
{
	if (should_refill_dirty(d))
		queue_work(dirty_wq, &d->refill);
}

static void write_dirty_finish(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct dirty *w = io->bio.bi_private;
	struct cached_dev *d = io->d;
	struct bio_vec *bv = bio_iovec_idx(&io->bio, io->bio.bi_vcnt);

	while (bv-- != w->io->bio.bi_io_vec)
		__free_page(bv->bv_page);

	closure_del(cl);
	kfree(io);

	if (!KEY_DIRTY(&w->key)) {
		struct btree_op op;
		btree_op_init_stack(&op);

		op.insert_type = INSERT_UNDIRTY;
		keylist_add(&op.keys, &w->key);

		pr_debug("clearing %s", pkey(&w->key));
		btree_insert(&op, d->c);
		closure_sync(&op.cl);
	}

	spin_lock(&d->lock);
	rb_erase(&w->node, &d->dirty);
	kmem_cache_free(dirty_cache, w);
	atomic_dec_bug(&d->in_flight);

	read_dirty(d);
}

static void dirty_endio(struct bio *bio, int error)
{
	struct dirty *w = bio->bi_private;

	if (error)
		SET_KEY_DIRTY(&w->key, true);

	bio_put(bio);
	closure_put(&w->io->cl, dirty_wq);
}

static void write_dirty(struct closure *cl)
{
	struct dirty_io *io = container_of(cl, struct dirty_io, cl);
	struct dirty *w = io->bio.bi_private;

	dirty_init(w);
	io->cl.fn		= write_dirty_finish;
	io->bio.bi_rw		= WRITE|REQ_UNPLUG;
	io->bio.bi_sector	= KEY_START(&w->key);
	io->bio.bi_bdev		= io->d->bdev;
	io->bio.bi_end_io	= dirty_endio;

	closure_bio_submit(&w->io->bio, cl, io->d->c->bio_split);
}

static void read_dirty_endio(struct bio *bio, int error)
{
	struct dirty *w = bio->bi_private;

	count_io_errors(PTR_CACHE(w->io->d->c, &w->key, 0),
			error, "reading dirty data from cache");

	dirty_endio(bio, error);
}

static void read_dirty(struct cached_dev *d)
{
	while (d->writeback_running) {
		struct dirty *w, s;
		s.key = KEY(d->id, d->last_read, 0);

		w = RB_GREATER(&d->dirty, s, node, dirty_cmp) ?:
		    RB_FIRST(&d->dirty, struct dirty, node);

		if (!w || w->io) {
			spin_unlock(&d->lock);

			if (should_refill_dirty(d) &&
			    refill_dirty(d)) {
				spin_lock(&d->lock);
				continue;
			}

			return;
		}

		if (ptr_stale(d->c, &w->key, 0)) {
			rb_erase(&w->node, &d->dirty);
			kmem_cache_free(dirty_cache, w);
			continue;
		}

		w->io = ERR_PTR(-EINTR);
		spin_unlock(&d->lock);

		w->io = kzalloc(sizeof(struct dirty_io) + sizeof(struct bio_vec)
				* DIV_ROUND_UP(KEY_SIZE(&w->key), PAGE_SECTORS),
				GFP_KERNEL);
		if (!w->io)
			return;

		closure_init(&w->io->cl, NULL);
		w->io->cl.fn		= write_dirty;
		w->io->d		= d;

		dirty_init(w);
		w->io->bio.bi_sector	= PTR_OFFSET(&w->key, 0);
		w->io->bio.bi_bdev	= PTR_CACHE(d->c, &w->key, 0)->bdev;
		w->io->bio.bi_rw	= READ|REQ_UNPLUG;
		w->io->bio.bi_end_io	= read_dirty_endio;

		if (bio_alloc_pages(&w->io->bio, GFP_KERNEL)) {
			kfree(w->io);
			w->io = NULL;
			return;
		}

		d->last_read = w->key.key;
		pr_debug("%s", pkey(&w->key));

		closure_bio_submit(&w->io->bio, &w->io->cl, d->c->bio_split);
		if (atomic_inc_return(&d->in_flight) >= 8)
			return;

		spin_lock(&d->lock);
	}

	spin_unlock(&d->lock);
}

static void read_dirty_work(struct work_struct *work)
{
	struct cached_dev *d = container_of(work, struct cached_dev, refill);
	spin_lock(&d->lock);
	read_dirty(d);
}

void bcache_writeback_init_cached_dev(struct cached_dev *d)
{
	INIT_WORK(&d->refill, read_dirty_work);
	init_rwsem(&d->writeback_lock);

	d->dirty			= RB_ROOT;
	d->writeback_running		= true;
	d->writeback_delay		= 30;
}

void bcache_writeback_exit(void)
{
	if (dirty_wq)
		destroy_workqueue(dirty_wq);
	if (dirty_cache)
		kmem_cache_destroy(dirty_cache);
}

int __init bcache_writeback_init(void)
{
	if (!(dirty_cache = KMEM_CACHE(dirty, 0)) ||
	    !(dirty_wq = create_singlethread_workqueue("dirty_wq"))) {
		bcache_writeback_exit();
		return -ENOMEM;
	} else
		return 0;
}
