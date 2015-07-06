/*
 * Handle a read or a write request and decide what to do with it.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 *
 * Main pieces here:
 *
 * 1) Data insert path, via bch_data_insert() -- writes data to cache and
 *    updates extents btree
 * 2) Read path, via bch_read() -- for now only used by bcachefs and ioctl
 *    interface
 * 3) Read path, via cache_lookup() and struct search -- used by block device
 *    make_request functions
 * 4) Cache promotion -- used by bch_read() and cache_lookup() to copy data to
 *    the cache, either from a backing device or a cache device in a higher tier
 *
 * One tricky thing that comes up is a race condition where a bucket may be
 * re-used while reads from it are still in flight. To guard against this, we
 * save the ptr that is being read and check if it is stale once the read
 * completes. If the ptr is stale, the read is retried.
 *
 * #2 and #3 will be unified further in the future.
 */

#include "bcache.h"
#include "blockdev.h"
#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "keybuf.h"
#include "request.h"
#include "writeback.h"
#include "stats.h"

#include <linux/module.h>
#include <linux/hash.h>
#include <linux/random.h>

#include <trace/events/bcache.h>

#define CUTOFF_CACHE_ADD	10
#define CUTOFF_CACHE_READA	15

/* Congested? */

unsigned bch_get_congested(struct cache_set *c)
{
	int i;
	long rand;

	if (!c->congested_read_threshold_us &&
	    !c->congested_write_threshold_us)
		return 0;

	i = (local_clock_us() - c->congested_last_us) / 1024;
	if (i < 0)
		return 0;

	i += atomic_read(&c->congested);
	if (i >= 0)
		return 0;

	i += CONGESTED_MAX;

	if (i > 0)
		i = fract_exp_two(i, 6);

	rand = get_random_int();
	i -= bitmap_weight(&rand, BITS_PER_LONG);

	return i > 0 ? i : 1;
}

static void add_sequential(struct task_struct *t)
{
	t->sequential_io_avg = ewma_add(t->sequential_io_avg,
					t->sequential_io, 3);
	t->sequential_io = 0;
}

static struct hlist_head *iohash(struct cached_dev *dc, uint64_t k)
{
	return &dc->io_hash[hash_64(k, RECENT_IO_BITS)];
}

static bool check_should_bypass(struct cached_dev *dc, struct bio *bio, int rw)
{
	struct cache_set *c = dc->disk.c;
	unsigned mode = BDEV_CACHE_MODE(&dc->sb);
	unsigned sectors, congested = bch_get_congested(c);
	struct task_struct *task = current;
	struct io *i;

	if (test_bit(BCACHE_DEV_DETACHING, &dc->disk.flags) ||
	    sectors_available(c) * 100 < c->capacity * CUTOFF_CACHE_ADD ||
	    (bio->bi_rw & REQ_DISCARD))
		goto skip;

	if (mode == CACHE_MODE_NONE ||
	    (mode == CACHE_MODE_WRITEAROUND &&
	     (bio->bi_rw & REQ_WRITE)))
		goto skip;

	if (bio->bi_iter.bi_sector & (c->sb.block_size - 1) ||
	    bio_sectors(bio) & (c->sb.block_size - 1)) {
		pr_debug("skipping unaligned io");
		goto skip;
	}

	if (bypass_torture_test(dc)) {
		if ((get_random_int() & 3) == 3)
			goto skip;
		else
			goto rescale;
	}

	if (!congested && !dc->sequential_cutoff)
		goto rescale;

	if (!congested &&
	    mode == CACHE_MODE_WRITEBACK &&
	    (bio->bi_rw & REQ_WRITE) &&
	    (bio->bi_rw & REQ_SYNC))
		goto rescale;

	spin_lock(&dc->io_lock);

	hlist_for_each_entry(i, iohash(dc, bio->bi_iter.bi_sector), hash)
		if (i->last == bio->bi_iter.bi_sector &&
		    time_before(jiffies, i->jiffies))
			goto found;

	i = list_first_entry(&dc->io_lru, struct io, lru);

	add_sequential(task);
	i->sequential = 0;
found:
	if (i->sequential + bio->bi_iter.bi_size > i->sequential)
		i->sequential	+= bio->bi_iter.bi_size;

	i->last			 = bio_end_sector(bio);
	i->jiffies		 = jiffies + msecs_to_jiffies(5000);
	task->sequential_io	 = i->sequential;

	hlist_del(&i->hash);
	hlist_add_head(&i->hash, iohash(dc, i->last));
	list_move_tail(&i->lru, &dc->io_lru);

	spin_unlock(&dc->io_lock);

	sectors = max(task->sequential_io,
		      task->sequential_io_avg) >> 9;

	if (dc->sequential_cutoff &&
	    sectors >= dc->sequential_cutoff >> 9) {
		trace_bcache_bypass_sequential(bio);
		goto skip;
	}

	if (congested && sectors >= congested) {
		trace_bcache_bypass_congested(bio);
		goto skip;
	}

rescale:
	return false;
skip:
	bch_mark_sectors_bypassed(c, dc, bio_sectors(bio));
	return true;
}

/* Common code for the make_request functions */

/**
 * request_endio - endio function for backing device bios
 */
static void request_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;

	if (error) {
		struct search *s = container_of(cl, struct search, cl);
		s->iop.error = error;
		/* Only cache read errors are recoverable */
		s->recoverable = false;
	}

	bio_put(bio);
	closure_put(cl);
}

static void bio_complete(struct search *s)
{
	if (s->orig_bio) {
		generic_end_io_acct(bio_data_dir(s->orig_bio),
				    &s->d->disk->part0, s->start_time);

		trace_bcache_request_end(s->d, s->orig_bio);
		bio_endio(s->orig_bio, s->iop.error);
		s->orig_bio = NULL;
	}
}

static void do_bio_hook(struct search *s, struct bio *orig_bio)
{
	struct bio *bio = &s->bio.bio;

	bio_init(bio);
	__bio_clone_fast(bio, orig_bio);
	bio->bi_end_io		= request_endio;
	bio->bi_private		= &s->cl;

	atomic_set(&bio->bi_cnt, 3);
}

static void search_free(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	bio_complete(s);

	if (s->iop.bio)
		bio_put(s->iop.bio);

	closure_debug_destroy(cl);
	mempool_free(s, s->d->c->search);
}

static inline struct search *search_alloc(struct bio *bio,
					  struct bcache_device *d)
{
	struct search *s;

	s = mempool_alloc(d->c->search, GFP_NOIO);

	closure_init(&s->cl, NULL);
	do_bio_hook(s, bio);

	s->orig_bio		= bio;
	s->d			= d;
	s->recoverable		= 1;
	s->bypass		= 0;
	s->write		= (bio->bi_rw & REQ_WRITE) != 0;
	s->read_dirty_data	= 0;
	s->cache_miss		= 0;
	s->start_time		= jiffies;
	s->inode		= bcache_dev_inum(d);

	s->iop.c		= d->c;
	s->iop.bio		= NULL;
	s->iop.error		= 0;

	return s;
}

/* Cached devices */

static void cached_dev_bio_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	search_free(cl);
	cached_dev_put(dc);
}

/* Process reads */

static void cached_dev_read_error(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio *bio = &s->bio.bio;

	if (s->recoverable) {
		/* Read bucket invalidate races are handled here, also plain
		 * old IO errors from the cache that can be retried from the
		 * backing device (reads of clean data) */
		trace_bcache_read_retry(s->orig_bio);

		s->iop.error = 0;
		do_bio_hook(s, s->orig_bio);

		/* XXX: invalidate cache, don't count twice */

		closure_bio_submit(bio, cl);
	}

	continue_at(cl, cached_dev_bio_complete, NULL);
}

static void cached_dev_read_done(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	if (dc->verify && s->recoverable && !s->read_dirty_data)
		bch_data_verify(dc, s->orig_bio);

	continue_at_nobarrier(cl, cached_dev_bio_complete, NULL);
}

static void cached_dev_read_done_bh(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	bch_mark_cache_accounting(s->iop.c, dc, !s->cache_miss, s->bypass);
	trace_bcache_read(s->orig_bio, !s->cache_miss, s->bypass);

	if (s->iop.error)
		continue_at_nobarrier(cl, cached_dev_read_error, s->iop.c->wq);
	else if (dc->verify)
		continue_at_nobarrier(cl, cached_dev_read_done, s->iop.c->wq);
	else
		continue_at_nobarrier(cl, cached_dev_bio_complete, NULL);
}

/**
 * cached_dev_cache_miss - populate cache with data from backing device
 *
 * We don't write to the cache if s->bypass is set.
 */
static int cached_dev_cache_miss(struct btree_iter *iter, struct search *s,
				 struct bio *bio, unsigned sectors)
{
	int ret;
	unsigned reada = 0;
	struct bio *miss;
	BKEY_PADDED(key) replace;

	s->cache_miss = 1;

	if (s->bypass)
		goto nopromote;
#if 0
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	/* XXX: broken */
	if (!(bio->bi_rw & REQ_RAHEAD) &&
	    !(bio->bi_rw & REQ_META) &&
	    ((u64) sectors_available(dc->disk.c) * 100 <
	     (u64) b->c->capacity * CUTOFF_CACHE_READA))
		reada = min_t(sector_t, dc->readahead >> 9,
			      bdev_sectors(bio->bi_bdev) - bio_end_sector(bio));
#endif
	sectors = min(sectors, bio_sectors(bio) + reada);

	replace.key = KEY(s->inode, bio->bi_iter.bi_sector + sectors, sectors);

	ret = bch_btree_insert_check_key(iter, &replace.key);
	if (ret == -EINTR || ret == -EAGAIN)
		return ret;

	miss = bio_next_split(bio, sectors, GFP_NOIO, s->d->bio_split);

	miss->bi_end_io		= request_endio;
	miss->bi_private	= &s->cl;

	to_bbio(miss)->key = KEY(s->inode,
				 bio_end_sector(miss),
				 bio_sectors(miss));
	to_bbio(miss)->ca = NULL;

	closure_get(&s->cl);
	__cache_promote(s->iop.c, to_bbio(miss),
			&replace.key,
			&KEY(replace.key.p.inode,
			     replace.key.p.offset,
			     replace.key.size),
			BCH_WRITE_ALLOC_NOWAIT|BCH_WRITE_CACHED);

	return 0;
nopromote:
	miss = bio_next_split(bio, sectors, GFP_NOIO, s->d->bio_split);

	miss->bi_end_io		= request_endio;
	miss->bi_private	= &s->cl;
	closure_bio_submit(miss, &s->cl);

	return 0;
}

static void bch_cache_read_endio(struct bio *bio, int error)
{
	struct bbio *b = to_bbio(bio);
	struct closure *cl = bio->bi_private;
	struct search *s = container_of(cl, struct search, cl);

	if (error)
		s->iop.error = error;
	else if (ptr_stale(b->ca, &bkey_i_to_extent_c(&b->key)->v.ptr[0])) {
		/* Read bucket invalidate race */
		atomic_long_inc(&s->iop.c->cache_read_races);
		s->iop.error = -EINTR;
	}

	bch_bbio_endio(b, error, "reading from cache");
}

static void cached_dev_read(struct cached_dev *dc, struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;
	struct btree_iter iter;
	const struct bkey *k;

	bch_increment_clock(s->iop.c, bio_sectors(&s->bio.bio), READ);

	for_each_btree_key_with_holes(&iter, s->iop.c, BTREE_ID_EXTENTS,
				POS(s->inode, bio->bi_iter.bi_sector), k) {
		struct bio *n;
		struct bbio *bbio;
		const struct bch_extent_ptr *ptr;
		unsigned sectors;
		struct cache *ca;
		bool done;
retry:
		BUG_ON(bkey_cmp(bkey_start_pos(k),
				POS(s->inode, bio->bi_iter.bi_sector)) > 0);

		BUG_ON(bkey_cmp(k->p,
				POS(s->inode, bio->bi_iter.bi_sector)) <= 0);

		sectors = k->p.offset - bio->bi_iter.bi_sector;
		done = sectors >= bio_sectors(bio);

		ca = bch_extent_pick_ptr(s->iop.c, k, &ptr);
		if (IS_ERR(ca)) {
			bcache_io_error(s->iop.c, bio,
					"no device to read from");
			bch_btree_iter_unlock(&iter);
			goto out;
		}

		if (!ca && k->type == KEY_TYPE_DISCARD) {
			/* The data is zeros.  Instantiate them. */
			unsigned bytes = min_t(unsigned, sectors,
					       bio_sectors(bio)) << 9;

			swap(bio->bi_iter.bi_size, bytes);
			zero_fill_bio(bio);
			swap(bio->bi_iter.bi_size, bytes);

			bio_advance(bio, bytes);
		} else if (!ca) {
			/* not present (hole), or stale cached data */
			if (cached_dev_cache_miss(&iter, s, bio, sectors)) {
				k = bch_btree_iter_peek_with_holes(&iter);
				goto retry;
			}
		} else {
			const struct bkey_i_extent *e = bkey_i_to_extent_c(k);

			PTR_BUCKET(ca, ptr)->read_prio =
				s->iop.c->prio_clock[READ].hand;

			if (!EXTENT_CACHED(&e->v))
				s->read_dirty_data = true;

			n = bio_next_split(bio, sectors, GFP_NOIO,
					   s->d->bio_split);

			bbio = to_bbio(n);
			bch_bkey_copy_single_ptr(&bbio->key, k, ptr - e->v.ptr);

			/* Trim the key to match what we're actually reading */
			bch_cut_front(POS(s->inode, n->bi_iter.bi_sector),
				      &bbio->key);
			bch_cut_back(POS(s->inode, bio_end_sector(n)),
				     &bbio->key);

			bch_bbio_prep(bbio, ca);

			n->bi_end_io		= bch_cache_read_endio;
			n->bi_private		= &s->cl;

			closure_get(&s->cl);
			if (!s->bypass) {
				if (cache_promote(s->iop.c, bbio, k))
					s->cache_miss = 1;
			} else
				submit_bio(0, n);
		}

		if (done) {
			bch_btree_iter_unlock(&iter);
			goto out;
		}
	}

	/*
	 * If we get here, it better have been because there was an error
	 * reading a btree node
	 */
	BUG_ON(!bch_btree_iter_unlock(&iter));
	bcache_io_error(s->iop.c, bio, "btree IO error");
out:
	continue_at(cl, cached_dev_read_done_bh, NULL);
}

/* Process writes */

static void cached_dev_write_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	up_read_non_owner(&dc->writeback_lock);
	cached_dev_bio_complete(cl);
}

static void cached_dev_write(struct cached_dev *dc, struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;
	unsigned inode = bcache_dev_inum(&dc->disk);
	bool writeback = false;
	bool bypass = s->bypass;
	struct bkey insert_key = KEY(s->inode, 0, 0);
	struct bio *insert_bio;
	unsigned flags = 0;

	down_read_non_owner(&dc->writeback_lock);
	if (bch_keybuf_check_overlapping(&dc->writeback_keys,
					 POS(inode, bio->bi_iter.bi_sector),
					 POS(inode, bio_end_sector(bio)))) {
		/*
		 * We overlap with some dirty data undergoing background
		 * writeback, force this write to writeback
		 */
		bypass = false;
		writeback = true;
	}

	/*
	 * Discards aren't _required_ to do anything, so skipping if
	 * check_overlapping returned true is ok
	 *
	 * But check_overlapping drops dirty keys for which io hasn't started,
	 * so we still want to call it.
	 */
	if (bio->bi_rw & REQ_DISCARD)
		bypass = true;

	if (should_writeback(dc, bio, BDEV_CACHE_MODE(&dc->sb),
			     bypass)) {
		bypass = false;
		writeback = true;
	}

	if (bypass) {
		insert_bio = s->orig_bio;
		bio_get(insert_bio);

		/* If this is a bypass-write (as opposed to a discard), send
		 * it down to the backing device. If this is a discard, only
		 * send it to the backing device if the backing device
		 * supports discards. Otherwise, we simply discard the key
		 * range from the cache and don't touch the backing device. */
		if (!(bio->bi_rw & REQ_DISCARD) ||
		    blk_queue_discard(bdev_get_queue(dc->bdev)))
			closure_bio_submit(bio, cl);
	} else if (writeback) {
		insert_bio = bio;
		bch_writeback_add(dc);

		if (bio->bi_rw & REQ_FLUSH) {
			/* Also need to send a flush to the backing device */
			struct bio *flush = bio_alloc_bioset(GFP_NOIO, 0,
							     dc->disk.bio_split);

			flush->bi_rw	= WRITE_FLUSH;
			flush->bi_bdev	= bio->bi_bdev;
			flush->bi_end_io = request_endio;
			flush->bi_private = cl;

			closure_bio_submit(flush, cl);
		}
	} else {
		insert_bio = bio_clone_fast(bio, GFP_NOIO, dc->disk.bio_split);
		closure_bio_submit(bio, cl);

		flags |= BCH_WRITE_CACHED;
		flags |= BCH_WRITE_ALLOC_NOWAIT;
	}

	if (bio->bi_rw & (REQ_FLUSH|REQ_FUA))
		flags |= BCH_WRITE_FLUSH;
	if (bypass)
		flags |= BCH_WRITE_DISCARD;

	bch_write_op_init(&s->iop, dc->disk.c, insert_bio, NULL,
			  &insert_key, NULL, flags);

	closure_call(&s->iop.cl, bch_write, NULL, cl);
	continue_at(cl, cached_dev_write_complete, NULL);
}

static void cached_dev_nodata(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio *bio = &s->bio.bio;

	if (s->orig_bio->bi_rw & (REQ_FLUSH|REQ_FUA))
		bch_journal_meta(s->iop.c, cl);

	/* If it's a flush, we send the flush to the backing device too */
	closure_bio_submit(bio, cl);

	continue_at(cl, cached_dev_bio_complete, NULL);
}

/* Cached devices - read & write stuff */

static void cached_dev_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct bcache_device *d = bio->bi_bdev->bd_disk->private_data;
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	int rw = bio_data_dir(bio);

	generic_start_io_acct(rw, bio_sectors(bio), &d->disk->part0);

	bio->bi_bdev = dc->bdev;
	bio->bi_iter.bi_sector += dc->sb.data_offset;

	if (cached_dev_get(dc)) {
		s = search_alloc(bio, d);
		trace_bcache_request_start(s->d, bio);

		if (!bio->bi_iter.bi_size) {
			/*
			 * can't call bch_journal_meta from under
			 * generic_make_request
			 */
			continue_at_nobarrier(&s->cl,
					      cached_dev_nodata,
					      d->c->wq);
		} else {
			s->bypass = check_should_bypass(dc, bio, rw);

			if (rw)
				cached_dev_write(dc, s);
			else
				cached_dev_read(dc, s);
		}
	} else {
		if ((bio->bi_rw & REQ_DISCARD) &&
		    !blk_queue_discard(bdev_get_queue(dc->bdev)))
			bio_endio(bio, 0);
		else
			generic_make_request(bio);
	}
}

static int cached_dev_ioctl(struct bcache_device *d, fmode_t mode,
			    unsigned int cmd, unsigned long arg)
{
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	return __blkdev_driver_ioctl(dc->bdev, mode, cmd, arg);
}

static int cached_dev_congested(void *data, int bits)
{
	struct bcache_device *d = data;
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	struct request_queue *q = bdev_get_queue(dc->bdev);
	int ret = 0;

	if (bdi_congested(&q->backing_dev_info, bits))
		return 1;

	if (cached_dev_get(dc)) {
		unsigned i;
		struct cache *ca;

		for_each_cache(ca, d->c, i) {
			q = bdev_get_queue(ca->bdev);
			ret |= bdi_congested(&q->backing_dev_info, bits);
		}

		cached_dev_put(dc);
	}

	return ret;
}

void bch_cached_dev_request_init(struct cached_dev *dc)
{
	struct gendisk *g = dc->disk.disk;

	g->queue->make_request_fn		= cached_dev_make_request;
	g->queue->backing_dev_info.congested_fn = cached_dev_congested;
	dc->disk.ioctl				= cached_dev_ioctl;
}

/* Flash backed devices */

static void flash_dev_nodata(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	if (s->orig_bio->bi_rw & (REQ_FLUSH|REQ_FUA))
		bch_journal_meta(s->iop.c, cl);

	continue_at(cl, search_free, NULL);
}

static void flash_dev_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct bcache_device *d = bio->bi_bdev->bd_disk->private_data;
	int rw = bio_data_dir(bio);

	generic_start_io_acct(rw, bio_sectors(bio), &d->disk->part0);

	trace_bcache_request_start(d, bio);

	if (!bio->bi_iter.bi_size) {
		s = search_alloc(bio, d);
		/*
		 * can't call bch_journal_meta from under
		 * generic_make_request
		 */
		continue_at_nobarrier(&s->cl,
				      flash_dev_nodata,
				      d->c->wq);
	} else if (rw) {
		unsigned flags = 0;

		s = search_alloc(bio, d);
		bio = &s->bio.bio;

		if (bio->bi_rw & (REQ_FLUSH|REQ_FUA))
			flags |= BCH_WRITE_FLUSH;
		if (bio->bi_rw & REQ_DISCARD)
			flags |= BCH_WRITE_DISCARD;

		bch_write_op_init(&s->iop, d->c, bio, NULL,
				  &KEY(s->inode, 0, 0), NULL, flags);

		closure_call(&s->iop.cl, bch_write, NULL, &s->cl);
		continue_at(&s->cl, search_free, NULL);
	} else {
		int ret = bch_read(d->c, bio, bcache_dev_inum(d));

		bio_endio(bio, ret);
	}
}

static int flash_dev_ioctl(struct bcache_device *d, fmode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

static int flash_dev_congested(void *data, int bits)
{
	struct bcache_device *d = data;
	struct request_queue *q;
	struct cache *ca;
	unsigned i;
	int ret = 0;

	for_each_cache(ca, d->c, i) {
		q = bdev_get_queue(ca->bdev);
		ret |= bdi_congested(&q->backing_dev_info, bits);
	}

	return ret;
}

void bch_flash_dev_request_init(struct bcache_device *d)
{
	struct gendisk *g = d->disk;

	g->queue->make_request_fn		= flash_dev_make_request;
	g->queue->backing_dev_info.congested_fn = flash_dev_congested;
	d->ioctl				= flash_dev_ioctl;
}
