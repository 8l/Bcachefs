/*
 * Some low level IO code, and hacks for various block layer limitations
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "bset.h"
#include "btree.h"
#include "buckets.h"
#include "debug.h"
#include "extents.h"
#include "io.h"
#include "keybuf.h"
#include "stats.h"
#include "super.h"

#include <linux/blkdev.h>

#include <trace/events/bcache.h>

void bch_generic_make_request(struct bio *bio, struct cache_set *c)
{
	if (current->bio_list) {
		spin_lock(&c->bio_submit_lock);
		bio_list_add(&c->bio_submit_list, bio);
		spin_unlock(&c->bio_submit_lock);
		queue_work(bcache_io_wq, &c->bio_submit_work);
	} else {
		generic_make_request(bio);
	}
}

void bch_bio_submit_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   bio_submit_work);
	struct bio *bio;

	while (1) {
		spin_lock(&c->bio_submit_lock);
		bio = bio_list_pop(&c->bio_submit_list);
		spin_unlock(&c->bio_submit_lock);

		if (!bio)
			break;

		bch_generic_make_request(bio, c);
	}
}

/* Bios with headers */

void bch_bbio_free(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	mempool_free(b, c->bio_meta);
}

struct bio *bch_bbio_alloc(struct cache_set *c)
{
	struct bbio *b = mempool_alloc(c->bio_meta, GFP_NOIO);
	struct bio *bio = &b->bio;

	bio_init(bio);
	bio->bi_flags		|= BIO_POOL_NONE << BIO_POOL_OFFSET;
	bio->bi_max_vecs	 = bucket_pages(c);
	bio->bi_io_vec		 = bio->bi_inline_vecs;

	return bio;
}

void bch_bbio_prep(struct bbio *b, struct cache *ca)
{
	struct bvec_iter *iter = &b->bio.bi_iter;

	b->ca				= ca;
	b->bio.bi_iter.bi_sector	= PTR_OFFSET(&b->key, 0);
	b->bio.bi_bdev			= ca ? ca->bdev : NULL;

	b->bi_idx			= iter->bi_idx;
	b->bi_bvec_done			= iter->bi_bvec_done;
}

void bch_submit_bbio(struct bbio *b, struct cache *ca,
		     struct bkey *k, unsigned ptr, bool punt)
{
	struct bio *bio = &b->bio;

	bch_bkey_copy_single_ptr(&b->key, k, ptr);
	bch_bbio_prep(b, ca);
	b->submit_time_us = local_clock_us();

	if (!ca) {
		closure_get(bio->bi_private);
		bio_io_error(bio);
	} else if (punt)
		closure_bio_submit_punt(bio, bio->bi_private, ca->set);
	else
		closure_bio_submit(bio, bio->bi_private);
}

void bch_submit_bbio_replicas(struct bio *bio, struct cache_set *c,
			      struct bkey *k, unsigned ptrs_from, bool punt)
{
	struct cache *ca;
	unsigned ptr;

	for (ptr = ptrs_from;
	     ptr < bch_extent_ptrs(k);
	     ptr++) {
		rcu_read_lock();
		ca = PTR_CACHE(c, k, ptr);
		if (ca)
			percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		if (!ca) {
			bch_submit_bbio(to_bbio(bio), ca, k, ptr, punt);
			break;
		}

		if (ptr + 1 < bch_extent_ptrs(k)) {
			struct bio *n = bio_clone_fast(bio, GFP_NOIO,
						       ca->replica_set);
			n->bi_end_io		= bio->bi_end_io;
			n->bi_private		= bio->bi_private;
			bch_submit_bbio(to_bbio(n), ca, k, ptr, punt);
		} else {
			bch_submit_bbio(to_bbio(bio), ca, k, ptr, punt);
		}
	}
}

static void bch_bbio_reset(struct bbio *b)
{
	struct bvec_iter *iter = &b->bio.bi_iter;

	bio_reset(&b->bio);
	iter->bi_sector		= KEY_START(&b->key);
	iter->bi_size		= KEY_SIZE(&b->key) << 9;
	iter->bi_idx		= b->bi_idx;
	iter->bi_bvec_done	= b->bi_bvec_done;
}

/* IO errors */

void bch_count_io_errors(struct cache *ca, int error, const char *m)
{
	/*
	 * The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */

	if (ca->set->error_decay) {
		unsigned count = atomic_inc_return(&ca->io_count);

		while (count > ca->set->error_decay) {
			unsigned errors;
			unsigned old = count;
			unsigned new = count - ca->set->error_decay;

			/*
			 * First we subtract refresh from count; each time we
			 * succesfully do so, we rescale the errors once:
			 */

			count = atomic_cmpxchg(&ca->io_count, old, new);

			if (count == old) {
				count = new;

				errors = atomic_read(&ca->io_errors);
				do {
					old = errors;
					new = ((uint64_t) errors * 127) / 128;
					errors = atomic_cmpxchg(&ca->io_errors,
								old, new);
				} while (old != errors);
			}
		}
	}

	if (error) {
		char buf[BDEVNAME_SIZE];
		unsigned errors = atomic_add_return(1 << IO_ERROR_SHIFT,
						    &ca->io_errors);
		errors >>= IO_ERROR_SHIFT;

		if (errors < ca->set->error_limit) {
			pr_err("%s: IO error on %s, recovering",
			       bdevname(ca->bdev, buf), m);
		} else {
			pr_err("%s: too many IO errors on %s, removing",
			       bdevname(ca->bdev, buf), m);
			bch_cache_remove(ca);
		}
	}
}

void bch_bbio_count_io_errors(struct bbio *bio, int error, const char *m)
{
	struct cache_set *c;
	unsigned threshold;

	if (!bio->ca)
		return;

	c = bio->ca->set;
	threshold = bio->bio.bi_rw & REQ_WRITE
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold && bio->submit_time_us) {
		unsigned t = local_clock_us();

		int us = t - bio->submit_time_us;
		int congested = atomic_read(&c->congested);

		if (us > (int) threshold) {
			int ms = us / 1024;
			c->congested_last_us = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	bch_count_io_errors(bio->ca, error, m);
}

void bch_bbio_endio(struct bbio *bio, int error, const char *m)
{
	struct closure *cl = bio->bio.bi_private;
	struct cache *ca = bio->ca;

	bch_bbio_count_io_errors(bio, error, m);
	bio_put(&bio->bio);
	if (ca)
		percpu_ref_put(&ca->ref);
	closure_put(cl);
}

/* Writes */

static void __bch_write(struct closure *);

static void bio_csum(struct bio *bio, struct bkey *k)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	u64 crc = 0xffffffffffffffffULL;

	bio_for_each_segment(bv, bio, iter) {
		void *d = kmap(bv.bv_page) + bv.bv_offset;

		crc = bch_checksum_update(KEY_CSUM(k), crc, d, bv.bv_len);
		kunmap(bv.bv_page);
	}

	k->val[bch_extent_ptrs(k)] = crc;
}

static int btree_insert_fn(struct btree_op *b_op, struct btree *b)
{
	struct bch_write_op *op = container_of(b_op,
					struct bch_write_op, op);
	struct bkey *replace_key = op->replace ? &op->replace_key : NULL;

	int ret = bch_btree_insert_node(b, &op->op, &op->insert_keys,
					replace_key,
					op->flush ? &op->cl : NULL);
	return bch_keylist_empty(&op->insert_keys) ? MAP_DONE : ret;
}

static void bch_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	unsigned i;

	if (op->op.insert_collision)
		op->replace_collision = true;

	for (i = 0; i < ARRAY_SIZE(op->open_buckets); i++)
		if (op->open_buckets[i]) {
			bch_open_bucket_put(op->c, op->open_buckets[i]);
			op->open_buckets[i] = NULL;
		}

	if (!op->write_done)
		continue_at(cl, __bch_write, op->io_wq);

	bch_keylist_free(&op->insert_keys);
	closure_return(cl);
}

static void __bch_write_index(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op,
					op.cl);
	struct keylist *keys = &op->insert_keys;
	int ret = 0;

	while (!ret && !bch_keylist_empty(keys)) {
		op->op.locks_want = 0;
		ret = bch_btree_map_nodes(&op->op, op->c,
					  &START_KEY(keys->keys),
					  btree_insert_fn,
					  MAP_ASYNC);
	}

	if (ret == -EAGAIN)
		continue_at(cl, __bch_write_index, op->c->wq);

	closure_return(cl);
}

/**
 * bch_write_index - after a write, update index to point to new data
 */
static void bch_write_index(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	enum btree_id id = BTREE_ID_EXTENTS;

	__bch_btree_op_init(&op->op, id, op->btree_alloc_reserve, 0);

	closure_call(&op->op.cl, __bch_write_index, NULL, cl);
	continue_at(cl, bch_write_done, op->c->wq);
}

/**
 * bch_discard - discard range of keys
 *
 * Used to implement discard, and to handle when writethrough write hits
 * a write error on the cache device.
 */
static void bch_discard(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct keylist *keys = &op->insert_keys;
	struct bio *bio = op->bio;

	pr_debug("invalidating %i sectors from %llu",
		 bio_sectors(bio), (uint64_t) bio->bi_iter.bi_sector);

	while (bio_sectors(bio)) {
		unsigned sectors = min(bio_sectors(bio),
				       1U << (KEY_SIZE_BITS - 1));

		if (bch_keylist_realloc(keys, BKEY_U64s))
			goto out;

		bio->bi_iter.bi_sector	+= sectors;
		bio->bi_iter.bi_size	-= sectors << 9;

		*keys->top = KEY(KEY_INODE(&op->insert_key),
				 bio->bi_iter.bi_sector, sectors);
		SET_KEY_DELETED(keys->top, true);

		bch_keylist_push(keys);
	}

	op->write_done = true;
	bio_put(bio);
out:
	continue_at(cl, bch_write_index, op->c->wq);
}

static void bch_write_error(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	/*
	 * Our data write just errored, which means we've got a bunch of keys to
	 * insert that point to data that wasn't successfully written.
	 *
	 * We don't have to insert those keys but we still have to invalidate
	 * that region of the cache - so, if we just strip off all the pointers
	 * from the keys we'll accomplish just that.
	 */

	struct bkey *src = op->insert_keys.keys, *dst = op->insert_keys.keys;

	while (src != op->insert_keys.top) {
		struct bkey *n = bkey_next(src);

		bch_set_extent_ptrs(src, 0);
		memmove(dst, src, bkey_bytes(src));

		dst = bkey_next(dst);
		src = n;
	}

	op->insert_keys.top = dst;

	bch_write_index(cl);
}

static void bch_write_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);

	if (error) {
		/* TODO: We could try to recover from this. */
		if (!KEY_CACHED(&op->insert_key))
			op->error = error;
		else if (!op->replace)
			set_closure_fn(cl, bch_write_error, op->c->wq);
		else
			set_closure_fn(cl, NULL, NULL);
	}

	bch_bbio_endio(to_bbio(bio), error, "writing data to cache");
}

static void __bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bio *bio = op->bio, *n;
	unsigned open_bucket_nr = 0, ptrs_from;
	struct open_bucket *b;

	memset(op->open_buckets, 0, sizeof(op->open_buckets));

	if (op->discard)
		return bch_discard(cl);

	bch_extent_drop_stale(op->c, &op->insert_key);
	ptrs_from = bch_extent_ptrs(&op->insert_key);

	/*
	 * Journal writes are marked REQ_FLUSH; if the original write was a
	 * flush, it'll wait on the journal write.
	 */
	bio->bi_rw &= ~(REQ_FLUSH|REQ_FUA);

	do {
		struct bkey *k;
		struct bio_set *split = op->c->bio_split;

		BUG_ON(bio_sectors(bio) != KEY_SIZE(&op->insert_key));

		if (open_bucket_nr == ARRAY_SIZE(op->open_buckets))
			continue_at(cl, bch_write_index,
				    op->c->wq);

		/* for the device pointers and 1 for the chksum */
		if (bch_keylist_realloc(&op->insert_keys,
					BKEY_EXTENT_MAX_U64s +
					(KEY_CSUM(&op->insert_key) ? 1 : 0)))
			continue_at(cl, bch_write_index, op->c->wq);

		k = op->insert_keys.top;
		bkey_copy(k, &op->insert_key);

		b = bch_alloc_sectors(op->c, op->wp, k, op->wait ? cl : NULL);
		BUG_ON(!b);

		if (PTR_ERR(b) == -EAGAIN) {
			/* If we already have some keys, must insert them first
			 * before allocating another open bucket. We only hit
			 * this case if open_bucket_nr > 1. */
			if (bch_keylist_empty(&op->insert_keys))
				continue_at(cl, __bch_write,
					    op->io_wq);
			else
				continue_at(cl, bch_write_index,
					    op->c->wq);
		} else if (IS_ERR(b))
			goto err;

		op->open_buckets[open_bucket_nr++] = b;

		bch_cut_front(k, &op->insert_key);

		n = bio_next_split(bio, KEY_SIZE(k), GFP_NOIO, split);
		n->bi_end_io	= bch_write_endio;
		n->bi_private	= cl;

		if (KEY_CSUM(k))
			bio_csum(n, k);

		trace_bcache_cache_insert(k);

		n->bi_rw |= REQ_WRITE;
		bch_submit_bbio_replicas(n, op->c, k, ptrs_from, false);

		bch_extent_normalize(op->c, k);
		bch_check_mark_super(op->c, k, false);

		bch_keylist_push(&op->insert_keys);
	} while (n != bio);

	op->write_done = true;
	continue_at(cl, bch_write_index, op->c->wq);
err:
	if (KEY_CACHED(&op->insert_key)) {
		/*
		 * If we were writing cached data, not doing the write is fine
		 * so long as we discard whatever would have been overwritten -
		 * then it's equivalent to doing the write and immediately
		 * reclaiming it.
		 */

		op->discard = true;
		return bch_discard(cl);
	}

	op->error		= -ENOSPC;
	op->write_done	= true;
	bio_put(bio);

	/*
	 * No reason not to insert keys for whatever data was successfully
	 * written (especially for a cmpxchg operation that's moving data
	 * around)
	 */
	if (!bch_keylist_empty(&op->insert_keys))
		continue_at(cl, bch_write_index, op->c->wq);
	else
		closure_return(cl);
}

void bch_wake_delayed_writes(unsigned long data)
{
	struct cache_set *c = (void *) data;
	struct bch_write_op *op;
	unsigned long flags;

	spin_lock_irqsave(&c->foreground_write_pd_lock, flags);

	while ((op = c->write_wait_head)) {
		if (time_after(op->expires, jiffies)) {
			c->foreground_write_wakeup.expires = op->expires;
			add_timer(&c->foreground_write_wakeup);
			break;
		}

		c->write_wait_head = op->next;
		if (!c->write_wait_head)
			c->write_wait_tail = NULL;

		closure_put(&op->cl);
	}

	spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);
}

/**
 * bch_write - handle a write to a cache device or flash only volume
 *
 * This is the starting point for any data to end up in a cache device; it could
 * be from a normal write, or a writeback write, or a write to a flash only
 * volume - it's also used by the moving garbage collector to compact data in
 * mostly empty buckets.
 *
 * It first writes the data to the cache, creating a list of keys to be inserted
 * (if the data won't fit in a single open bucket, there will be multiple keys);
 * after the data is written it calls bch_journal, and after the keys have been
 * added to the next journal write they're inserted into the btree.
 *
 * It inserts the data in op->bio; bi_sector is used for the key offset, and
 * op->inode is used for the key inode.
 *
 * If op->discard is true, instead of inserting the data it invalidates the
 * region of the cache represented by op->bio and op->inode.
 */
void bch_write(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct cache_set *c = op->c;
	u64 inode = KEY_INODE(&op->insert_key);

	trace_bcache_write(c, inode, op->bio, !KEY_CACHED(&op->insert_key),
			   op->discard);

	if (!bio_sectors(op->bio)) {
		WARN_ONCE(1, "bch_write() called with empty bio");
		closure_return(cl);
	}

	/*
	 * This ought to be initialized in bch_write_op_init(), but struct
	 * cache_set isn't exported
	 */
	if (!op->io_wq)
		op->io_wq = op->c->wq;

	if (!op->discard)
		bch_increment_clock(c, bio_sectors(op->bio), WRITE);

	if (!op->replace) {
		/* XXX: discards may be for more sectors than max key size */

		struct bkey start = KEY(inode, op->bio->bi_iter.bi_sector, 0);
		struct bkey end = KEY(inode, bio_end_sector(op->bio), 0);

		unsigned i;
		struct cache *ca;

		for_each_cache(ca, c, i)
			bch_keybuf_check_overlapping(&ca->moving_gc_keys,
						     &start, &end);

		bch_keybuf_check_overlapping(&c->tiering_keys,
					     &start, &end);
	}

	if (op->wp->ca)
		bch_mark_gc_write(c, bio_sectors(op->bio));
	else if (!op->discard)
		bch_mark_foreground_write(c, bio_sectors(op->bio));
	else
		bch_mark_discard(c, bio_sectors(op->bio));

	if (atomic64_sub_return(bio_sectors(op->bio),
		                &c->sectors_until_gc) < 0) {
		set_gc_sectors(c);
		wake_up_process(c->gc_thread);
	}

	SET_KEY_OFFSET(&op->insert_key, bio_end_sector(op->bio));
	SET_KEY_SIZE(&op->insert_key, bio_sectors(op->bio));

	bch_keylist_init(&op->insert_keys);
	bio_get(op->bio);

	/* Don't call bch_next_delay() if rate is >= 1 GB/sec */

	if (c->foreground_write_pd.rate.rate < (1 << 30) &&
	    !op->discard) {
		unsigned long flags;
		u64 next, now = local_clock();

		spin_lock_irqsave(&c->foreground_write_pd_lock, flags);
		bch_ratelimit_increment(&c->foreground_write_pd.rate,
					op->bio->bi_iter.bi_size);

		next = c->foreground_write_pd.rate.next;

		if (time_after64(next, now + NSEC_PER_MSEC * 10)) {
			closure_get(&op->cl); /* list takes a ref */

			op->expires = div_u64(next, NSEC_PER_SEC / HZ);
			op->next = NULL;

			if (c->write_wait_tail)
				c->write_wait_tail->next = op;
			else
				c->write_wait_head = op;
			c->write_wait_tail = op;

			if (!timer_pending(&c->foreground_write_wakeup))
				mod_timer(&c->foreground_write_wakeup,
					  op->expires);

			spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);
			continue_at(cl, __bch_write, op->c->wq);
		}

		spin_unlock_irqrestore(&c->foreground_write_pd_lock, flags);
	}

	continue_at_nobarrier(cl, __bch_write, NULL);
}
EXPORT_SYMBOL(bch_write);

void bch_write_op_init(struct bch_write_op *op, struct cache_set *c,
		       struct bio *bio, struct write_point *wp,
		       bool wait, bool discard, bool flush,
		       struct bkey *insert_key, struct bkey *replace_key)
{
	if (!wp) {
		unsigned wp_idx = hash_long((unsigned long) current,
					    ilog2(ARRAY_SIZE(c->write_points)));

		BUG_ON(wp_idx > ARRAY_SIZE(c->write_points));
		wp = &c->write_points[wp_idx];
	}

	op->c		= c;
	op->io_wq	= NULL;
	op->bio		= bio;
	op->error	= 0;
	op->flags	= 0;
	op->wait	= wait;
	op->discard	= discard;
	op->flush	= flush;
	op->wp		= wp;
	op->btree_alloc_reserve = BTREE_ID_EXTENTS;

	bch_keylist_init(&op->insert_keys);
	bkey_copy(&op->insert_key, insert_key);

	if (replace_key) {
		op->replace = true;
		bkey_copy(&op->replace_key, replace_key);
	}
}
EXPORT_SYMBOL(bch_write_op_init);

/* Cache promotion on read */

struct cache_promote_op {
	struct closure		cl;
	struct bio		*orig_bio;
	struct bch_write_op	iop;
	bool			stale; /* was the ptr stale after the read? */
	struct bbio		bio; /* must be last */
};

static void cache_promote_done(struct closure *cl)
{
	struct cache_promote_op *op = container_of(cl,
					struct cache_promote_op, cl);
	int i;
	struct bio_vec *bv;

	if (op->iop.replace_collision) {
		trace_bcache_promote_collision(&op->iop.replace_key);
		atomic_inc(&op->iop.c->accounting.collector.cache_miss_collisions);
	}

	bio_for_each_segment_all(bv, op->iop.bio, i)
		__free_page(bv->bv_page);

	kfree(op);
}

static void cache_promote_write(struct closure *cl)
{
	struct cache_promote_op *op = container_of(cl,
					struct cache_promote_op, cl);
	struct bio *bio = op->iop.bio;

	bio_reset(bio);
	bio->bi_iter.bi_sector	= KEY_START(&op->iop.insert_key);
	bio->bi_iter.bi_size	= KEY_SIZE(&op->iop.insert_key) << 9;
	/* needed to reinit bi_vcnt so pages can be freed later */
	bch_bio_map(bio, NULL);

	bio_copy_data(op->orig_bio, bio);
	bio_endio(op->orig_bio, op->iop.error);

	if (!op->stale &&
	    !op->iop.error &&
	    !test_bit(CACHE_SET_STOPPING, &op->iop.c->flags))
		closure_call(&op->iop.cl, bch_write, NULL, cl);

	closure_return_with_destructor(cl, cache_promote_done);
}

static void cache_promote_endio(struct bio *bio, int error)
{
	struct bbio *b = to_bbio(bio);
	struct cache_promote_op *op = container_of(b,
					struct cache_promote_op, bio);

	/*
	 * If the bucket was reused while our bio was in flight, we might have
	 * read the wrong data. Set s->error but not error so it doesn't get
	 * counted against the cache device, but we'll still reread the data
	 * from the backing device.
	 */

	if (error)
		op->iop.error = error;
	else if (b->ca && ptr_stale(b->ca->set, b->ca, &b->key, 0))
		op->stale = 1;

	bch_bbio_endio(b, error, "reading from cache");
}

/**
 * __cache_promote -- insert result of read bio into cache
 *
 * Used for backing devices and flash-only volumes.
 *
 * @orig_bio must actually be a bbio with a valid key.
 */
void __cache_promote(struct cache_set *c, struct bbio *orig_bio,
		     struct bkey *replace_key)
{
	struct cache_promote_op *op;
	struct bio *bio;
	unsigned pages = DIV_ROUND_UP(orig_bio->bio.bi_iter.bi_size, PAGE_SIZE);

	/* XXX: readahead? */

	op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * pages, GFP_NOIO);
	if (!op)
		goto out_submit;

	/* clone the bbio */
	memcpy(&op->bio, orig_bio, offsetof(struct bbio, bio));

	bio = &op->bio.bio;
	bio_init(bio);
	bio_get(bio);
	bio->bi_bdev		= orig_bio->bio.bi_bdev;
	bio->bi_iter.bi_sector	= orig_bio->bio.bi_iter.bi_sector;
	bio->bi_iter.bi_size	= orig_bio->bio.bi_iter.bi_size;
	bio->bi_end_io		= cache_promote_endio;
	bio->bi_private		= &op->cl;
	bio->bi_io_vec		= bio->bi_inline_vecs;
	bch_bio_map(bio, NULL);

	if (bio_alloc_pages(bio, __GFP_NOWARN|GFP_NOIO))
		goto out_free;

	orig_bio->ca = NULL;

	closure_init(&op->cl, &c->cl);
	op->orig_bio		= &orig_bio->bio;
	op->stale		= 0;

	bch_write_op_init(&op->iop, c, bio,
			  &c->tier_write_points[0],
			  false, false, false,
			  replace_key, replace_key);

	bch_cut_front(&START_KEY(&orig_bio->key), &op->iop.insert_key);
	bch_cut_back(&orig_bio->key, &op->iop.insert_key);

	trace_bcache_promote(&orig_bio->bio);

	op->bio.submit_time_us = local_clock_us();
	closure_bio_submit(bio, &op->cl);

	continue_at(&op->cl, cache_promote_write, c->wq);
out_free:
	kfree(op);
out_submit:
	generic_make_request(&orig_bio->bio);
}

/**
 * cache_promote - promote data stored in higher tiers
 *
 * Used for flash only volumes.
 *
 * @bio must actually be a bbio with valid key.
 */
bool cache_promote(struct cache_set *c, struct bbio *bio,
		   struct bkey *k, unsigned ptr)
{
	if (!CACHE_TIER(&c->members[PTR_DEV(k, ptr)])) {
		generic_make_request(&bio->bio);
		return 0;
	}

	__cache_promote(c, bio, k);
	return 1;
}

/* Read */

struct bch_read_op {
	struct btree_op		op;
	struct cache_set	*c;
	struct bio		*bio;
	u64			inode;
};

static void bch_read_requeue(struct cache_set *c, struct bio *bio)
{
	unsigned long flags;
	spin_lock_irqsave(&c->read_race_lock, flags);
	bio_list_add(&c->read_race_list, bio);
	spin_unlock_irqrestore(&c->read_race_lock, flags);
	queue_work(c->wq, &c->read_race_work);
}

static void bch_read_endio(struct bio *bio, int error)
{
	struct bbio *b = to_bbio(bio);
	struct cache *ca = b->ca;

	bch_bbio_count_io_errors(b, error, "reading from cache");

	if (!error && ca &&
	    (dynamic_fault() || ptr_stale(ca->set, ca, &b->key, 0))) {
		/* Read bucket invalidate race */
		atomic_long_inc(&ca->set->cache_read_races);
		bch_read_requeue(ca->set, bio);
	} else {
		bio_endio(bio->bi_private, error);
		bio_put(bio);
	}

	if (ca)
		percpu_ref_put(&ca->ref);
}

/* XXX: this looks a lot like cache_lookup_fn() */
static int bch_read_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct bch_read_op *op = container_of(b_op,
			struct bch_read_op, op);
	struct bio *n, *bio = op->bio;
	struct bbio *bbio;
	int sectors, ret;
	unsigned ptr;
	struct cache *ca;

	BUG_ON(bkey_cmp(&START_KEY(k),
			&KEY(op->inode, bio->bi_iter.bi_sector, 0)) > 0);

	BUG_ON(bkey_cmp(k, &KEY(op->inode, bio->bi_iter.bi_sector, 0)) <= 0);

	sectors = KEY_OFFSET(k) - bio->bi_iter.bi_sector;

	ca = bch_extent_pick_ptr(b->c, k, &ptr);
	if (!ca) {
		if (!KEY_CACHED(k) && bch_extent_ptrs(k)) {
			bio_io_error(bio);
			return MAP_DONE;
		} else {
			unsigned bytes = min_t(unsigned, sectors,
					       bio_sectors(bio)) << 9;

			swap(bio->bi_iter.bi_size, bytes);
			zero_fill_bio(bio);
			swap(bio->bi_iter.bi_size, bytes);

			bio_advance(bio, bytes);

			return bio->bi_iter.bi_size ? MAP_CONTINUE : MAP_DONE;
		}
	}

	PTR_BUCKET(b->c, ca, k, ptr)->read_prio = b->c->prio_clock[READ].hand;

	if (sectors >= bio_sectors(bio)) {
		n = bio_clone_fast(bio, GFP_NOIO, b->c->bio_split);
		ret = MAP_DONE;
	} else {
		n = bio_split(bio, sectors, GFP_NOIO, b->c->bio_split);
		ret = MAP_CONTINUE;
	}

	n->bi_private		= bio;
	n->bi_end_io		= bch_read_endio;
	atomic_inc(&bio->bi_remaining);

	bbio = to_bbio(n);
	bch_bkey_copy_single_ptr(&bbio->key, k, ptr);

	/* Trim the key to match what we're actually reading */
	bch_cut_front(&KEY(op->inode, n->bi_iter.bi_sector, 0), &bbio->key);
	bch_cut_back(&KEY(op->inode, bio_end_sector(n), 0), &bbio->key);

	bch_bbio_prep(bbio, ca);

	cache_promote(b->c, bbio, k, ptr);

	return ret;
}

int bch_read(struct cache_set *c, struct bio *bio, u64 inode)
{
	struct bch_read_op op;
	int ret;

	bch_increment_clock(c, bio_sectors(bio), READ);

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, -1);
	op.c = c;
	op.bio = bio;
	op.inode = inode;

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(inode, bio->bi_iter.bi_sector, 0),
				 bch_read_fn, MAP_HOLES);
	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL(bch_read);

/**
 * bch_read_retry - re-submit a bio originally from bch_read()
 */
static void bch_read_retry(struct bbio *bbio)
{
	struct bio *bio = &bbio->bio;
	struct bio *parent;
	u64 inode;

	trace_bcache_read_retry(bio);

	/*
	 * This used to be a leaf bio from bch_read_fn(), but
	 * since we don't know what happened to the btree in
	 * the meantime, we have to re-submit it via the
	 * top-level bch_read() entry point. Before doing that,
	 * we have to reset the bio, preserving the biovec.
	 *
	 * The inode, offset and size come from the bbio's key,
	 * which was set by bch_read_fn().
	 */
	inode = KEY_INODE(&bbio->key);
	parent = bio->bi_private;

	bch_bbio_reset(bbio);
	bio_chain(bio, parent);

	bch_read(bbio->ca->set, bio, inode);
	bio_endio(parent, 0);  /* for bio_chain() in bch_read_fn() */
	bio_endio(bio, 0);
}

void bch_read_race_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set,
					   read_race_work);
	unsigned long flags;
	struct bio *bio;

	while (1) {
		spin_lock_irqsave(&c->read_race_lock, flags);
		bio = bio_list_pop(&c->read_race_list);
		spin_unlock_irqrestore(&c->read_race_lock, flags);

		if (!bio)
			break;

		bch_read_retry(to_bbio(bio));
	}
}
