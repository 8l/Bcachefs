/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Uses a block device as cache for other block devices; optimized for SSDs.
 * All allocation is done in buckets, which should match the erase block size
 * of the device.
 *
 * Buckets containing cached data are kept on a heap sorted by priority;
 * bucket priority is increased on cache hit, and periodically all the buckets
 * on the heap have their priority scaled down. This currently is just used as
 * an LRU but in the future should allow for more intelligent heuristics.
 *
 * Buckets have an 8 bit counter; freeing is accomplished by incrementing the
 * counter. Garbage collection is used to remove stale pointers.
 *
 * Indexing is done via a btree; nodes are not necessarily fully sorted, rather
 * as keys are inserted we only sort the pages that have not yet been written.
 * When garbage collection is run, we resort the entire node.
 *
 * All configuration is done via sysfs; see Documentation/bcache.txt.
 */

#include "bcache.h"

#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/console.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/hash.h>
#include <linux/ratelimit.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/swap.h>

/*
 * Todo:
 * register_bcache: Return errors out to userspace correctly
 *
 * Writeback: don't undirty key until after a cache flush
 *
 * Create an iterator for key pointers
 *
 * On btree write error, mark bucket such that it won't be freed from the cache
 *
 * Journalling:
 *   Check for bad keys in replay
 *   Propagate barriers
 *   Refcount journal entries in journal_replay
 *
 * Garbage collection:
 *   Finish incremental gc
 *   Gc should free old UUIDs, data for invalid UUIDs
 *
 * Provide a way to list backing device UUIDs we have data cached for, and
 * probably how long it's been since we've seen them, and a way to invalidate
 * dirty data for devices that will never be attached again
 *
 * Keep 1 min/5 min/15 min statistics of how busy a block device has been, so
 * that based on that and how much dirty data we have we can keep writeback
 * from being starved
 *
 * Add a tracepoint or somesuch to watch for writeback starvation
 *
 * When btree depth > 1 and splitting an interior node, we have to make sure
 * alloc_bucket() cannot fail. This should be true but is not completely
 * obvious.
 *
 * Don't keep the full heap around, build a small heap when we need to that
 * doesn't have backpointers
 *
 * Make sure all allocations get charged to the root cgroup
 *
 * bucket_lock shouldn't be in any fastpaths anymore - verify and turn it into
 * a mutex?
 *
 * Plugging?
 *
 * If data write is less than hard sector size of ssd, round up offset in open
 * bucket to the next whole sector
 *
 * Also lookup by cgroup in get_open_bucket()
 *
 * Superblock needs to be fleshed out for multiple cache devices
 *
 * Add a sysfs tunable for the number of writeback IOs in flight
 *
 * Add a sysfs tunable for the number of open data buckets
 *
 * IO tracking: Can we track when one process is doing io on behalf of another?
 * IO tracking: Don't use just an average, weigh more recent stuff higher
 *
 * Test module load/unload
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

const char *insert_type(struct btree_op *op)
{
	static const char *insert_types[] = {
		"read", "write", NULL, "writeback", "undirty", NULL, "replay"
	};

	return insert_types[op->insert_type];
}

#define MAX_NEED_GC		64
#define MAX_SAVE_PRIO		72

#define PTR_DIRTY_BIT		(((uint64_t) 1 << 36))

#define PTR_HASH(c, k)							\
	(((k)->ptr[0] >> c->bucket_bits) | PTR_GEN(k, 0))

static void btree_gc_work(struct work_struct *);

/* Btree key manipulation */

static void bkey_copy_single_ptr(struct bkey *dest,
				 const struct bkey *src,
				 unsigned i)
{
	BUG_ON(i > KEY_PTRS(src));

	/* Only copy the header, key, and one pointer. */
	memcpy(dest, src, 2 * sizeof(uint64_t));
	dest->ptr[0] = src->ptr[i];
	SET_KEY_PTRS(dest, 1);
	/* We didn't copy the checksum so clear that bit. */
	SET_KEY_CSUM(dest, 0);
}

static void bkey_put(struct cache_set *c, struct bkey *k, int write, int level)
{
	if ((level && k->key) ||
	    (!level && write != INSERT_UNDIRTY))
		__bkey_put(c, k);
}

/* Bios with headers */

static void bbio_destructor(struct bio *bio)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	kfree(b);
}

struct bio *bbio_kmalloc(gfp_t gfp, int vecs)
{
	struct bio *bio;
	struct bbio *b;

	b = kmalloc(sizeof(struct bbio) + sizeof(struct bio_vec) * vecs, gfp);
	if (!b)
		return NULL;

	bio = &b->bio;

	bio_init(bio);
	bio->bi_flags		|= BIO_POOL_NONE << BIO_POOL_OFFSET;
	bio->bi_max_vecs	 = vecs;
	bio->bi_io_vec		 = bio->bi_inline_vecs;
	bio->bi_destructor	 = bbio_destructor;

	return bio;
}

struct bio *bio_split_get(struct bio *bio, int len, struct cache_set *c)
{
	struct bio *ret;
	struct bio_set *bs = c->bio_split;

	ret = bio_split_front(bio, len, bbio_kmalloc, GFP_NOIO, bs);

	if (ret && ret != bio) {
		closure_get(ret->bi_private);
		ret->bi_rw &= ~REQ_UNPLUG;
	}

	return ret;
}

void submit_bbio(struct bio *bio, struct cache_set *c,
		 struct bkey *k, unsigned ptr)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	bkey_copy_single_ptr(&b->key, k, ptr);

	BUG_ON(bio->bi_destructor &&
	       (bio->bi_destructor != bbio_destructor) &&
	       (bio->bi_destructor != (void *) c->bio_split));

	bio->bi_sector	= PTR_OFFSET(&b->key, 0);
	bio->bi_bdev	= PTR_CACHE(c, &b->key, 0)->bdev;
	b->time		= ktime_get();

	generic_make_request(bio);
}

int submit_bbio_split(struct bio *bio, struct cache_set *c,
		      struct bkey *k, unsigned ptr)
{
	struct bbio *b;
	struct bio *n;
	unsigned sectors_done = 0;

	bio->bi_sector	= PTR_OFFSET(k, ptr);
	bio->bi_bdev	= PTR_CACHE(c, k, ptr)->bdev;

	do {
		n = bio_split_get(bio, bio_max_sectors(bio), c);
		if (!n)
			return -ENOMEM;

		b = container_of(n, struct bbio, bio);

		bkey_copy_single_ptr(&b->key, k, ptr);
		SET_KEY_SIZE(&b->key, KEY_SIZE(k) - sectors_done);
		SET_PTR_OFFSET(&b->key, 0, PTR_OFFSET(k, ptr) + sectors_done);

		b->time = ktime_get();
		generic_make_request(n);
	} while (n != bio);

	return 0;
}

/* IO errors */

void count_io_errors(struct cache *c, int error, const char *m)
{
	/* The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */
	int n, errors, count = 0, refresh = c->set->error_decay;

	if (refresh) {
		count = atomic_inc_return(&c->io_count);
		while (count > refresh) {
			int old_count = count;
			n = count - refresh;
			count = atomic_cmpxchg(&c->io_count, old_count, n);
			if (count == old_count) {
				int old_errors;
				errors = atomic_read(&c->io_errors);
				do {
					old_errors = errors;
					n = ((uint64_t) errors * 127) / 128;
					errors = atomic_cmpxchg(&c->io_errors,
								old_errors,
								n);
				} while (old_errors != errors);

				pr_debug("Errors scaled from %d to %d\n",
					 n, errors);
			}
		}
	}

	if (error) {
		char buf[BDEVNAME_SIZE];
		errors = atomic_add_return(1 << IO_ERROR_SHIFT, &c->io_errors);
		pr_debug("Errors: %d, Count: %d, Refresh: %d",
			 errors, count, refresh);
		errors >>= IO_ERROR_SHIFT;

		if (errors < c->set->error_limit)
			err_printk("IO error on %s %s, recovering\n",
				   bdevname(c->bdev, buf), m);
		else
			cache_set_error(c->set, "too many IO errors", m);
	}
}

void bcache_endio(struct cache_set *c, struct bio *bio,
		  int error, const char *m)
{
	struct closure *cl = bio->bi_private;
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct cache *ca = PTR_CACHE(c, &b->key, 0);

	BUG_ON(bio->bi_destructor &&
	       (bio->bi_destructor != bbio_destructor) &&
	       (bio->bi_destructor != (void *) c->bio_split));
	BUG_ON(KEY_PTRS(&b->key) != 1);

	if (c->congested_us) {
		int us, congested;
		ktime_t t = ktime_get();

		us = ktime_us_delta(t, b->time);
		congested = atomic_read(&c->congested);

		if (us > (int) c->congested_us) {
			int ms = us / 1024;
			c->congested_last = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	count_io_errors(ca, error, m);
	bio_put(bio);
	closure_put(cl, bcache_wq);
}

/* Btree IO */

static uint64_t btree_csum_set(struct btree *b, struct bset *i)
{
	uint64_t crc = b->key.ptr[0];
	void *data = (void *) i + 8, *end = end(i);

	crc = crc64_update(crc, data, end - data);
	return crc ^ 0xffffffffffffffff;
}

static void btree_bio_resubmit(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);
	bio_submit_split(&b->bio, &b->io, b->c->bio_split);
}

static void btree_bio_init(struct btree *b)
{
	bio_reset(&b->bio);
	b->bio.bi_sector = PTR_OFFSET(&b->key, 0) +
		b->written * b->c->sb.block_size;
	b->bio.bi_bdev	 = PTR_CACHE(b->c, &b->key, 0)->bdev;
	b->bio.bi_rw	 = REQ_META;
}

void btree_read_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);
	struct bset *i = b->data;
	struct btree_iter *iter = b->c->fill_iter;
	const char *err = "bad btree header";
	BUG_ON(b->nsets || b->written);

	mutex_lock(&b->c->fill_lock);
	iter->used = 0;

	if (!b->data->seq)
		goto err;

	for (i = b->data;
	     b->written < btree_blocks(b) && i->seq == b->data->seq;
	     i = write_block(b)) {
		err = "unsupported bset version";
		if (i->version > BCACHE_BSET_VERSION)
			goto err;

		err = "bad btree header";
		if (b->written + set_blocks(i, b->c) > btree_blocks(b))
			goto err;

		err = "bad magic";
		if (i->magic != bset_magic(b->c))
			goto err;

		err = "bad checksum";
		switch (i->version) {
		case 0:
			if (i->csum != csum_set(i))
				goto err;
			break;
		case BCACHE_BSET_VERSION:
			if (i->csum != btree_csum_set(b, i))
				goto err;
			break;
		}

		err = "empty set";
		if (i != b->data && !i->keys)
			goto err;

		err = "short btree key";
		if (i->keys && bkey_cmp(&b->key, last_key(i)) < 0)
			goto err;

		btree_iter_push(iter, i->start, end(i));

		b->written += set_blocks(i, b->c);
	}

	err = "corrupted btree";
	for (i = write_block(b);
	     index(i, b) < btree_blocks(b);
	     i = ((void *) i) + block_bytes(b->c))
		if (i->seq == b->data->seq)
			goto err;

	__btree_sort(b, 0, NULL, iter, true);

	pr_latency(b->expires, "btree_read");

	smp_wmb(); /* b->nread is our write lock */
	atomic_set(&b->nread, 1);

	if (0) {
err:		atomic_set(&b->nread, -1);
		cache_set_error(b->c, "%s at bucket %lu, block %i, %i keys",
				err, PTR_BUCKET_NR(b->c, &b->key, 0),
				index(i, b), i->keys);
	}

	mutex_unlock(&b->c->fill_lock);

	atomic_set(&b->io, -1);
	closure_run_wait(&b->wait, bcache_wq);
}

static void btree_read_endio(struct bio *bio, int error)
{
	struct btree *b = bio->bi_private;
	bio_put(bio);

	if (error) {
		cache_set_error(b->c, "reading index");
		atomic_set(&b->nread, -1);
	}

	if (!atomic_dec_and_test(&b->io))
		return;

	PREPARE_DELAYED_WORK(&b->work, btree_read_work);

	if (atomic_read(&b->nread) == -1) {
		atomic_set(&b->io, -1);
		closure_run_wait(&b->wait, bcache_wq);
	} else
		BUG_ON(!schedule_work(&b->work.work));
}

static void btree_read(struct btree *b)
{
	BUG_ON(b->nsets || b->written);
	BUG_ON(atomic_xchg(&b->io, 1) != -1);

	cancel_delayed_work_sync(&b->work);
	b->expires = jiffies;

	btree_bio_init(b);
	b->bio.bi_rw	       |= READ_SYNC;
	b->bio.bi_size		= KEY_SIZE(&b->key) << 9;
	b->bio.bi_end_io	= btree_read_endio;
	b->bio.bi_private	= b;

	bio_map(&b->bio, b->data);

	if (bio_submit_split(&b->bio, &b->io, b->c->bio_split)) {
		PREPARE_DELAYED_WORK(&b->work, btree_bio_resubmit);
		BUG_ON(!schedule_work(&b->work.work));
	}
	pr_debug("%s", pbtree(b));
}

static void btree_write_endio(struct bio *bio, int error)
{
	int n;
	struct bio_vec *bv;
	struct btree_write *w = bio->bi_private;
	struct btree *b = w->b;
	bio_put(bio);

	cache_set_err_on(error, b->c, "writing index");

	if (!atomic_dec_and_test(&b->io))
		return;

	pr_latency(w->wait_time, "btree write");

	if (!w->nofree)
		__bio_for_each_segment(bv, &b->bio, n, 0)
			__free_page(bv->bv_page);

	closure_run_wait(&w->wait, bcache_wq);
	if (w->owner)
		closure_put(w->owner, bcache_wq);

	if (w->prio_blocked &&
	    !atomic_sub_return(w->prio_blocked, &b->c->prio_blocked))
		closure_run_wait(&b->c->bucket_wait, bcache_wq);

	if (w->journal) {
		atomic_dec_bug(w->journal);
		w->journal = NULL;
		closure_run_wait(&b->c->journal.wait, bcache_wq);
		if (journal_full(b->c))
			schedule_work(&b->c->journal.work);
	}

	memset(w, 0, sizeof(struct btree_write));
	atomic_set(&b->io, -1);
	closure_run_wait(&b->wait, bcache_wq);

	if (b->write) {
		long delay = max_t(long, 0, b->expires - jiffies);
		schedule_delayed_work(&b->work, delay);
	}
}

int __btree_write(struct btree *b)
{
	int j;
	struct bio_vec *bv;
	struct btree_write *w;
	struct bset *i = write_block(b);
	void *base = (void *) ((unsigned long) i & ~(PAGE_SIZE - 1));

	if (atomic_cmpxchg(&b->io, -1, 1) != -1)
		return -1;

	/* XXX: get rid of this since we have b->io? */
	w = xchg(&b->write, NULL);
	if (!w) {
		/* We raced, first saw b->write before the write was
		 * started, but the write has already completed.
		 */
		atomic_set(&b->io, -1);
		return -1;
	}

	__cancel_delayed_work(&b->work);

	pr_latency(w->wait_time, "btree write");
	set_wait(w);
	check_key_order(b, i);
	BUG_ON(b->written && !i->keys);

	i->version	= BCACHE_BSET_VERSION;
	i->csum		= btree_csum_set(b, i);

	btree_bio_init(b);
	b->bio.bi_rw	       |= REQ_WRITE|REQ_SYNC;
	b->bio.bi_size		= set_blocks(i, b->c) * block_bytes(b->c);
	b->bio.bi_end_io	= btree_write_endio;
	b->bio.bi_private	= w;

	bio_map(&b->bio, i);
	if (bio_alloc_pages(&b->bio, GFP_NOIO))
		goto err;

	bio_for_each_segment(bv, &b->bio, j)
		memcpy(page_address(bv->bv_page),
		       base + j * PAGE_SIZE, PAGE_SIZE);

	if (bio_submit_split(&b->bio, &b->io, b->c->bio_split)) {
		cancel_delayed_work_sync(&b->work);
		PREPARE_DELAYED_WORK(&b->work, btree_bio_resubmit);
		BUG_ON(!schedule_work(&b->work.work));
	}

	if (0) {
		struct closure wait;
err:		closure_init_stack(&wait);

		if (current->bio_list) {
			atomic_set(&b->io, -1);
			b->write = w;
			return -1;
		}

		w->nofree = true;
		bio_map(&b->bio, i);

		BUG_ON(!closure_wait(&w->wait, &wait));
		bio_submit_split(&b->bio, &b->io, b->c->bio_split);
		closure_sync(&wait);
	}

	if (b->written) {
		atomic_long_inc(&b->c->btree_write_count);
		atomic_long_add(i->keys, &b->c->keys_write_count);
	}

	pr_debug("%s block %i keys %i", pbtree(b), b->written, i->keys);

	BUG_ON(b->sets[b->nsets] != write_block(b));
	smp_wmb();

	b->written += set_blocks(i, b->c);
	atomic_long_add(set_blocks(i, b->c) * b->c->sb.block_size,
			&PTR_CACHE(b->c, &b->key, 0)->btree_sectors_written);
	return 0;
}

static void btree_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);

	pr_latency(b->expires, "btree_write_work");

	smp_mb(); /* between unlock/requeue from rw_unlock */
	if (down_read_trylock(&b->lock))
		rw_unlock(false, b);
}

void btree_write(struct btree *b, bool now, struct btree_op *op)
{
	struct bset *i = write_block(b);

	BUG_ON(!now && !op);
	BUG_ON(b->written &&
	       (b->written >= btree_blocks(b) ||
		i->seq != b->data->seq ||
		!i->keys));

	if (!b->write) {
		b->write = &b->writes[b->next];
		b->write->b = b;
		b->write->journal = NULL;
		b->next ^= 1;

		PREPARE_DELAYED_WORK(&b->work, btree_write_work);
		b->expires = jiffies + msecs_to_jiffies(30000);
	}

	b->write->prio_blocked += b->prio_blocked;
	b->prio_blocked = 0;

	if (op && op->journal && !b->level) {
		if (b->write->journal &&
		    journal_pin_cmp(b->c, b->write, op)) {
			atomic_dec_bug(b->write->journal);
			b->write->journal = NULL;
		}

		if (!b->write->journal) {
			b->write->journal = op->journal;
			atomic_inc(b->write->journal);
		}
	}

	/* Force write if set is too big */
	if (now ||
	    b->level ||
	    set_bytes(i) > PAGE_SIZE - 48) {
#ifdef CONFIG_BCACHE_LATENCY_DEBUG
		if (!b->write->wait_time)
			set_wait(b->write);
#endif
		if (op && now) {
			/* Must wait on multiple writes */
			BUG_ON(b->write->owner);
			b->write->owner = &op->cl;
			closure_get(&op->cl);
		}

		if (__btree_write(b)) {
			b->expires = jiffies;
			if (b->work.timer.function)
				mod_timer_pending(&b->work.timer, b->expires);
		}
	}
	BUG_ON(!b->written);
}

/* Btree cache */

#define btree_reserve(c)	((c->root ? c->root->level : 1) * 4 + 4)

static void free_bucket(struct btree *b)
{
	lockdep_assert_held(&b->c->bucket_lock);
	BUG_ON(b->write);

	if (b->data)
		list_move_tail(&b->lru, &b->c->lru);
	else
		list_move_tail(&b->lru, &b->c->freed);

	b->written = 0;
	b->nsets = 0;
	for (int i = 0; i < 4; i++)
		b->tree[i].size = 0;
	atomic_set(&b->nread, 0);
	__cancel_delayed_work(&b->work);

	b->key.ptr[0] = 0;
	hlist_del_init_rcu(&b->hash);
}

static int reap_bucket(struct btree *b, struct closure *cl)
{
	lockdep_assert_held(&b->c->bucket_lock);

	if (!down_write_trylock(&b->lock))
		return -1;

	BUG_ON(!b->data);
	if (b->write || atomic_read(&b->io) != -1) {
		if (b->write && time_is_after_jiffies(b->expires))
			b->expires = jiffies;

		if (b->write && cl) {
			spin_unlock(&b->c->bucket_lock);
			__btree_write(b);
			spin_lock(&b->c->bucket_lock);
		}

		rw_unlock_nowrite(true, b);

		if (!cl)
			return -1;

		closure_wait_on_async(&b->wait, bcache_wq, cl,
				      !b->write && atomic_read(&b->io) == -1);
		return -EAGAIN;
	}

	return 0;
}

static int shrink_buckets(struct shrinker *shrink, struct shrink_control *sc)
{
	struct btree *oldest_bucket(struct cache_set *c)
	{
		struct btree *ret = NULL, *b;
		list_for_each_entry(b, &c->lru, lru)
			if (!ret || time_after(ret->jiffies, b->jiffies))
				ret = b;
		return ret;
	}

	struct cache_set *c = container_of(shrink, struct cache_set, shrink);
	struct btree *b;
	int nr = sc->nr_to_scan, ret = 0, reserve = 16, orig;

	spin_lock(&c->bucket_lock);

	orig = nr /= c->btree_pages;
	reserve = btree_reserve(c);

	list_for_each_entry(b, &c->lru, lru)
		ret++;

	ret = max(ret - reserve, 0);

	while (nr && ret && !c->try_harder) {
		b = oldest_bucket(c);
		if (reap_bucket(b, NULL))
			break;

		free_pages((unsigned long) b->data, b->page_order);
		free_pages((unsigned long) b->tree->key, bset_tree_order(b));
		b->data = NULL;
		b->tree->key = NULL;
		free_bucket(b);
		rw_unlock(true, b);
		nr--, ret--;
	}

	spin_unlock(&c->bucket_lock);

	if (orig)
		pr_debug("wanted %i freed %i now %i", orig, orig - nr, ret);
	return ret * c->btree_pages;
}

static struct hlist_head *hash_bucket(struct cache_set *c, struct bkey *k)
{
	return &c->bucket_hash[hash_32(PTR_HASH(c, k), BUCKET_HASH_BITS)];
}

static struct btree *find_bucket(struct cache_set *c, struct bkey *k)
{
	struct hlist_node *cursor;
	struct btree *b;

	rcu_read_lock();
	hlist_for_each_entry_rcu(b, cursor, hash_bucket(c, k), hash)
		if (PTR_HASH(c, &b->key) == PTR_HASH(c, k))
			goto out;
	b = NULL;
out:
	rcu_read_unlock();
	return b;
}

static void reset_bucket(struct btree *b, int level)
{
	atomic_set(&b->nread, 0);
	b->level	= level;
	b->written	= 0;
	b->nsets	= 0;
	for (int i = 0; i < 4; i++)
		b->tree[i].size = 0;

	lock_set_subclass(&b->lock.dep_map, level + 1, _THIS_IP_);
}

static void alloc_bucket_data(struct btree *b, gfp_t gfp)
{
	unsigned pages = KEY_SIZE(&b->key) / PAGE_SECTORS ?: 1;
	b->page_order = ilog2(max(b->c->btree_pages, pages));

	b->data = (void *) __get_free_pages(gfp, b->page_order);
	b->tree->key = (void *) __get_free_pages(gfp, bset_tree_order(b));
}

static struct btree *__alloc_bucket(struct cache_set *c, gfp_t flags)
{
	struct btree *b = kzalloc(sizeof(*b) + sizeof(struct bio_vec) *
				  bucket_pages(c), flags);

	if (b) {
		INIT_LIST_HEAD(&b->lru);
		init_rwsem(&b->lock);
		INIT_DELAYED_WORK(&b->work, NULL);
		b->c = c;
		atomic_set(&b->io, -1);
		b->bio.bi_max_vecs	= bucket_pages(b->c);
		b->bio.bi_io_vec	= b->bio.bi_inline_vecs;
	}
	return b;
}

void free_btree_cache(struct cache_set *c)
{
	struct btree *b;

	if (c->shrink.list.next)
		unregister_shrinker(&c->shrink);

	list_splice(&c->lru, &c->freed);
	while (!list_empty(&c->freed)) {
		b = list_first_entry(&c->freed, struct btree, lru);
		list_del(&b->lru);
		cancel_delayed_work_sync(&b->work);
		free_pages((unsigned long) b->data, b->page_order);
		free_pages((unsigned long) b->tree->key, bset_tree_order(b));
		kfree(b);
	}
}

int alloc_btree_cache(struct cache_set *c)
{
	INIT_WORK(&c->gc_work, btree_gc_work);

	for (int i = 0; i < btree_reserve(c); i++) {
		struct btree *b = __alloc_bucket(c, GFP_KERNEL);
		if (!b)
			return -ENOMEM;

		alloc_bucket_data(b, GFP_KERNEL);
		if (!b->data)
			return -ENOMEM;

		list_move_tail(&b->lru, &c->lru);
	}

	c->shrink.shrink = shrink_buckets;
	c->shrink.seeks = 3;
	register_shrinker(&c->shrink);

	return 0;
}

/* Caller must have locked bucket_lock; always returns with bucket_lock
 * unlocked
 */
static struct btree *alloc_bucket(struct cache_set *c, struct bkey *k,
				  struct closure *cl)
{
	struct btree *init_bucket(struct btree *b)
	{
		if (!find_bucket(c, k)) {
			BUG_ON(atomic_read(&b->io) != -1);

			bkey_copy(&b->key, k);
			list_move(&b->lru, &c->lru);
			hlist_del_init_rcu(&b->hash);
			hlist_add_head_rcu(&b->hash, hash_bucket(c, k));
		} else {
			up_write(&b->lock);
			b = NULL;
		}
		spin_unlock(&c->bucket_lock);
		return b;
	}

	struct btree *b, *i;
	unsigned pages = KEY_SIZE(k) / PAGE_SECTORS;

	lockdep_assert_held(&c->bucket_lock);
	BUG_ON(list_empty(&c->lru));

	b = list_entry(c->lru.prev, struct btree, lru);
	if (pages <= c->btree_pages &&
	    !b->key.ptr[0] &&
	    !reap_bucket(b, NULL))
		return init_bucket(b);

	list_for_each_entry(b, &c->freed, lru)
		if (atomic_read(&b->io) == -1 &&
		    !work_pending(&b->work.work) &&
		    down_write_trylock(&b->lock)) {
			BUG_ON(b->data);
			goto out;
		}

	spin_unlock(&c->bucket_lock);

	b = __alloc_bucket(c, GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!down_write_trylock(&b->lock));

	spin_lock(&c->bucket_lock);
out:
	if (!init_bucket(b))
		return NULL;

	alloc_bucket_data(b, __GFP_NOWARN|GFP_NOIO);
	if (!b->data)
		goto err;

	return b;
err:
	spin_lock(&c->bucket_lock);

	if (b) {
		free_bucket(b);
		rw_unlock(true, b);
	}
retry:
	b = ERR_PTR(-ENOMEM);

	if (pages > c->btree_pages || !cl) {
		spin_unlock(&c->bucket_lock);
		return b;
	}

	if (!c->try_harder || c->try_harder == cl) {
		/* XXX: tracepoint */
		c->try_harder = cl;

		list_for_each_entry_reverse(i, &c->lru, lru) {
			int e = reap_bucket(i, cl);
			if (e == -EAGAIN)
				b = ERR_PTR(-EAGAIN);
			if (!e)
				return init_bucket(i);
		}

		if (b == ERR_PTR(-EAGAIN) &&
		    test_bit(CLOSURE_BLOCK, &cl->flags)) {
			spin_unlock(&c->bucket_lock);
			closure_sync(cl);
			spin_lock(&c->bucket_lock);
			goto retry;
		}
	} else {
		closure_wait_on_async(&c->try_wait, bcache_wq,
				      cl, !c->try_harder);
		b = ERR_PTR(-EAGAIN);
	}

	spin_unlock(&c->bucket_lock);
	return b;
}

struct btree *get_bucket(struct cache_set *c, struct bkey *k,
				int level, struct btree_op *op)
{
	int nread;
	bool write = false;
	struct closure *cl = NULL;
	struct btree *b;

	if (op) {
		cl = &op->cl;
		write = level <= op->lock;
	}

	BUG_ON(level < 0);
retry:
	b = find_bucket(c, k);

	if (!b) {
		spin_lock(&c->bucket_lock);
		b = alloc_bucket(c, k, cl);
		if (!b)
			goto retry;
		if (IS_ERR(b))
			return b;

		reset_bucket(b, level);
		btree_read(b);

		if (!write)
			downgrade_write(&b->lock);
	} else {
		rw_lock(write, b, level);
		if (PTR_HASH(c, &b->key) != PTR_HASH(c, k)) {
			rw_unlock(write, b);
			goto retry;
		}
		BUG_ON(b->level != level);
	}

	b->jiffies = jiffies;

	if (!cl) {
		rw_unlock(write, b);
		return NULL;
	}

	for (int i = 0; i < 4 && b->tree[i].size; i++)
		prefetch(b->tree[i].key);

	nread = closure_wait_on(&b->wait, bcache_wq, &op->cl,
				atomic_read(&b->nread));
	if (nread != 1) {
		rw_unlock(write, b);
		b = ERR_PTR(nread ? -EIO : -EAGAIN);
	} else
		BUG_ON(!b->written);

	return b;
}

/* Btree alloc */

static void btree_free(struct btree *b, struct btree_op *op)
{
	/* The BUG_ON() in get_bucket() implies that we must have a write lock
	 * on parent to free or even invalidate a node
	 */
	BUG_ON(op->lock <= b->level);
	BUG_ON(b == b->c->root);
	pr_debug("bucket %s", pbtree(b));

	spin_lock(&b->c->bucket_lock);

	for (unsigned i = 0; i < KEY_PTRS(&b->key); i++) {
		BUG_ON(atomic_read(&PTR_BUCKET(b->c, &b->key, i)->pin));

		inc_gen(PTR_CACHE(b->c, &b->key, i),
			PTR_BUCKET(b->c, &b->key, i));
	}

	/* This isn't correct, the caller needs to add the wait list
	 * to the wait list for the new bucket's write.
	 */
	if (b->write) {
		BUG_ON(b->write->owner);
		BUG_ON(b->write->prio_blocked);
		closure_run_wait(&b->write->wait, bcache_wq);
		if (b->write->journal)
			atomic_dec_bug(b->write->journal);
		b->write->journal = NULL;
		b->write = NULL;
	}

	unpop_bucket(b->c, &b->key);
	free_bucket(b);
	spin_unlock(&b->c->bucket_lock);
}

struct btree *btree_alloc(struct cache_set *c, int level, struct closure *cl)
{
	BKEY_PADDED(key) k;
	struct btree *b = ERR_PTR(-EAGAIN);
retry:
	spin_lock(&c->bucket_lock);
	if (__pop_bucket_set(c, btree_prio, &k.key, 1, cl))
		goto err_unlock;

	SET_KEY_SIZE(&k.key, c->btree_pages * PAGE_SECTORS);
retry_alloc:
	b = alloc_bucket(c, &k.key, cl);
	if (IS_ERR(b))
		goto err;

	/* A btree pointer may occasionally be invalidated without btree_free()
	 * being called, thus the bucket may potentially be cached while
	 * legitimately free.
	 */
	if (!b) {
		b = find_bucket(c, &k.key);
		/* this is bothersome - but it's probably a harmless race
		 * with gc
		 * XXX: might not be a bad idea to trace this stuff
		 */
		if (!down_write_trylock(&b->lock))
			goto retry;

		if (PTR_HASH(c, &b->key) != PTR_HASH(c, &k.key)) {
			/* belt and suspenders */
			rw_unlock(true, b);
			spin_lock(&c->bucket_lock);
			goto retry_alloc;
		}
	}

	reset_bucket(b, level);
	atomic_set(&b->nread, 1);
	b->jiffies = jiffies;

	bset_init(b, b->data);

	return b;
err:
	spin_lock(&c->bucket_lock);

	unpop_bucket(c, &k.key);
	__bkey_put(c, &k.key);
err_unlock:
	spin_unlock(&c->bucket_lock);
	return b;
}

/* Garbage collection */

void __btree_mark_key(struct cache_set *c, int level, struct bkey *k)
{
	if (!k->key)
		return;

	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bucket *g = PTR_BUCKET(c, k, i);

		if (gen_after(g->gc_gen, PTR_GEN(k, i)))
			g->gc_gen = PTR_GEN(k, i);

		if (ptr_stale(c, k, i))
			continue;

		cache_bug_on(level
			     ? g->mark && g->mark != GC_MARK_BTREE
			     : g->mark < GC_MARK_DIRTY, c,
			     "inconsistent pointers: mark = %i, "
			     "level = %i", g->mark, level);

		if (level)
			g->mark = GC_MARK_BTREE;
		else if (KEY_DIRTY(k))
			g->mark = GC_MARK_DIRTY;
		else if (g->mark >= 0 &&
			 ((int) g->mark) + KEY_SIZE(k) < SHRT_MAX)
			g->mark += KEY_SIZE(k);
	}
}

#define btree_mark_key(b, k)	__btree_mark_key(b->c, b->level, k)

static int btree_gc_mark(struct btree *b, size_t *keys, struct gc_stat *gc)
{
	uint8_t ret = 0;
	struct bset *i;
	struct bkey *k;

	for_each_sorted_set(b, i)
		btree_bug_on(i->keys && bkey_cmp(&b->key, last_key(i)) < 0,
			     b, "found short btree key in gc");

	gc->nodes++;
	for_each_key_filter(b, k, ptr_bad) {
		*keys += bkey_u64s(k);

		gc->key_bytes += bkey_u64s(k);
		gc->nkeys++;

		gc->data += KEY_SIZE(k);
		if (KEY_DIRTY(k))
			gc->dirty += KEY_SIZE(k);
	}

	for_each_key_filter(b, k, ptr_invalid) {
		for (unsigned i = 0; i < KEY_PTRS(k); i++) {
			ret = max(ret, ptr_stale(b->c, k, i));

			btree_bug_on(gen_after(PTR_BUCKET(b->c, k, i)->last_gc,
					       PTR_GEN(k, i)),
				     b, "found old gen in gc");
		}

		btree_mark_key(b, k);
	}

	return ret;
}

static int btree_gc_recurse(struct btree *b, struct btree_op *op,
			    struct closure *writes, struct gc_stat *gc)
{
	struct btree *alloc(struct btree *r, struct bkey *k)
	{
		/* can't sleep in pop_bucket(), as we block priorities from
		 * being written
		 */
		struct btree *n = btree_alloc(r->c, r->level, NULL);

		if (!IS_ERR_OR_NULL(n)) {
			btree_sort(r, 0, n->data);
			bkey_copy_key(&n->key, &r->key);
			swap(r, n);

			memcpy(k->ptr, r->key.ptr,
			       sizeof(uint64_t) * KEY_PTRS(&r->key));

			__bkey_put(b->c, &r->key);
			atomic_inc(&b->c->prio_blocked);
			b->prio_blocked++;

			btree_free(n, op);
			rw_unlock(true, n);
		}

		return r;
	}

	void write(struct btree *r)
	{
		if (!r->written)
			btree_write(r, true, op);
		else if (r->write) {
			BUG_ON(r->write->owner);
			r->write->owner = writes;
			closure_get(writes);

			btree_write(r, true, NULL);
		}

		rw_unlock(true, r);
	}

	int ret = 0, stale;
	size_t keys, pkeys = 0;
	struct btree *r, *p = NULL;
	struct bkey *k;

	while ((k = next_recurse_key(b, &b->c->gc_done))) {
		r = get_bucket(b->c, k, b->level - 1, op);
		if (IS_ERR(r)) {
			ret = PTR_ERR(r);
			break;
		}

		keys = 0;
		stale = btree_gc_mark(r, &keys, gc);

		if (!b->written &&
		    (r->level || stale > 10))
			r = alloc(r, k);

		if (r->level)
			ret = btree_gc_recurse(r, op, writes, gc);

		if (ret) {
			write(r);
			break;
		}

		pkeys = __set_blocks(b->data, pkeys + keys, b->c);
		if (p && pkeys < (btree_blocks(b) * 2) / 3) {
			if (r->written)
				r = alloc(r, k);

			if (!r->written) {
				pr_debug("coalescing");
				r->nsets += p->nsets + 1;
				memcpy(&r->sets[1],
				       &p->sets[0],
				       sizeof(void *) * (p->nsets + 1));
				btree_sort(r, 0, NULL);

				btree_free(p, op);
				rw_unlock(true, p);

				p = NULL;
				keys = r->data->keys;
				gc->nodes--;
			}
		}

		if (p)
			write(p);

		lock_set_subclass(&r->lock.dep_map, 0, _THIS_IP_);
		p = r;
		pkeys = keys;
		bkey_copy_key(&b->c->gc_done, k);

		/* When we've got incremental GC working, we'll want to do
		 * if (should_resched())
		 *	return -EAGAIN;
		 */
		cond_resched();
#if 0
		if (need_resched()) {
			ret = -EAGAIN;
			break;
		}
#endif
	}

	if (p)
		write(p);

	/* Might have freed some children, must remove their keys */
	btree_sort(b, 0, NULL);

	return ret;
}

static int btree_gc_root(struct btree *b, struct btree_op *op,
			 struct closure *writes, struct gc_stat *gc)
{
	struct btree *n = NULL;
	size_t keys = 0;
	int ret = 0, stale = btree_gc_mark(b, &keys, gc);

	if (b->level || stale > 10)
		n = btree_alloc(b->c, b->level, &op->cl);

	if (!IS_ERR_OR_NULL(n)) {
		swap(b, n);
		btree_sort(n, 0, b->data);
		bkey_copy_key(&b->key, &n->key);
	}

	if (b->level)
		ret = btree_gc_recurse(b, op, writes, gc);

	if (!b->written || b->write) {
		atomic_inc(&b->c->prio_blocked);
		b->prio_blocked++;
		btree_write(b, true, n ? op : NULL);
	}

	if (!IS_ERR_OR_NULL(n)) {
		closure_sync(&op->cl);
		set_new_root(b);
		btree_free(n, op);
		rw_unlock(true, b);
	}

	return ret;
}

size_t btree_gc_finish(struct cache_set *c)
{
	void mark_key(struct bkey *k)
	{
		for (unsigned i = 0; i < KEY_PTRS(k); i++)
			PTR_BUCKET(c, k, i)->mark = GC_MARK_BTREE;
	}

	size_t available = 0;
	struct bucket *b;
	struct cache *ca;
	uint64_t *i;

	spin_lock(&c->bucket_lock);

	set_gc_sectors(c);
	c->gc_mark_valid = 1;
	c->need_gc	= 0;
	c->min_prio	= initial_prio;

	if (c->root)
		mark_key(&c->root->key);

	mark_key(&c->uuid_bucket);

	for_each_cache(ca, c) {
		ca->invalidate_needs_gc = 0;

		for (i = ca->sb.d; i < ca->sb.d + ca->sb.keys; i++)
			ca->buckets[*i].mark = GC_MARK_BTREE;

		for (i = ca->prio_buckets;
		     i < ca->prio_buckets + prio_buckets(ca) * 2; i++)
			ca->buckets[*i].mark = GC_MARK_BTREE;

		for_each_bucket(b, ca) {
			cache_bug_on(c->journal.cur &&
				     gen_after(b->last_gc, b->gc_gen), c,
				     "found old gen in gc");

			b->last_gc	= b->gc_gen;
			b->gc_gen	= b->gen;
			c->need_gc	= max(c->need_gc, bucket_gc_gen(b));

			if (!atomic_read(&b->pin) &&
			    b->mark >= 0) {
				available++;
				if (!b->mark)
					bucket_add_unused(ca, b);
			}

			if (b->prio)
				c->min_prio = min(c->min_prio, b->prio);
		}
	}

	spin_unlock(&c->bucket_lock);
	return available;
}

static void btree_gc(struct cache_set *c)
{
	int ret;
	unsigned long available, time = jiffies;
	struct bucket *b;
	struct cache *ca;

	struct gc_stat stats;
	struct closure writes;
	struct btree_op op;

	memset(&stats, 0, sizeof(struct gc_stat));
	closure_init_stack(&writes);
	btree_op_init_stack(&op);
	op.lock = SHRT_MAX;

	lockdep_assert_held(&c->gc_lock);
	blktrace_msg_all(c, "Starting gc");

	spin_lock(&c->bucket_lock);
	for_each_cache(ca, c)
		free_some_buckets(ca);

	if (c->gc_mark_valid) {
		c->gc_mark_valid = 0;
		c->gc_done = ZERO_KEY;

		for_each_cache(ca, c)
			for_each_bucket(b, ca)
				if (!atomic_read(&b->pin))
					b->mark = 0;
	}
	spin_unlock(&c->bucket_lock);

	ret = btree_root(gc_root, c, &op, &writes, &stats);
	closure_sync(&op.cl);
	closure_sync(&writes);

	if (ret) {
		blktrace_msg_all(c, "Stopped gc");
		printk(KERN_WARNING "bcache: gc failed!\n");
		queue_work(bcache_wq, &c->gc_work);
		goto out;
	}

	/* Possibly wait for new UUIDs or whatever to hit disk */
	bcache_journal_wait(c, &op.cl);
	closure_sync(&op.cl);

	available = btree_gc_finish(c);

	time = jiffies_to_msecs(jiffies - time);

	stats.count	= c->gc_stats.count + 1;
	stats.ms_max	= max_t(unsigned, c->gc_stats.ms_max, time);
	stats.last	= get_seconds();

	stats.key_bytes *= sizeof(uint64_t);
	stats.dirty	<<= 9;
	stats.data	<<= 9;
	stats.in_use	= (c->nbuckets - available) * 100 / c->nbuckets;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));
	blktrace_msg_all(c, "Finished gc");
out:
	closure_run_wait(&c->bucket_wait, bcache_wq);
}

static void btree_gc_work(struct work_struct *w)
{
	struct cache_set *c = container_of(w, struct cache_set, gc_work);
	if (!mutex_trylock(&c->gc_lock))
		return;

	btree_gc(c);
	mutex_unlock(&c->gc_lock);
}

/* Initial partial gc */

int btree_check(struct btree *b, struct btree_op *op)
{
	int ret;
	struct bkey *k;

	for_each_key_filter(b, k, ptr_invalid) {
		for (unsigned i = 0; i < KEY_PTRS(k); i++) {
			struct bucket *g = PTR_BUCKET(b->c, k, i);

			if (!ptr_stale(b->c, k, i)) {
				g->gen = PTR_GEN(k, i);

				if (b->level)
					g->prio = btree_prio;
				else if (g->prio == btree_prio)
					g->prio = initial_prio;
			}
		}

		btree_mark_key(b, k);
	}

	if (b->level) {
		k = next_recurse_key(b, &ZERO_KEY);

		while (k) {
			struct bkey *p = next_recurse_key(b, k);
			if (p)
				get_bucket(b->c, p, b->level - 1, NULL);

			ret = btree(check, k, b, op);
			if (ret)
				return ret;

			k = p;
		}
	}

	return 0;
}

/* Btree insertion */

static void shift_keys(struct bset *i, struct bkey *where, struct bkey *insert)
{
	unsigned n = bkey_u64s(insert);
	uint64_t *src = i->d + i->keys;
	uint64_t *dst = i->d + i->keys + n;

	while (src > (uint64_t *) where) {
		src -= 2;
		dst -= 2;

		dst[0] = src[0];
		dst[1] = src[1];
	}

	i->keys += n;
	bkey_copy(where, insert);
}

static bool check_old_keys(struct btree *b, struct bkey *k,
			   struct btree_iter *iter, struct btree_op *op)
{
	void rebuild(struct bkey *j)
	{
		for (int i = 0; i < b->nsets; i++)
			if (j < end(b->sets[i])) {
				bset_build_tree_noalloc(b, i);
				return;
			}
	}

	bool overwrote = false;
	struct bset *w = write_block(b);

	while (1) {
		struct bkey *j = btree_iter_next(iter);
		if (!j || bkey_cmp(k, &START_KEY(j)) <= 0)
			break;

		if (op->insert_type == INSERT_READ &&
		    !ptr_bad(b, j)) {
			/* Should split this key in two if necessary */
			if (bkey_cmp(&START_KEY(j), &START_KEY(k)) > 0)
				cut_back(&START_KEY(j), k);
			else if (bkey_cmp(j, k) < 0)
				cut_front(j, k);
			else {
				atomic_inc(&op->d->cache_miss_collisions);
				return true;
			}

			BUG_ON(!KEY_SIZE(k));
			continue;
		}

		if (op->insert_type == INSERT_UNDIRTY) {
			if (j->header != (k->header | PTR_DIRTY_BIT) ||
			    memcmp(&j->key, &k->key, bkey_bytes(k) - 8))
				goto wb_failed;

			if (j < w->start)
				cut_front(k, j);
			else
				cut_back(&START_KEY(k), j);
			atomic_long_inc(&b->c->writeback_keys_done);
			return false;
		}

		if (bkey_cmp(k, j) < 0) {
			if (bkey_cmp(&START_KEY(k), &START_KEY(j)) > 0) {
				struct bkey *m = j;

				if (j < w->start) {
					m = bset_search(b, b->nsets, k);
					shift_keys(w, m, j);

					cut_back(&START_KEY(k), j);
					rebuild(j);
				} else {
					BKEY_PADDED(key) temp;
					bkey_copy(&temp.key, j);
					shift_keys(w, m, &temp.key);
					m = next(j);

					cut_back(&START_KEY(k), j);
				}

				cut_front(k, m);
				return false;
			}

			cut_front(k, j);
		} else {
			if (j >= w->start)
				__cut_back(&START_KEY(k), j);
			else if (!bkey_cmp(k, j) &&
				 bkey_cmp(&START_KEY(k), &START_KEY(j)) <= 0)
				/* Completely overwrote, so we don't have to
				 * invalidate the binary search tree */
				cut_front(k, j);
			else {
				__cut_back(&START_KEY(k), j);
				rebuild(j);
			}
		}

		overwrote = true;
	}

	if (op->insert_type == INSERT_UNDIRTY) {
wb_failed:	atomic_long_inc(&b->c->writeback_keys_failed);
		return true;
	}

	if (!KEY_PTRS(k) && !overwrote)
		return true;

	return false;
}

bool btree_insert_keys(struct btree *b, struct btree_op *op)
{
	/* If a read generates a cache miss, and a write to the same location
	 * finishes before the new data is added to the cache, the write will
	 * be overwritten with stale data. We can catch this by never
	 * overwriting good data if it came from a read.
	 */
	bool ret = false;
	struct bset *i = write_block(b);
	struct bkey *k, *m;

	while ((k = keylist_pop(&op->keys))) {
		const char *status = "insert";
		unsigned oldsize = count_data(b);

		BUG_ON(b->level && !KEY_PTRS(k));
		BUG_ON(!b->level && !k->key);
		BUG_ON(!b->level && op->insert_type != INSERT_REPLAY &&
		       (!KEY_DIRTY(k) ==
			(op->insert_type == INSERT_WRITEBACK)));

		bkey_put(b->c, k, op->insert_type, b->level);

		if (!b->level) {
			struct btree_iter iter;
			m = btree_iter_init(b, &iter, &START_KEY(k));

			BUG_ON(!m || m < i->start);

			if (check_old_keys(b, k, &iter, op))
				continue;

			while (m != end(i) && bkey_cmp(k, &START_KEY(m)) > 0)
				m = next(m);

			if (m != i->start) {
				m = prev(m);

				status = "overwrote back";
				if (KEY_PTRS(m) == KEY_PTRS(k) && !KEY_SIZE(m))
					goto copy;

				/* m is in the tree, if we merge we're done */

				status = "back merging";
				if (bkey_try_merge(b, m, k))
					goto merged;

				m = next(m);
			}

			if (m != end(i)) {
				status = "overwrote front";
				if (KEY_PTRS(m) == KEY_PTRS(k) && !KEY_SIZE(m))
					goto copy;

				status = "front merge";
				if (bkey_try_merge(b, k, m))
					goto copy;
			}
		} else
			m = bset_search(b, b->nsets, k);

		shift_keys(i, m, k);
copy:		bkey_copy(m, k);
merged:		ret = true;

		check_key_order_msg(b, i, "%s for %s at %s: %s", status,
				    insert_type(op), pbtree(b), pkey(k));
		BUG_ON(count_data(b) < oldsize);

		if (b->level && !k->key)
			b->prio_blocked++;

		pr_debug("%s for %s at %s: %s", status,
			 insert_type(op), pbtree(b), pkey(k));
	}

	return ret;
}

static int btree_split(struct btree *b, struct btree_op *op)
{
	bool split, root = b == b->c->root;
	struct btree *n1, *n2 = NULL, *n3 = NULL;

	n1 = btree_alloc(b->c, b->level, &op->cl);
	if (IS_ERR(n1))
		goto err;

	btree_sort(b, 0, n1->data);
	bkey_copy_key(&n1->key, &b->key);

	split = set_blocks(n1->data, n1->c) > (btree_blocks(b) * 4) / 5;
	pr_debug("%ssplitting at %s keys %i", split ? "" : "not ",
		 pbtree(b), n1->data->keys);

	if (split) {
		n2 = btree_alloc(b->c, b->level, &op->cl);
		if (IS_ERR(n2))
			goto err_free1;

		if (root) {
			n3 = btree_alloc(b->c, b->level + 1, &op->cl);
			if (IS_ERR(n3))
				goto err_free2;
		}

		btree_insert_keys(n1, op);

		n2->data->keys = (n1->data->keys * 2) / 5;

		while (!KEY_IS_HEADER(node(n1->data, n1->data->keys
					   - n2->data->keys)))
			n2->data->keys++;

		n1->data->keys -= n2->data->keys;

		memcpy(n2->data->start,
		       end(n1->data),
		       n2->data->keys * sizeof(uint64_t));

		bkey_copy_key(&n1->key, last_key(n1->data));
		bkey_copy_key(&n2->key, &b->key);

		keylist_add(&op->keys, &n2->key);
		btree_write(n2, true, op);
		rw_unlock(true, n2);
	} else
		btree_insert_keys(n1, op);

	keylist_add(&op->keys, &n1->key);
	btree_write(n1, true, op);

	if (n3) {
		bkey_copy_key(&n3->key, &MAX_KEY);
		btree_insert_keys(n3, op);
		btree_write(n3, true, op);

		closure_sync(&op->cl);
		set_new_root(n3);
		rw_unlock(true, n3);
	} else if (root) {
		op->keys.top = op->keys.bottom;
		closure_sync(&op->cl);
		set_new_root(n1);
	} else {
		bkey_copy(op->keys.top, &b->key);
		bkey_copy_key(op->keys.top, &ZERO_KEY);

		for (unsigned i = 0; i < KEY_PTRS(&b->key); i++) {
			uint8_t g = PTR_BUCKET(b->c, &b->key, i)->gen + 1;

			SET_PTR_GEN(op->keys.top, i, g);
		}

		keylist_push(&op->keys);
		closure_sync(&op->cl);
		atomic_inc(&b->c->prio_blocked);
	}

	rw_unlock(true, n1);
	btree_free(b, op);

	return 0;
err_free2:
	__bkey_put(n2->c, &n2->key);
	btree_free(n2, op);
	rw_unlock(true, n2);
err_free1:
	__bkey_put(n1->c, &n1->key);
	btree_free(n1, op);
	rw_unlock(true, n1);
err:
	if (n3 == ERR_PTR(-EAGAIN) ||
	    n2 == ERR_PTR(-EAGAIN) ||
	    n1 == ERR_PTR(-EAGAIN))
		return -EAGAIN;

	printk(KERN_WARNING "bcache: couldn't split");
	return -ENOMEM;
}

static int btree_insert_recurse(struct btree *b, struct btree_op *op,
				struct keylist *stack_keys)
{
	if (b->level) {
		int ret;
		struct bkey *insert = op->keys.bottom;
		struct bkey *k = next_recurse_key(b, &START_KEY(insert));

		if (!k) {
			btree_bug(b, "no key to recurse on at level %i/%i",
				  b->level, b->c->root->level);

			op->keys.top = op->keys.bottom;
			return -EIO;
		}

		if (bkey_cmp(insert, k) > 0) {
			if (op->insert_type == INSERT_UNDIRTY) {
				op->keys.top = op->keys.bottom;
				return 0;
			}

			for (unsigned i = 0; i < KEY_PTRS(insert); i++)
				atomic_inc(&PTR_BUCKET(b->c, insert, i)->pin);

			bkey_copy(stack_keys->top, insert);

			cut_back(k, insert);
			cut_front(k, stack_keys->top);

			keylist_push(stack_keys);
		}

		ret = btree(insert_recurse, k, b, op, stack_keys);
		if (ret)
			return ret;
	}

	if (!keylist_empty(&op->keys)) {
		BUG_ON(!current_is_writer(&b->lock));

		if (should_split(b)) {
			if (op->lock <= b->c->root->level) {
				BUG_ON(b->level);
				op->lock = b->c->root->level + 1;
				return -EINTR;
			}
			return btree_split(b, op);
		}

		if (write_block(b) != b->sets[b->nsets]) {
			bset_build_tree(b, b->nsets);
			btree_sort_lazy(b);
			bset_init(b, write_block(b));
		}

		if (btree_insert_keys(b, op))
			btree_write(b, false, op);
	}

	return 0;
}

int btree_insert(struct btree_op *op, struct cache_set *c)
{
	int ret = 0;
	struct cache *ca;
	struct keylist stack_keys;

	set_bit(CLOSURE_BLOCK, &op->cl.flags);

	BUG_ON(keylist_empty(&op->keys));
	keylist_copy(&stack_keys, &op->keys);
	keylist_init(&op->keys);

	while (c->need_gc > MAX_NEED_GC) {
		mutex_lock(&c->gc_lock);

		if (c->need_gc > MAX_NEED_GC)
			btree_gc(c);

		mutex_unlock(&c->gc_lock);
	}

	for_each_cache(ca, c)
		while (ca->need_save_prio > MAX_SAVE_PRIO) {
			spin_lock(&c->bucket_lock);
			free_some_buckets(ca);
			spin_unlock(&c->bucket_lock);

			closure_wait_on(&c->bucket_wait, bcache_wq, &op->cl,
					ca->need_save_prio <= MAX_SAVE_PRIO ||
					can_save_prios(ca));
		}

	while (!keylist_empty(&stack_keys) ||
	       !keylist_empty(&op->keys)) {
		if (keylist_empty(&op->keys)) {
			keylist_add(&op->keys, keylist_pop(&stack_keys));
			op->lock = 0;
		}

		ret = btree_root(insert_recurse, c, op, &stack_keys);

		if (ret == -EAGAIN) {
			ret = 0;
			closure_sync(&op->cl);
		} else if (ret) {
			struct bkey *k;

			printk(KERN_WARNING "bcache: error %i trying to "
			       "insert key for %s\n", ret, insert_type(op));

			while ((k = keylist_pop(&stack_keys) ?:
				    keylist_pop(&op->keys)))
				bkey_put(c, k, op->insert_type, 0);
		}
	}

	keylist_free(&stack_keys);

	if (op->journal)
		atomic_dec_bug(op->journal);
	op->journal = NULL;
	return ret;
}

void set_new_root(struct btree *b)
{
	BUG_ON(!b->written);
	BUG_ON(!current_is_writer(&b->c->root->lock));

	for (unsigned i = 0; i < KEY_PTRS(&b->key); i++)
		BUG_ON(PTR_BUCKET(b->c, &b->key, i)->prio != btree_prio);

	spin_lock(&b->c->bucket_lock);
	list_del_init(&b->lru);
	spin_unlock(&b->c->bucket_lock);

	b->c->root = b;
	__bkey_put(b->c, &b->key);

	bcache_journal_meta(b->c, NULL);
	pr_debug("%s for %pf", pbtree(b), __builtin_return_address(0));
}

/* Cache lookup */

static struct bio *cache_hit(struct btree *b, struct bio *bio,
			     struct bkey *k, struct btree_op *op)
{
	sector_t sector = bio->bi_sector;
	unsigned sectors = k->key - sector;
	struct bio *ret;
	struct block_device *bdev;

	if (keylist_realloc(&op->keys, 1))
		return ERR_PTR(-ENOMEM);

	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bucket *g = PTR_BUCKET(b->c, k, i);

		atomic_inc(&g->pin);
		smp_mb__after_atomic_inc();

		if (ptr_stale(b->c, k, i)) {
			atomic_dec_bug(&g->pin);
			continue;
		}

		/* For multiple cache devices, copy only the pointer we're
		 * actually reading from
		 */
		bkey_copy_single_ptr(op->keys.top, k, i);
		BUG_ON(KEY_PTRS(op->keys.top) != 1);

		bdev = PTR_CACHE(b->c, k, i)->bdev;
		sector += KEY_SIZE(k) - k->key + PTR_OFFSET(k, i);
		sectors = min(sectors, __bio_max_sectors(bio, bdev, sector));

		ret = bio_split_get(bio, sectors, b->c);
		if (!ret) {
			atomic_dec_bug(&g->pin);
			return ERR_PTR(-ENOMEM);
		}

		g->prio = initial_prio;
		/* * (cache_hit_seek + cache_hit_priority
		 * bio_sectors(bio) / c->sb.bucket_size)
		 / (cache_hit_seek + cache_hit_priority);*/

		pr_debug("cache hit of %i sectors from %llu, need %i sectors",
			 bio_sectors(ret), (uint64_t) ret->bi_sector,
			 ret == bio ? 0 : bio_sectors(bio));

		SET_PTR_OFFSET(op->keys.top, 0, sector);

		ret->bi_end_io = cache_read_endio;

		submit_bbio(ret, b->c, op->keys.top, 0);
		keylist_push(&op->keys);

		return ret;
	}

	return NULL;
}

#define SEARCH(op, bio) KEY((op)->d->id, (bio)->bi_sector, 0)

static int btree_search_leaf(struct btree *b, struct btree_op *op,
			     struct bio *bio, uint64_t *reada)
{
	struct btree_iter iter;
	btree_iter_init(b, &iter, &SEARCH(op, bio));

	while (1) {
		struct bkey *k = btree_iter_next(&iter);
		if (!k || KEY_DEV(k) != op->d->id)
			return 0;

		if (ptr_bad(b, k))
			continue;

		if (bio_end(bio) <= KEY_START(k)) {
			*reada = min(*reada, KEY_START(k));
			return 0;
		}

		while (bio->bi_sector < KEY_START(k)) {
			int sectors = min_t(int, bio_max_sectors(bio),
					    KEY_START(k) - bio->bi_sector);

			struct bio *n = bio_split_get(bio, sectors, b->c);
			if (!n)
				return -ENOMEM;

			BUG_ON(n == bio);
			op->cache_miss = true;
			generic_make_request(n);
		}

		pr_debug("%s", pkey(k));

		do {
			struct bio *n = cache_hit(b, bio, k, op);
			if (!n)
				break;
			if (IS_ERR(n))
				return -ENOMEM;

			if (n == bio) {
				op->cache_hit = true;
				return 0;
			}
		} while (bio->bi_sector < k->key);
	}
}

int btree_search_recurse(struct btree *b, struct btree_op *op,
			 struct bio *bio, uint64_t *reada)
{
	int ret = -1;
	struct bkey search = SEARCH(op, bio), *k = &search;

	pr_debug("at %s searching for %llu", pbtree(b), search.key);

	if (!b->level)
		return btree_search_leaf(b, op, bio, reada);

	while ((k = next_recurse_key(b, k))) {
		ret = btree(search_recurse, k, b, op, bio, reada);

		if (ret ||
		    op->cache_hit ||
		    bkey_cmp(k, &KEY(op->d->id, bio_end(bio), 0)) >= 0)
			return ret;
	}

	btree_bug_on(ret == -1, b, "no key to recurse on at level %i/%i",
		     b->level, b->c->root->level);
	return 0;
}
