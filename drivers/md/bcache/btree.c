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
#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "journal.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/hash.h>
#include <linux/jhash.h>
#include <linux/kthread.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcache.h>

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
 * Plugging?
 *
 * If data write is less than hard sector size of ssd, round up offset in open
 * bucket to the next whole sector
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

#define MAX_NEED_GC		64
#define MAX_SAVE_PRIO		72

#define PTR_DIRTY_BIT		(((uint64_t) 1 << 36))

#define insert_lock(s, b)	((b)->level <= (s)->lock)

/*
 * These macros are for recursing down the btree - they handle the details of
 * locking and looking up nodes in the cache for you. They're best treated as
 * mere syntax when reading code that uses them.
 *
 * op->lock determines whether we take a read or a write lock at a given depth.
 * If you've got a read lock and find that you need a write lock (i.e. you're
 * going to have to split), set op->lock and return -EINTR; btree_root() will
 * call you again and you'll have the correct lock.
 */

/**
 * btree - recurse down the btree on a specified key
 * @fn:		function to call, which will be passed the child node
 * @key:	key to recurse on
 * @b:		parent btree node
 * @op:		pointer to struct btree_op
 */
#define btree(fn, key, b, op, ...)					\
({									\
	int _r, l = (b)->level - 1;					\
	bool _w = l <= (op)->lock;					\
	struct btree *_child = bch_btree_node_get((b)->c, op, key, l,	\
						  _w, b);		\
	if (!IS_ERR(_child)) {						\
		_r = bch_btree_ ## fn(_child, op, ##__VA_ARGS__);	\
		rw_unlock(_w, _child);					\
	} else								\
		_r = PTR_ERR(_child);					\
	_r;								\
})

/**
 * btree_root - call a function on the root of the btree
 * @fn:		function to call, which will be passed the child node
 * @c:		cache set
 * @op:		pointer to struct btree_op
 */
#define btree_root(fn, c, op, ...)					\
({									\
	int _r = -EINTR;						\
	do {								\
		struct btree *_b = (c)->root;				\
		bool _w = insert_lock(op, _b);				\
		rw_lock(_w, _b, _b->level);				\
		if (_b == (c)->root &&					\
		    _w == insert_lock(op, _b)) {			\
			_r = bch_btree_ ## fn(_b, op, ##__VA_ARGS__);	\
		}							\
		rw_unlock(_w, _b);					\
		bch_cannibalize_unlock(c);				\
		if (_r == -EINTR)					\
			schedule();					\
	} while (_r == -EINTR);						\
									\
	finish_wait(&(c)->btree_cache_wait, &(op)->wait);		\
	_r;								\
})

static inline struct bset *write_block(struct btree *b)
{
	return ((void *) btree_bset_first(b)) + b->written * block_bytes(b->c);
}

static void bch_btree_init_next(struct btree *b)
{
	unsigned nsets = b->keys.nsets;

	/* If not a leaf node, always sort */
	if (b->level && b->keys.nsets)
		bch_btree_sort(&b->keys, &b->c->sort);
	else
		bch_btree_sort_lazy(&b->keys, &b->c->sort);

	/*
	 * do verify if there was more than one set initially (i.e. we did a
	 * sort) and we sorted down to a single set:
	 */
	if (nsets && !b->keys.nsets)
		bch_btree_verify(b);

	if (b->written < btree_blocks(b))
		bch_bset_init_next(&b->keys, write_block(b),
				   bset_magic(&b->c->sb));
}

/* Btree IO */

static uint64_t btree_csum_set(struct btree *b, struct bset *i)
{
	uint64_t crc = b->key.ptr[0];
	void *data = (void *) i + 8, *end = bset_bkey_last(i);

	crc = bch_crc64_update(crc, data, end - data);
	return crc ^ 0xffffffffffffffffULL;
}

void bch_btree_node_read_done(struct btree *b)
{
	const char *err = "bad btree header";
	struct bset *i = btree_bset_first(b);
	struct btree_iter *iter;

	iter = mempool_alloc(b->c->fill_iter, GFP_NOIO);
	iter->size = b->c->sb.bucket_size / b->c->sb.block_size;
	iter->used = 0;

#ifdef CONFIG_BCACHE_DEBUG
	iter->b = &b->keys;
#endif

	if (!i->seq)
		goto err;

	for (;
	     b->written < btree_blocks(b) && i->seq == b->keys.set[0].data->seq;
	     i = write_block(b)) {
		err = "unsupported bset version";
		if (i->version > BCACHE_BSET_VERSION)
			goto err;

		err = "bad btree header";
		if (b->written + set_blocks(i, block_bytes(b->c)) >
		    btree_blocks(b))
			goto err;

		err = "bad magic";
		if (i->magic != bset_magic(&b->c->sb))
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
		if (i != b->keys.set[0].data && !i->keys)
			goto err;

		bch_btree_iter_push(iter, i->start, bset_bkey_last(i));

		b->written += set_blocks(i, block_bytes(b->c));
	}

	err = "corrupted btree";
	for (i = write_block(b);
	     bset_sector_offset(&b->keys, i) < KEY_SIZE(&b->key);
	     i = ((void *) i) + block_bytes(b->c))
		if (i->seq == b->keys.set[0].data->seq)
			goto err;

	bch_btree_sort_and_fix_extents(&b->keys, iter, &b->c->sort);

	i = b->keys.set[0].data;
	err = "short btree key";
	if (b->keys.set[0].size &&
	    bkey_cmp(&b->key, &b->keys.set[0].end) < 0)
		goto err;

	if (b->written < btree_blocks(b))
		bch_bset_init_next(&b->keys, write_block(b),
				   bset_magic(&b->c->sb));
out:
	mempool_free(iter, b->c->fill_iter);
	return;
err:
	set_btree_node_io_error(b);
	bch_cache_set_error(b->c, "%s at bucket %zu, block %u, %u keys",
			    err, PTR_BUCKET_NR(b->c, &b->key, 0),
			    bset_block_offset(b, i), i->keys);
	goto out;
}

static void btree_node_read_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

static void bch_btree_node_read(struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bio *bio;
	int ptr;

	trace_bcache_btree_read(b);

	closure_init_stack(&cl);

	ptr = bch_btree_pick_ptr(b->c, &b->key);
	if (ptr < 0) {
		set_btree_node_io_error(b);
		goto err;
	}

	bio = bch_bbio_alloc(b->c);
	bio->bi_rw	= REQ_META|READ_SYNC;
	bio->bi_iter.bi_size = KEY_SIZE(&b->key) << 9;
	bio->bi_end_io	= btree_node_read_endio;
	bio->bi_private	= &cl;

	bch_bio_map(bio, b->keys.set[0].data);

	bch_bbio_prep(bio, b->c, &b->key, ptr);
	closure_bio_submit_punt(bio, &cl, b->c);
	closure_sync(&cl);

	if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
		set_btree_node_io_error(b);

	bch_bbio_free(bio, b->c);

	if (btree_node_io_error(b))
		goto err;

	bch_btree_node_read_done(b);
	bch_time_stats_update(&b->c->btree_read_time, start_time);

	return;
err:
	bch_cache_set_error(b->c, "io error reading bucket %zu",
			    PTR_BUCKET_NR(b->c, &b->key, 0));
}

static void btree_complete_write(struct btree *b, struct btree_write *w)
{
	if (w->prio_blocked &&
	    !atomic_sub_return(w->prio_blocked, &b->c->prio_blocked))
		wake_up_allocators(b->c);

	if (w->journal) {
		atomic_dec_bug(w->journal);
		wake_up(&b->c->journal.wait);
	}

	w->prio_blocked	= 0;
	w->journal	= NULL;
}

static void btree_node_write_unlock(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);

	up(&b->io_mutex);
}

static void __btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);
	struct btree_write *w = btree_prev_write(b);

	bch_bbio_free(b->bio, b->c);
	b->bio = NULL;
	btree_complete_write(b, w);

	if (btree_node_dirty(b))
		schedule_delayed_work(&b->work, 30 * HZ);

	closure_return_with_destructor(cl, btree_node_write_unlock);
}

static void btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);
	struct bio_vec *bv;
	int n;

	bio_for_each_segment_all(bv, b->bio, n)
		__free_page(bv->bv_page);

	__btree_node_write_done(cl);
}

static void btree_node_write_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct btree *b = container_of(cl, struct btree, io);

	if (error)
		set_btree_node_io_error(b);

	bch_bbio_count_io_errors(b->c, bio, error, "writing btree");

	/* This won't free b->bio because we took an extra reference, but it
	 * will free any replica bios from bch_submit_bbio_replicas() */
	bio_put(bio);

	closure_put(cl);
}

static void do_btree_node_write(struct btree *b)
{
	struct closure *cl = &b->io;
	struct bset *i = btree_bset_last(b);
	unsigned long ptrs_to_write[BITS_TO_LONGS(MAX_CACHES_PER_SET)];
	BKEY_PADDED(key) k;
	int n;

	i->version	= BCACHE_BSET_VERSION;
	i->csum		= btree_csum_set(b, i);

	BUG_ON(b->bio);
	b->bio = bch_bbio_alloc(b->c);

	/* Take an extra reference so that the bio_put() in
	 * btree_node_write_endio() doesn't call bio_free() */
	bio_get(b->bio);

	b->bio->bi_end_io	= btree_node_write_endio;
	b->bio->bi_private	= cl;
	b->bio->bi_rw		= REQ_META|WRITE_SYNC|REQ_FUA;
	b->bio->bi_iter.bi_size	= roundup(set_bytes(i), block_bytes(b->c));
	bch_bio_map(b->bio, i);

	memset(ptrs_to_write, 0xFF, sizeof(ptrs_to_write));

	/*
	 * If we're appending to a leaf node, we don't technically need FUA -
	 * this write just needs to be persisted before the next journal write,
	 * which will be marked FLUSH|FUA.
	 *
	 * Similarly if we're writing a new btree root - the pointer is going to
	 * be in the next journal entry.
	 *
	 * But if we're writing a new btree node (that isn't a root) or
	 * appending to a non leaf btree node, we need either FUA or a flush
	 * when we write the parent with the new pointer. FUA is cheaper than a
	 * flush, and writes appending to leaf nodes aren't blocking anything so
	 * just make all btree node writes FUA to keep things sane.
	 */

	bkey_copy(&k.key, &b->key);
	for (n = 0; n < KEY_PTRS(&b->key); n++)
		SET_PTR_OFFSET(&k.key, n, PTR_OFFSET(&k.key, n) +
			       bset_sector_offset(&b->keys, i));

	if (!bio_alloc_pages(b->bio, __GFP_NOWARN|GFP_NOWAIT)) {
		int j;
		struct bio_vec *bv;
		void *base = (void *) ((unsigned long) i & ~(PAGE_SIZE - 1));

		bio_for_each_segment_all(bv, b->bio, j)
			memcpy(page_address(bv->bv_page),
			       base + j * PAGE_SIZE, PAGE_SIZE);


		bch_submit_bbio_replicas(b->bio, b->c, &k.key, ptrs_to_write);
		continue_at(cl, btree_node_write_done, NULL);
	} else {
		b->bio->bi_vcnt = 0;
		bch_bio_map(b->bio, i);

		bch_submit_bbio_replicas(b->bio, b->c, &k.key, ptrs_to_write);

		closure_sync(cl);
		continue_at_nobarrier(cl, __btree_node_write_done, NULL);
	}
}

void __bch_btree_node_write(struct btree *b, struct closure *parent)
{
	struct bset *i = btree_bset_last(b);

	lockdep_assert_held(&b->write_lock);

	trace_bcache_btree_write(b);

	BUG_ON(b->written >= btree_blocks(b));
	BUG_ON(b->written && !i->keys);
	BUG_ON(btree_bset_first(b)->seq != i->seq);
	bch_check_keys(&b->keys, "writing");

	cancel_delayed_work(&b->work);

	/* If caller isn't waiting for write, parent refcount is cache set */
	down(&b->io_mutex);
	closure_init(&b->io, parent ?: &b->c->cl);

	clear_bit(BTREE_NODE_dirty,	 &b->flags);
	change_bit(BTREE_NODE_write_idx, &b->flags);

	do_btree_node_write(b);

	atomic_long_add(set_blocks(i, block_bytes(b->c)) * b->c->sb.block_size,
			&PTR_CACHE(b->c, &b->key, 0)->btree_sectors_written);

	b->written += set_blocks(i, block_bytes(b->c));
}

void bch_btree_node_write(struct btree *b, struct closure *parent)
{
	lockdep_assert_held(&b->lock);

	__bch_btree_node_write(b, parent);
	bch_btree_init_next(b);
}

static void bch_btree_node_write_sync(struct btree *b)
{
	struct closure cl;

	closure_init_stack(&cl);

	mutex_lock(&b->write_lock);
	bch_btree_node_write(b, &cl);
	mutex_unlock(&b->write_lock);

	closure_sync(&cl);
}

static void btree_node_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);

	mutex_lock(&b->write_lock);
	if (btree_node_dirty(b))
		__bch_btree_node_write(b, NULL);
	mutex_unlock(&b->write_lock);
}

/*
 * Write all dirty btree nodes to disk, including roots
 */
void bch_btree_flush(struct cache_set *c)
{
	struct closure cl;
	struct btree *b;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	bool dropped_lock;
	unsigned i;

	closure_init_stack(&cl);

	rcu_read_lock();

	do {
		dropped_lock = false;
		i = 0;
restart:
		tbl = rht_dereference_rcu(c->btree_cache_table.tbl,
					  &c->btree_cache_table);

		for (; i < tbl->size; i++)
			rht_for_each_entry_rcu(b, pos, tbl, i, hash)
				if (btree_node_dirty(b)) {
					rcu_read_unlock();

					mutex_lock(&b->write_lock);
					__bch_btree_node_write(b, &cl);
					mutex_unlock(&b->write_lock);
					dropped_lock = true;

					rcu_read_lock();
					goto restart;
				}
	} while (dropped_lock);

	rcu_read_unlock();

	closure_sync(&cl);
}

/*
 * Btree in memory cache - allocation/freeing
 * mca -> memory cache
 */

#define mca_reserve(c)	(((c->root && c->root->level)		\
			  ? c->root->level : 1) * 8 + 16)
#define mca_can_free(c)						\
	max_t(int, 0, c->btree_cache_used - mca_reserve(c))

static void mca_data_free(struct btree *b)
{
	BUG_ON(b->io_mutex.count != 1);

	bch_btree_keys_free(&b->keys);

	b->c->btree_cache_used--;
	list_move(&b->list, &b->c->btree_cache_freed);
}

static const struct rhashtable_params bch_btree_cache_params = {
	.head_offset	= offsetof(struct btree, hash),
	.key_offset	= offsetof(struct btree, key.ptr[0]),
	.key_len	= sizeof(u64),
	.hashfn		= jhash,
};

static void mca_bucket_free(struct btree *b)
{
	BUG_ON(btree_node_dirty(b));

	rhashtable_remove_fast(&b->c->btree_cache_table, &b->hash,
			       bch_btree_cache_params);

	/* Cause future lookups for this node to fail: */
	b->key.ptr[0] = 0;
	list_move(&b->list, &b->c->btree_cache_freeable);
}

static unsigned btree_order(struct bkey *k)
{
	return ilog2(KEY_SIZE(k) / PAGE_SECTORS ?: 1);
}

static void mca_data_alloc(struct btree *b, struct bkey *k, gfp_t gfp)
{
	if (!bch_btree_keys_alloc(&b->keys,
				  max_t(unsigned,
					ilog2(b->c->btree_pages),
					btree_order(k)),
				  gfp)) {
		b->c->btree_cache_used++;
		list_move(&b->list, &b->c->btree_cache);
	} else {
		list_move(&b->list, &b->c->btree_cache_freed);
	}
}

static struct btree *mca_bucket_alloc(struct cache_set *c,
				      struct bkey *k, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	init_rwsem(&b->lock);
	lockdep_set_novalidate_class(&b->lock);
	mutex_init(&b->write_lock);
	lockdep_set_novalidate_class(&b->write_lock);
	INIT_LIST_HEAD(&b->list);
	INIT_DELAYED_WORK(&b->work, btree_node_write_work);
	b->c = c;
	sema_init(&b->io_mutex, 1);

	mca_data_alloc(b, k, gfp);
	return b;
}

static int mca_reap(struct btree *b, unsigned min_order, bool flush)
{
	struct closure cl;

	closure_init_stack(&cl);
	lockdep_assert_held(&b->c->btree_cache_lock);

	if (!down_write_trylock(&b->lock))
		return -ENOMEM;

	BUG_ON(btree_node_dirty(b) && !b->keys.set[0].data);

	if (b->keys.page_order < min_order)
		goto out_unlock;

	if (!flush) {
		if (btree_node_dirty(b))
			goto out_unlock;

		if (down_trylock(&b->io_mutex))
			goto out_unlock;
		up(&b->io_mutex);
	}

	mutex_lock(&b->write_lock);
	if (btree_node_dirty(b))
		__bch_btree_node_write(b, &cl);
	mutex_unlock(&b->write_lock);

	closure_sync(&cl);

	/* wait for any in flight btree write */
	down(&b->io_mutex);
	up(&b->io_mutex);

	return 0;
out_unlock:
	rw_unlock(true, b);
	return -ENOMEM;
}

static unsigned long bch_mca_scan(struct shrinker *shrink,
				  struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);
	struct btree *b, *t;
	unsigned long i, nr = sc->nr_to_scan;
	unsigned long freed = 0;

	if (c->shrinker_disabled)
		return SHRINK_STOP;

	if (c->btree_cache_alloc_lock)
		return SHRINK_STOP;

	/* Return -1 if we can't do anything right now */
	if (sc->gfp_mask & __GFP_IO)
		mutex_lock(&c->btree_cache_lock);
	else if (!mutex_trylock(&c->btree_cache_lock))
		return -1;

	/*
	 * It's _really_ critical that we don't free too many btree nodes - we
	 * have to always leave ourselves a reserve. The reserve is how we
	 * guarantee that allocating memory for a new btree node can always
	 * succeed, so that inserting keys into the btree can always succeed and
	 * IO can always make forward progress:
	 */
	nr /= c->btree_pages;
	nr = min_t(unsigned long, nr, mca_can_free(c));

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		if (freed >= nr)
			break;

		if (++i > 3 &&
		    !mca_reap(b, 0, false)) {
			mca_data_free(b);
			rw_unlock(true, b);
			freed++;
		}
	}

	for (i = 0; (nr--) && i < c->btree_cache_used; i++) {
		if (list_empty(&c->btree_cache))
			goto out;

		b = list_first_entry(&c->btree_cache, struct btree, list);
		list_rotate_left(&c->btree_cache);

		if (!b->accessed &&
		    !mca_reap(b, 0, false)) {
			mca_bucket_free(b);
			mca_data_free(b);
			rw_unlock(true, b);
			freed++;
		} else
			b->accessed = 0;
	}
out:
	mutex_unlock(&c->btree_cache_lock);
	return freed;
}

static unsigned long bch_mca_count(struct shrinker *shrink,
				   struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);

	if (c->shrinker_disabled)
		return 0;

	if (c->btree_cache_alloc_lock)
		return 0;

	return mca_can_free(c) * c->btree_pages;
}

void bch_btree_cache_free(struct cache_set *c)
{
	struct btree *b;
	struct closure cl;
	closure_init_stack(&cl);

	if (c->btree_cache_shrink.list.next)
		unregister_shrinker(&c->btree_cache_shrink);

	mutex_lock(&c->btree_cache_lock);

#ifdef CONFIG_BCACHE_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);

	free_pages((unsigned long) c->verify_ondisk, ilog2(bucket_pages(c)));
#endif

	list_splice(&c->btree_cache_freeable,
		    &c->btree_cache);

	while (!list_empty(&c->btree_cache)) {
		b = list_first_entry(&c->btree_cache, struct btree, list);

		if (btree_node_dirty(b))
			btree_complete_write(b, btree_current_write(b));
		clear_bit(BTREE_NODE_dirty, &b->flags);

		mca_data_free(b);
	}

	while (!list_empty(&c->btree_cache_freed)) {
		b = list_first_entry(&c->btree_cache_freed,
				     struct btree, list);
		list_del(&b->list);
		cancel_delayed_work_sync(&b->work);
		kfree(b);
	}

	rhashtable_destroy(&c->btree_cache_table);
	mutex_unlock(&c->btree_cache_lock);
}

int bch_btree_cache_alloc(struct cache_set *c)
{
	unsigned i;
	int ret;

	ret = rhashtable_init(&c->btree_cache_table, &bch_btree_cache_params);
	if (ret)
		return ret;

	for (i = 0; i < mca_reserve(c); i++)
		if (!mca_bucket_alloc(c, &ZERO_KEY, GFP_KERNEL))
			return -ENOMEM;

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHE_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_ondisk = (void *)
		__get_free_pages(GFP_KERNEL, ilog2(bucket_pages(c)));

	c->verify_data = mca_bucket_alloc(c, &ZERO_KEY, GFP_KERNEL);

	if (c->verify_data &&
	    c->verify_data->keys.set->data)
		list_del_init(&c->verify_data->list);
	else
		c->verify_data = NULL;
#endif

	c->btree_cache_shrink.count_objects = bch_mca_count;
	c->btree_cache_shrink.scan_objects = bch_mca_scan;
	c->btree_cache_shrink.seeks = 4;
	c->btree_cache_shrink.batch = c->btree_pages * 2;
	register_shrinker(&c->btree_cache_shrink);

	return 0;
}

/* Btree in memory cache - hash table */

#define PTR_HASH(_k)	((_k)->ptr[0])

static struct btree *mca_find(struct cache_set *c, struct bkey *k)
{
	return rhashtable_lookup_fast(&c->btree_cache_table, &PTR_HASH(k),
				      bch_btree_cache_params);
}

static int mca_cannibalize_lock(struct cache_set *c, struct btree_op *op)
{
	struct task_struct *old;

	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old && old != current) {
		if (op)
			prepare_to_wait(&c->btree_cache_wait, &op->wait,
					TASK_UNINTERRUPTIBLE);
		return -EINTR;
	}

	return 0;
}

static struct btree *mca_cannibalize(struct cache_set *c, struct btree_op *op,
				     struct bkey *k)
{
	struct btree *b;

	trace_bcache_btree_cache_cannibalize(c);

	if (mca_cannibalize_lock(c, op))
		return ERR_PTR(-EINTR);

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, btree_order(k), false))
			goto out;

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, btree_order(k), true))
			goto out;

	WARN(1, "btree cache cannibalize failed\n");
	return ERR_PTR(-ENOMEM);
out:
	mca_bucket_free(b);
	return b;
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
static void bch_cannibalize_unlock(struct cache_set *c)
{
	if (c->btree_cache_alloc_lock == current) {
		c->btree_cache_alloc_lock = NULL;
		wake_up(&c->btree_cache_wait);
	}
}

static struct btree *mca_alloc(struct cache_set *c, struct btree_op *op,
			       struct bkey *k, int level)
{
	struct btree *b = NULL;

	mutex_lock(&c->btree_cache_lock);

	if (mca_find(c, k))
		goto out_unlock;

	/* btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (!mca_reap(b, btree_order(k), false))
			goto out;

	/* We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap(b, 0, false)) {
			mca_data_alloc(b, k, __GFP_NOWARN|GFP_NOIO);
			if (!b->keys.set[0].data)
				goto err;
			else
				goto out;
		}

	b = mca_bucket_alloc(c, k, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!down_write_trylock(&b->lock));
	if (!b->keys.set->data)
		goto err;
out:
	BUG_ON(PTR_HASH(&b->key));
	BUG_ON(b->io_mutex.count != 1);

	bkey_copy(&b->key, k);
	list_move(&b->list, &c->btree_cache);
	BUG_ON(rhashtable_insert_fast(&c->btree_cache_table, &b->hash,
				      bch_btree_cache_params));

	lock_set_subclass(&b->lock.dep_map, level + 1, _THIS_IP_);
	b->parent	= (void *) ~0UL;
	b->flags	= 0;
	b->written	= 0;
	b->level	= level;

	if (!b->level)
		bch_btree_keys_init(&b->keys, &bch_extent_keys_ops,
				    &b->c->expensive_debug_checks);
	else
		bch_btree_keys_init(&b->keys, &bch_btree_keys_ops,
				    &b->c->expensive_debug_checks);

out_unlock:
	mutex_unlock(&c->btree_cache_lock);
	return b;
err:
	if (b)
		rw_unlock(true, b);

	b = mca_cannibalize(c, op, k);
	if (!IS_ERR(b))
		goto out;

	goto out_unlock;
}

/**
 * bch_btree_node_get - find a btree node in the cache and lock it, reading it
 * in from disk if necessary.
 *
 * If IO is necessary and running under generic_make_request, returns -EAGAIN.
 *
 * The btree node will have either a read or a write lock held, depending on
 * level and op->lock.
 */
struct btree *bch_btree_node_get(struct cache_set *c, struct btree_op *op,
				 struct bkey *k, int level, bool write,
				 struct btree *parent)
{
	int i = 0;
	struct btree *b;

	BUG_ON(level < 0);
retry:
	rcu_read_lock();
	b = mca_find(c, k);
	rcu_read_unlock();

	if (unlikely(!b)) {
		if (current->bio_list)
			return ERR_PTR(-EAGAIN);

		b = mca_alloc(c, op, k, level);
		if (!b)
			goto retry;
		if (IS_ERR(b))
			return b;

		bch_btree_node_read(b);

		if (!write)
			downgrade_write(&b->lock);
	} else {
		rw_lock(write, b, level);
		if (PTR_HASH(&b->key) != PTR_HASH(k)) {
			rw_unlock(write, b);
			goto retry;
		}
		BUG_ON(b->level != level);
	}

	b->parent = parent;
	b->accessed = 1;

	for (; i <= b->keys.nsets && b->keys.set[i].size; i++) {
		prefetch(b->keys.set[i].tree);
		prefetch(b->keys.set[i].data);
	}

	for (; i <= b->keys.nsets; i++)
		prefetch(b->keys.set[i].data);

	if (btree_node_io_error(b)) {
		rw_unlock(write, b);
		return ERR_PTR(-EIO);
	}

	BUG_ON(!b->written);

	return b;
}

static void btree_node_prefetch(struct btree *parent, struct bkey *k)
{
	struct btree *b;

	b = mca_alloc(parent->c, NULL, k, parent->level - 1);
	if (!IS_ERR_OR_NULL(b)) {
		b->parent = parent;
		bch_btree_node_read(b);
		rw_unlock(true, b);
	}
}

/* Btree alloc */

static void btree_node_free(struct btree *b)
{
	trace_bcache_btree_node_free(b);

	BUG_ON(b == b->c->root);

	mutex_lock(&b->write_lock);

	if (btree_node_dirty(b))
		btree_complete_write(b, btree_current_write(b));
	clear_bit(BTREE_NODE_dirty, &b->flags);

	mutex_unlock(&b->write_lock);

	cancel_delayed_work(&b->work);

	mutex_lock(&b->c->bucket_lock);
	bch_bucket_free(b->c, &b->key);
	mutex_unlock(&b->c->bucket_lock);

	mutex_lock(&b->c->btree_cache_lock);
	mca_bucket_free(b);
	mutex_unlock(&b->c->btree_cache_lock);
}

struct btree *__bch_btree_node_alloc(struct cache_set *c, struct btree_op *op,
				     int level, bool wait,
				     struct btree *parent)
{
	BKEY_PADDED(key) k;
	struct btree *b = ERR_PTR(-EAGAIN);
retry:
	if (bch_bucket_alloc_set(c, RESERVE_BTREE, &k.key,
				 c->meta_replicas, wait))
		goto err;

	SET_KEY_SIZE(&k.key, c->btree_pages * PAGE_SECTORS);

	b = mca_alloc(c, op, &k.key, level);
	if (IS_ERR(b))
		goto err_free;

	if (!b) {
		cache_bug(c,
			"Tried to allocate bucket that was in btree cache");
		goto retry;
	}

	b->accessed = 1;
	b->parent = parent;
	bch_bset_init_next(&b->keys, b->keys.set->data, bset_magic(&b->c->sb));

	trace_bcache_btree_node_alloc(b);
	return b;
err_free:
	mutex_lock(&c->bucket_lock);
	bch_bucket_free(c, &k.key);
	mutex_unlock(&c->bucket_lock);
err:
	trace_bcache_btree_node_alloc_fail(c);
	return b;
}

static struct btree *bch_btree_node_alloc(struct cache_set *c,
					  struct btree_op *op, int level,
					  struct btree *parent)
{
	return __bch_btree_node_alloc(c, op, level, op != NULL, parent);
}

static struct btree *btree_node_alloc_replacement(struct btree *b,
						  struct btree_op *op)
{
	struct btree *n = bch_btree_node_alloc(b->c, op, b->level, b->parent);
	if (!IS_ERR_OR_NULL(n)) {
		mutex_lock(&n->write_lock);
		bch_btree_sort_into(&b->keys, &n->keys, &b->c->sort);
		bkey_copy_key(&n->key, &b->key);
		mutex_unlock(&n->write_lock);
	}

	return n;
}

static void make_btree_freeing_key(struct btree *b, struct bkey *k)
{
	unsigned i;

	mutex_lock(&b->c->bucket_lock);

	atomic_inc(&b->c->prio_blocked);

	bkey_copy(k, &b->key);
	bkey_copy_key(k, &ZERO_KEY);

	for (i = 0; i < KEY_PTRS(k); i++)
		SET_PTR_GEN(k, i,
			    bch_inc_gen(PTR_CACHE(b->c, &b->key, i),
					PTR_BUCKET(b->c, &b->key, i)));

	mutex_unlock(&b->c->bucket_lock);
}

static int btree_check_reserve(struct btree *b, struct btree_op *op)
{
	struct cache_set *c = b->c;
	struct cache *ca;
	unsigned i, reserve = (c->root->level - b->level) * 2 + 1;

	mutex_lock(&c->bucket_lock);

	for_each_cache(ca, c, i)
		if (fifo_used(&ca->free[RESERVE_BTREE]) < reserve) {
			if (op)
				prepare_to_wait(&c->btree_cache_wait, &op->wait,
						TASK_UNINTERRUPTIBLE);
			mutex_unlock(&c->bucket_lock);
			return -EINTR;
		}

	mutex_unlock(&c->bucket_lock);

	return mca_cannibalize_lock(b->c, op);
}

/* Garbage collection */

static uint8_t __bch_btree_mark_key(struct cache_set *c, int level,
				    struct bkey *k)
{
	uint8_t stale = 0;
	unsigned i;
	struct bucket *g;

	/*
	 * ptr_invalid() can't return true for the keys that mark btree nodes as
	 * freed, but since ptr_bad() returns true we'll never actually use them
	 * for anything and thus we don't want mark their pointers here
	 */
	if (!bkey_cmp(k, &ZERO_KEY))
		return stale;

	for (i = 0; i < KEY_PTRS(k); i++) {
		if (!ptr_available(c, k, i))
			continue;

		g = PTR_BUCKET(c, k, i);

		if (gen_after(g->last_gc, PTR_GEN(k, i)))
			g->last_gc = PTR_GEN(k, i);

		if (ptr_stale(c, k, i)) {
			stale = max(stale, ptr_stale(c, k, i));
			continue;
		}

		cache_bug_on(GC_MARK(g) &&
			     (GC_MARK(g) == GC_MARK_METADATA) != (level != 0),
			     c, "inconsistent ptrs: mark = %llu, level = %i",
			     GC_MARK(g), level);

		if (level)
			SET_GC_MARK(g, GC_MARK_METADATA);
		else if (KEY_DIRTY(k))
			SET_GC_MARK(g, GC_MARK_DIRTY);
		else if (!GC_MARK(g))
			SET_GC_MARK(g, GC_MARK_RECLAIMABLE);

		/* guard against overflow */
		SET_GC_SECTORS_USED(g, min_t(unsigned,
					     GC_SECTORS_USED(g) + KEY_SIZE(k),
					     MAX_GC_SECTORS_USED));

		BUG_ON(!GC_SECTORS_USED(g));
	}

	return stale;
}

#define btree_mark_key(b, k)	__bch_btree_mark_key(b->c, b->level, k)

void bch_initial_mark_key(struct cache_set *c, int level, struct bkey *k)
{
	unsigned i;

	for (i = 0; i < KEY_PTRS(k); i++)
		if (ptr_available(c, k, i) &&
		    !ptr_stale(c, k, i)) {
			struct bucket *b = PTR_BUCKET(c, k, i);

			b->gen = PTR_GEN(k, i);

			if (level && bkey_cmp(k, &ZERO_KEY))
				b->read_prio = BTREE_PRIO;
			else if (!level && b->read_prio == BTREE_PRIO)
				b->read_prio = INITIAL_PRIO;
		}

	__bch_btree_mark_key(c, level, k);
}

static bool btree_gc_mark_node(struct btree *b, struct gc_stat *gc)
{
	uint8_t stale = 0;
	unsigned keys = 0, good_keys = 0;
	struct bkey *k;
	struct btree_iter iter;
	struct bset_tree *t;

	gc->nodes++;

	for_each_key_filter(&b->keys, k, &iter, bch_ptr_invalid) {
		stale = max(stale, btree_mark_key(b, k));
		keys++;

		if (bch_ptr_bad(&b->keys, k))
			continue;

		gc->key_bytes += bkey_u64s(k);
		gc->nkeys++;
		good_keys++;

		gc->data += KEY_SIZE(k);
	}

	for (t = b->keys.set; t <= &b->keys.set[b->keys.nsets]; t++)
		btree_bug_on(t->size &&
			     bset_written(&b->keys, t) &&
			     bkey_cmp(&b->key, &t->end) < 0,
			     b, "found short btree key in gc");

	if (b->c->gc_always_rewrite)
		return true;

	if (stale > 10)
		return true;

	if ((keys - good_keys) * 2 > keys)
		return true;

	return false;
}

#define GC_MERGE_NODES	4U

struct gc_merge_info {
	struct btree	*b;
	unsigned	keys;
};

static int bch_btree_insert_node(struct btree *, struct btree_op *,
				 struct keylist *, struct bkey *,
				 struct closure *);

static int btree_gc_coalesce(struct btree *b, struct btree_op *op,
			     struct gc_stat *gc, struct gc_merge_info *r)
{
	unsigned i, nodes = 0, old_nodes, keys = 0, blocks;
	struct btree *new_nodes[GC_MERGE_NODES];
	struct keylist keylist;
	struct closure cl;
	struct bkey *k;

	bch_keylist_init(&keylist);

	/* If we can't allocate new nodes, just keep going */
	if (btree_check_reserve(b, NULL))
		return 0;

	memset(new_nodes, 0, sizeof(new_nodes));
	closure_init_stack(&cl);

	while (nodes < GC_MERGE_NODES && !IS_ERR_OR_NULL(r[nodes].b))
		keys += r[nodes++].keys;

	old_nodes = nodes;

	blocks = btree_default_blocks(b->c) * 2 / 3;

	if (nodes <= 1 ||
	    __set_blocks(b->keys.set[0].data,
			 DIV_ROUND_UP(keys, nodes - 1),
			 block_bytes(b->c)) > blocks)
		return 0;

	for (i = 0; i < nodes; i++) {
		new_nodes[i] = btree_node_alloc_replacement(r[i].b, NULL);
		if (IS_ERR_OR_NULL(new_nodes[i]))
			goto out_nocoalesce;
	}

	/*
	 * We have to check the reserve here, after we've allocated our new
	 * nodes, to make sure the insert below will succeed - we also check
	 * before as an optimization to potentially avoid a bunch of expensive
	 * allocs/sorts
	 */
	if (btree_check_reserve(b, NULL))
		goto out_nocoalesce;

	for (i = 0; i < nodes; i++)
		mutex_lock(&new_nodes[i]->write_lock);

	/*
	 * Conceptually we concatenate the nodes' keys together and slice them
	 * up at different boundaries. This means the new nodes will different
	 * keys in their parent nodes.
	 */
	for (i = nodes - 1; i > 0; --i) {
		struct bset *n1 = btree_bset_first(new_nodes[i]);
		struct bset *n2 = btree_bset_first(new_nodes[i - 1]);
		struct bkey *k, *last = NULL;

		keys = 0;

		for (k = n2->start;
		     k < bset_bkey_last(n2) &&
		     __set_blocks(n1, n1->keys + keys + bkey_u64s(k),
				  block_bytes(b->c)) <= blocks;
		     k = bkey_next(k)) {
			last = k;
			keys += bkey_u64s(k);
		}

		if (keys == n2->keys) {
			/* n2 fits entirely in n1 */
			bkey_copy_key(&new_nodes[i]->key,
				      &new_nodes[i - 1]->key);

			memcpy(bset_bkey_last(n1),
			       n2->start,
			       n2->keys * sizeof(u64));
			n1->keys += n2->keys;

			btree_node_free(new_nodes[i - 1]);
			rw_unlock(true, new_nodes[i - 1]);

			memmove(new_nodes + i - 1,
				new_nodes + i,
				sizeof(new_nodes[0]) * (nodes - i));
			--nodes;
		} else if (keys) {
			/* move part of n2 into n1 */
			bkey_copy_key(&new_nodes[i]->key, last);

			memcpy(bset_bkey_last(n1),
			       n2->start,
			       keys * sizeof(u64));
			n1->keys += keys;

			memmove(n2->start,
				bset_bkey_idx(n2, keys),
				(n2->keys - keys) * sizeof(u64));
			n2->keys -= keys;
		}
	}

	for (i = 0; i < nodes; i++) {
		if (bch_keylist_realloc(&keylist,
					bkey_u64s(&new_nodes[i]->key)))
			goto out_nocoalesce;

		bch_btree_node_write(new_nodes[i], &cl);
		bch_keylist_add(&keylist, &new_nodes[i]->key);
		mutex_unlock(&new_nodes[i]->write_lock);
	}

	/* Wait for all the writes to finish */
	closure_sync(&cl);

	/* The keys for the old nodes get deleted */
	for (i = 0; i < old_nodes; i++) {
		if (bch_keylist_realloc(&keylist, bkey_u64s(&r[i].b->key)))
			goto out_nocoalesce;

		make_btree_freeing_key(r[i].b, keylist.top);
		bch_keylist_push(&keylist);
	}

	/* Insert the newly coalesced nodes */
	bch_btree_insert_node(b, op, &keylist, NULL, NULL);
	BUG_ON(!bch_keylist_empty(&keylist));

	/* Free the old nodes and update our sliding window */
	for (i = 0; i < old_nodes; i++) {
		btree_node_free(r[i].b);
		rw_unlock(true, r[i].b);

		r[i].b = ERR_PTR(-EINTR);
	}

	for (i = 0; i < nodes; i++) {
		r[i].b = new_nodes[i];
		r[i].keys = btree_bset_first(r[i].b)->keys;
	}

	trace_bcache_btree_gc_coalesce(nodes);
	gc->nodes -= old_nodes - nodes;

	bch_keylist_free(&keylist);

	/* Invalidated our iterator */
	return -EINTR;

out_nocoalesce:
	closure_sync(&cl);
	bch_keylist_free(&keylist);

	while ((k = bch_keylist_pop(&keylist)))
		if (!bkey_cmp(k, &ZERO_KEY))
			atomic_dec(&b->c->prio_blocked);

	for (i = 0; i < nodes; i++)
		if (!IS_ERR_OR_NULL(new_nodes[i])) {
			btree_node_free(new_nodes[i]);
			rw_unlock(true, new_nodes[i]);
		}
	return 0;
}

static int btree_gc_rewrite_node(struct btree *b, struct btree_op *op,
				 struct btree *replace)
{
	struct keylist keys;
	struct btree *n;

	if (btree_check_reserve(b, NULL))
		return 0;

	n = btree_node_alloc_replacement(replace, NULL);

	/* recheck reserve after allocating replacement node */
	if (btree_check_reserve(b, NULL)) {
		btree_node_free(n);
		rw_unlock(true, n);
		return 0;
	}

	bch_btree_node_write_sync(n);

	bch_keylist_init(&keys);
	bch_keylist_add(&keys, &n->key);

	make_btree_freeing_key(replace, keys.top);
	bch_keylist_push(&keys);

	bch_btree_insert_node(b, op, &keys, NULL, NULL);
	BUG_ON(!bch_keylist_empty(&keys));

	btree_node_free(replace);
	rw_unlock(true, n);

	/* Invalidated our iterator */
	return -EINTR;
}

static unsigned btree_gc_count_keys(struct btree *b)
{
	struct bkey *k;
	struct btree_iter iter;
	unsigned ret = 0;

	for_each_key_filter(&b->keys, k, &iter, bch_ptr_bad)
		ret += bkey_u64s(k);

	return ret;
}

static int btree_gc_recurse(struct btree *b, struct btree_op *op,
			    struct gc_stat *gc)
{
	int ret = 0;
	bool should_rewrite;
	struct bkey *k;
	struct btree_iter iter;
	struct gc_merge_info r[GC_MERGE_NODES];
	struct gc_merge_info *i, *last = r + ARRAY_SIZE(r) - 1;

	bch_btree_iter_init(&b->keys, &iter, &b->c->gc_done);

	for (i = r; i < r + ARRAY_SIZE(r); i++)
		i->b = ERR_PTR(-EINTR);

	while (1) {
		k = bch_btree_iter_next_filter(&iter, &b->keys, bch_ptr_bad);
		if (k) {
			r->b = bch_btree_node_get(b->c, op, k, b->level - 1,
						  true, b);
			if (IS_ERR(r->b)) {
				ret = PTR_ERR(r->b);
				break;
			}

			r->keys = btree_gc_count_keys(r->b);

			ret = btree_gc_coalesce(b, op, gc, r);
			if (ret)
				break;
		}

		if (!last->b)
			break;

		if (!IS_ERR(last->b)) {
			should_rewrite = btree_gc_mark_node(last->b, gc);
			if (should_rewrite) {
				ret = btree_gc_rewrite_node(b, op, last->b);
				if (ret)
					break;
			}

			if (last->b->level) {
				ret = btree_gc_recurse(last->b, op, gc);
				if (ret)
					break;
			}

			bkey_copy_key(&b->c->gc_done, &last->b->key);
			rw_unlock(true, last->b);
		}

		memmove(r + 1, r, sizeof(r[0]) * (GC_MERGE_NODES - 1));
		r->b = NULL;

		if (need_resched()) {
			ret = -EAGAIN;
			break;
		}
	}

	for (i = r; i < r + ARRAY_SIZE(r); i++)
		if (!IS_ERR_OR_NULL(i->b))
			rw_unlock(true, i->b);

	return ret;
}

static int bch_btree_gc_root(struct btree *b, struct btree_op *op,
			     struct gc_stat *gc)
{
	struct btree *n = NULL;
	int ret = 0;
	bool should_rewrite;

	should_rewrite = btree_gc_mark_node(b, gc);
	if (should_rewrite) {
		n = btree_node_alloc_replacement(b, NULL);

		if (!IS_ERR_OR_NULL(n)) {
			bch_btree_node_write_sync(n);

			bch_btree_set_root(n);
			btree_node_free(b);
			rw_unlock(true, n);

			return -EINTR;
		}
	}

	__bch_btree_mark_key(b->c, b->level + 1, &b->key);

	if (b->level) {
		ret = btree_gc_recurse(b, op, gc);
		if (ret)
			return ret;
	}

	bkey_copy_key(&b->c->gc_done, &b->key);

	return ret;
}

static void btree_gc_start(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *b;
	unsigned i;

	if (!c->gc_mark_valid)
		return;

	mutex_lock(&c->bucket_lock);

	c->gc_mark_valid = 0;
	c->gc_done = ZERO_KEY;

	for_each_cache(ca, c, i)
		for_each_bucket(b, ca) {
			b->last_gc = b->gen;
			SET_GC_MARK(b, 0);
			SET_GC_SECTORS_USED(b, 0);
		}

	/*
	 * must happen before traversing the btree, as pointers move from open
	 * buckets into the btree - if we race and an open_bucket has been freed
	 * before we marked it, it's in the btree now
	 */
	bch_mark_open_buckets(c);

	mutex_unlock(&c->bucket_lock);
}

static void bch_btree_gc_finish(struct cache_set *c)
{
	struct bucket *b;
	struct cache *ca;
	unsigned i;

	mutex_lock(&c->bucket_lock);

	set_gc_sectors(c);
	c->gc_mark_valid = 1;
	c->need_gc	= 0;

	for (i = 0; i < KEY_PTRS(&c->uuid_bucket); i++)
		SET_GC_MARK(PTR_BUCKET(c, &c->uuid_bucket, i),
			    GC_MARK_METADATA);

	bch_mark_writeback_keys(c);

	for_each_cache(ca, c, i) {
		size_t buckets_free = 0;
		uint64_t *i;

		ca->invalidate_needs_gc = 0;

		for (i = ca->sb.d; i < ca->sb.d + ca->sb.keys; i++)
			SET_GC_MARK(ca->buckets + *i, GC_MARK_METADATA);

		for (i = ca->prio_buckets;
		     i < ca->prio_buckets + prio_buckets(ca) * 2; i++)
			SET_GC_MARK(ca->buckets + *i, GC_MARK_METADATA);

		for_each_bucket(b, ca) {
			c->need_gc	= max(c->need_gc, bucket_gc_gen(b));

			if (!GC_MARK(b) || GC_MARK(b) == GC_MARK_RECLAIMABLE)
				buckets_free++;
		}

		ca->buckets_free = buckets_free;
	}

	mutex_unlock(&c->bucket_lock);
}

static void bch_btree_gc(struct cache_set *c)
{
	int ret;
	struct gc_stat stats;
	struct btree_op op;
	uint64_t start_time = local_clock();

	trace_bcache_gc_start(c);

	memset(&stats, 0, sizeof(struct gc_stat));
	bch_btree_op_init(&op, SHRT_MAX);

	btree_gc_start(c);

	do {
		ret = btree_root(gc_root, c, &op, &stats);
		cond_resched();

		if (ret && ret != -EAGAIN)
			pr_warn("gc failed!");
	} while (ret);

	bch_btree_gc_finish(c);
	wake_up_allocators(c);

	bch_time_stats_update(&c->btree_gc_time, start_time);

	stats.key_bytes *= sizeof(uint64_t);
	stats.data	<<= 9;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));

	trace_bcache_gc_end(c);

	bch_moving_gc(c);
}

static int bch_gc_thread(void *arg)
{
	struct cache_set *c = arg;
	struct cache *ca;
	unsigned i;

	while (1) {
again:
		bch_btree_gc(c);

		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		mutex_lock(&c->bucket_lock);

		for_each_cache(ca, c, i)
			if (ca->invalidate_needs_gc) {
				mutex_unlock(&c->bucket_lock);
				set_current_state(TASK_RUNNING);
				goto again;
			}

		mutex_unlock(&c->bucket_lock);

		try_to_freeze();
		schedule();
	}

	return 0;
}

int bch_gc_thread_start(struct cache_set *c)
{
	c->gc_thread = kthread_create(bch_gc_thread, c, "bcache_gc");
	if (IS_ERR(c->gc_thread))
		return PTR_ERR(c->gc_thread);

	set_task_state(c->gc_thread, TASK_INTERRUPTIBLE);
	return 0;
}

/* Initial partial gc */

static int bch_btree_check_recurse(struct btree *b, struct btree_op *op)
{
	int ret = 0;
	struct bkey *k, *p = NULL;
	struct btree_iter iter;

	for_each_key_filter(&b->keys, k, &iter, bch_ptr_invalid)
		bch_initial_mark_key(b->c, b->level, k);

	bch_initial_mark_key(b->c, b->level + 1, &b->key);

	if (b->level) {
		bch_btree_iter_init(&b->keys, &iter, NULL);

		do {
			k = bch_btree_iter_next_filter(&iter, &b->keys,
						       bch_ptr_bad);
			if (k)
				btree_node_prefetch(b, k);

			if (p)
				ret = btree(check_recurse, p, b, op);

			p = k;
		} while (p && !ret);
	}

	return ret;
}

int bch_btree_check(struct cache_set *c)
{
	struct btree_op op;

	bch_btree_op_init(&op, SHRT_MAX);

	return btree_root(check_recurse, c, &op);
}

void bch_initial_gc_finish(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *b;
	unsigned i;

	bch_btree_gc_finish(c);

	mutex_lock(&c->bucket_lock);

	/*
	 * We need to put some unused buckets directly on the prio freelist in
	 * order to get the allocator thread started - it needs freed buckets in
	 * order to rewrite the prios and gens, and it needs to rewrite prios
	 * and gens in order to free buckets.
	 *
	 * This is only safe for buckets that have no live data in them, which
	 * there should always be some of.
	 */
	for_each_cache(ca, c, i) {
		for_each_bucket(b, ca) {
			if (fifo_full(&ca->free[RESERVE_PRIO]))
				break;

			if (bch_can_invalidate_bucket(ca, b) &&
			    !GC_MARK(b)) {
				__bch_invalidate_one_bucket(ca, b);
				fifo_push(&ca->free[RESERVE_PRIO],
					  b - ca->buckets);
			}
		}
	}

	mutex_unlock(&c->bucket_lock);
}

/* Btree insertion */

static bool btree_insert_key(struct btree *b, struct bkey *k,
			     struct bkey *replace_key,
			     struct journal_write *journal_write)
{
	unsigned status;

	BUG_ON(bkey_cmp(k, &b->key) > 0);

	status = bch_btree_insert_key(&b->keys, k, replace_key);
	if (status == BTREE_INSERT_STATUS_NO_INSERT)
		return false;

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);
		schedule_delayed_work(&b->work, 30 * HZ);
	}

	if (!b->level &&
	    test_bit(JOURNAL_REPLAY_DONE, &b->c->journal.flags)) {
		struct btree_write *w = btree_current_write(b);

		if (!w->journal) {
			w->journal = &fifo_back(&b->c->journal.pin);
			atomic_inc(w->journal);
		}

		BUG_ON(bkey_u64s(k) >
		       journal_write_u64s_remaining(b->c, journal_write));

		bch_journal_add_keys(journal_write->data, k, bkey_u64s(k));
	}

	bch_check_keys(&b->keys, "%u for %s", status,
		       replace_key ? "replace" : "insert");

	trace_bcache_btree_insert_key(b, k, replace_key != NULL, status);
	return true;
}

static size_t insert_u64s_remaining(struct btree *b)
{
	long ret = bch_btree_keys_u64s_remaining(&b->keys);

	/*
	 * Might land in the middle of an existing extent and have to split it
	 */
	if (b->keys.ops->is_extents)
		ret -= KEY_MAX_U64S;

	return max(ret, 0L);
}

static void btree_node_lock_for_insert(struct btree *b)
	__acquires(b->write_lock)
{
	mutex_lock(&b->write_lock);

	if (write_block(b) != btree_bset_last(b) &&
	    b->keys.last_set_unwritten)
		bch_btree_init_next(b); /* just wrote a set */

	BUG_ON(b->written > btree_blocks(b));

	BUG_ON(b->written == btree_blocks(b) &&
	       b->keys.last_set_unwritten);
}

static struct journal_write *btree_journal_write_get(struct btree *b,
						     unsigned nkeys)
{
	DEFINE_WAIT(wait);
	struct journal_write *ret = bch_journal_write_get(b->c, nkeys);

	if (!IS_ERR_OR_NULL(ret))
		return ret;

	/*
	 * If b is a freshly allocated node (i.e. we're being called from
	 * btree_split(), we can't unlock the node as that would allow it to be
	 * written underneath btree_split() and would really screw it up
	 */
	if (!b->written)
		return NULL;

	while (1) {
		prepare_to_wait(&b->c->journal.wait, &wait,
				TASK_UNINTERRUPTIBLE);

		ret = bch_journal_write_get(b->c, nkeys);
		if (!IS_ERR_OR_NULL(ret))
			break;

		mutex_unlock(&b->write_lock);
		if (!ret)
			btree_flush_write(b->c);
		schedule();
		btree_node_lock_for_insert(b);
	}

	finish_wait(&b->c->journal.wait, &wait);
	return ret;
}

enum btree_insert_status {
	BTREE_INSERT_NO_INSERT,
	BTREE_INSERT_INSERTED,
	BTREE_INSERT_NEED_SPLIT,
};

static enum btree_insert_status bch_btree_insert_keys(struct btree *b,
						struct btree_op *op,
						struct keylist *insert_keys,
						struct bkey *replace_key,
						struct closure *parent)
{
	bool inserted = false, need_split = false;
	int oldsize = bch_count_data(&b->keys);
	struct journal_write *journal_write = NULL;

	while (!bch_keylist_empty(insert_keys)) {
		BKEY_PADDED(key) temp;
		struct bkey *k = insert_keys->keys;
		/*
		 * For updates to interior nodes, everything on the keylist has
		 * to be inserted atomically
		 */
		unsigned u64s = b->level
			? bch_keylist_nkeys(insert_keys)
			: bkey_u64s(k);

		/* finished for this node */
		if (b->keys.ops->is_extents
		    ? bkey_cmp(&START_KEY(k), &b->key) >= 0
		    : bkey_cmp(k, &b->key) > 0)
			break;

		/* full, need split */
		if (u64s > insert_u64s_remaining(b)) {
			need_split = true;
			break;
		}

		if (journal_write &&
		    u64s > journal_write_u64s_remaining(b->c,
							journal_write)) {
			bch_journal_write_put(b->c, journal_write, NULL);
			journal_write = NULL;
		}

		if (!b->level && !journal_write)
			journal_write = btree_journal_write_get(b, u64s);

		if (!b->level && !journal_write)
			break;

		/*
		 * recheck because btree_journal_write_get() might've dropped
		 * and retaken write_lock
		 */
		if (u64s > insert_u64s_remaining(b)) {
			need_split = true;
			break;
		}

		BUG_ON(write_block(b) != btree_bset_last(b));

		if (b->keys.ops->is_extents &&
		    bkey_cmp(k, &b->key) > 0) {
			bkey_copy(&temp.key, k);

			bch_cut_back(&b->key, &temp.key);
			bch_cut_front(&b->key, k);
			k = &temp.key;
		}

		inserted |= btree_insert_key(b, k, replace_key, journal_write);

		if (k == insert_keys->keys)
			bch_keylist_pop_front(insert_keys);
	}

	if (journal_write)
		bch_journal_write_put(b->c, journal_write,
					bch_keylist_empty(insert_keys)
					? parent : NULL);

	if (!inserted)
		op->insert_collision = true;

	BUG_ON(!bch_keylist_empty(insert_keys) && inserted && b->level);
	bch_count_data_verify(&b->keys, oldsize);

	return need_split ? BTREE_INSERT_NEED_SPLIT :
		inserted ? BTREE_INSERT_INSERTED : BTREE_INSERT_NO_INSERT;
}

static int btree_split(struct btree *b, struct btree_op *op,
		       struct keylist *insert_keys,
		       struct bkey *replace_key,
		       struct closure *parent)
{
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	struct bset *set1, *set2;
	uint64_t start_time = local_clock();
	struct closure cl;
	struct keylist parent_keys;
	struct bkey *k;

	closure_init_stack(&cl);
	bch_keylist_init(&parent_keys);

	if (btree_check_reserve(b, op)) {
		if (!b->level)
			return -EINTR;
		else
			WARN(1, "insufficient reserve for split\n");
	}

	n1 = btree_node_alloc_replacement(b, op);
	set1 = btree_bset_first(n1);

	mutex_lock(&n1->write_lock);

	bch_btree_insert_keys(n1, op, insert_keys, replace_key, parent);

	/*
	 * There might be duplicate (deleted) keys after the
	 * bch_btree_insert_keys() call - we need to remove them before we
	 * split, as it would be rather bad if we picked a duplicate for the
	 * pivot.
	 *
	 * Additionally, inserting might overwrite a bunch of existing keys
	 * (i.e. a big discard when there were a bunch of small extents
	 * previously) - we might not want to split after the insert. Splitting
	 * a node that's too small to be split would be bad (if the node had
	 * only one key, we wouldn't be able to assign the new node a key
	 * different from the original node)
	 */
	k = set1->start;
	while (k != bset_bkey_last(set1))
		if (bch_ptr_bad(&b->keys, k)) {
			set1->keys -= bkey_u64s(k);
			memmove(k, bkey_next(k),
				(void *) bset_bkey_last(set1) - (void *) k);
		} else
			k = bkey_next(k);

	if (set_blocks(set1, block_bytes(n1->c)) > btree_blocks(b) * 3 / 4) {
		trace_bcache_btree_node_split(b, set1->keys);

		n2 = bch_btree_node_alloc(b->c, op, b->level, b->parent);
		set2 = btree_bset_first(n2);

		if (!b->parent) {
			n3 = bch_btree_node_alloc(b->c, op, b->level + 1, NULL);
			BUG_ON(!n3);
		}

		mutex_lock(&n2->write_lock);

		/*
		 * Has to be a linear search because we don't have an auxiliary
		 * search tree yet
		 */
		for (k = set1->start;
		     ((u64 *) k - set1->d) < (set1->keys * 3) / 5;
		     k = bkey_next(k))
			;

		bkey_copy_key(&n1->key, k);

		k = bkey_next(k);

		set2->keys = (u64 *) bset_bkey_last(set1) - (u64 *) k;
		set1->keys -= set2->keys;

		BUG_ON(!set1->keys);
		BUG_ON(!set2->keys);

		memcpy(set2->start,
		       bset_bkey_last(set1),
		       set2->keys * sizeof(u64));

		bkey_copy_key(&n2->key, &b->key);

		bch_keylist_add(&parent_keys, &n2->key);
		bch_btree_node_write(n2, &cl);
		mutex_unlock(&n2->write_lock);
		rw_unlock(true, n2);
	} else {
		trace_bcache_btree_node_compact(b, set1->keys);
	}

	bch_keylist_add(&parent_keys, &n1->key);
	bch_btree_node_write(n1, &cl);
	mutex_unlock(&n1->write_lock);

	if (n3) {
		/* Depth increases, make a new root */
		mutex_lock(&n3->write_lock);
		bkey_copy_key(&n3->key, &MAX_KEY);
		bch_btree_insert_keys(n3, op, &parent_keys, NULL, NULL);
		bch_btree_node_write(n3, &cl);
		mutex_unlock(&n3->write_lock);

		closure_sync(&cl);
		bch_btree_set_root(n3);
		rw_unlock(true, n3);
	} else if (!b->parent) {
		/* Root filled up but didn't need to be split */
		closure_sync(&cl);
		bch_btree_set_root(n1);
	} else {
		/* Split a non root node */
		closure_sync(&cl);
		make_btree_freeing_key(b, parent_keys.top);
		bch_keylist_push(&parent_keys);

		bch_btree_insert_node(b->parent, op, &parent_keys, NULL, NULL);
		BUG_ON(!bch_keylist_empty(&parent_keys));
	}

	btree_node_free(b);
	rw_unlock(true, n1);

	bch_time_stats_update(&b->c->btree_split_time, start_time);

	return 0;
}

/**
 * bch_btree_insert_node - insert a node into the btree
 * @b:			parent btree node
 * @op:			pointer to struct btree_op
 * @insert_keys:	list of keys to insert
 * @replace_key:	old key for compare exchange
 * @parent:		closure will wait on last key to be inserted
 *
 * The @parent closure is used to wait on the journal write. The wait
 * will only happen if the full list is inserted.
 */
static int bch_btree_insert_node(struct btree *b, struct btree_op *op,
				 struct keylist *insert_keys,
				 struct bkey *replace_key,
				 struct closure *parent)
{
	struct closure cl;

	BUG_ON(b->level && replace_key);
	BUG_ON(!b->written);

	closure_init_stack(&cl);

	btree_node_lock_for_insert(b);

	switch (bch_btree_insert_keys(b, op, insert_keys,
				      replace_key, parent)) {
	case BTREE_INSERT_NO_INSERT:
		mutex_unlock(&b->write_lock);
		return 0;

	case BTREE_INSERT_INSERTED:
		/*
		 * Force write if set is too big (or if it's an interior node,
		 * since those aren't journalled yet)
		 */
		if (b->level)
			bch_btree_node_write(b, &cl);
		else {
			unsigned long bytes = set_bytes(btree_bset_last(b));

			if (b->io_mutex.count > 0 &&
			    ((max(roundup(bytes, block_bytes(b->c)),
				  PAGE_SIZE) - bytes < 48) ||
			     bytes > (16 << 10)))
				bch_btree_node_write(b, NULL);
		}

		mutex_unlock(&b->write_lock);

		/* wait for btree node write after unlock */
		closure_sync(&cl);
		return 0;

	case BTREE_INSERT_NEED_SPLIT:
		mutex_unlock(&b->write_lock);

		if (op->lock <= b->c->root->level) {
			op->lock = b->c->root->level + 1;
			return -EINTR;
		} else {
			/* Invalidated all iterators */
			int ret = btree_split(b, op, insert_keys,
					      replace_key, parent);

			if (bch_keylist_empty(insert_keys))
				return 0;
			else if (!ret)
				return -EINTR;
			return ret;
		}
	default:
		BUG();
	}
}

int bch_btree_insert_check_key(struct btree *b, struct btree_op *op,
			       struct bkey *check_key)
{
	int ret = -EINTR;
	uint64_t btree_ptr = b->key.ptr[0];
	unsigned long seq = b->seq;
	struct keylist insert;
	bool upgrade = op->lock == -1;

	bch_keylist_init(&insert);

	if (upgrade) {
		rw_unlock(false, b);
		rw_lock(true, b, b->level);

		if (b->key.ptr[0] != btree_ptr ||
		    b->seq != seq + 1)
			goto out;
	}

	SET_KEY_PTRS(check_key, 1);
	get_random_bytes(&check_key->ptr[0], sizeof(uint64_t));

	SET_PTR_DEV(check_key, 0, PTR_CHECK_DEV);

	bch_keylist_add(&insert, check_key);

	ret = bch_btree_insert_node(b, op, &insert, NULL, NULL);

	BUG_ON(!ret && !bch_keylist_empty(&insert));
out:
	if (upgrade)
		downgrade_write(&b->lock);
	return ret;
}

struct btree_insert_op {
	struct btree_op	op;
	struct keylist	*keys;
	struct bkey	*replace_key;
	struct closure	*parent;
};

static int btree_insert_fn(struct btree_op *b_op, struct btree *b)
{
	struct btree_insert_op *op = container_of(b_op,
					struct btree_insert_op, op);

	int ret = bch_btree_insert_node(b, &op->op, op->keys,
					op->replace_key, op->parent);
	if (ret && !bch_keylist_empty(op->keys))
		return ret;
	else
		return MAP_DONE;
}

int bch_btree_insert(struct cache_set *c, struct keylist *keys,
		     struct bkey *replace_key, struct closure *parent)
{
	struct btree_insert_op op;
	int ret = 0;

	BUG_ON(bch_keylist_empty(keys));

	bch_btree_op_init(&op.op, 0);
	op.keys		= keys;
	op.replace_key	= replace_key;
	op.parent	= parent;

	while (!ret && !bch_keylist_empty(keys)) {
		op.op.lock = 0;
		ret = bch_btree_map_leaf_nodes(&op.op, c,
					       &START_KEY(keys->keys),
					       btree_insert_fn);
	}

	if (ret)
		pr_err("error %i", ret);
	else if (op.op.insert_collision)
		ret = -ESRCH;

	return ret;
}

void bch_btree_set_root(struct btree *b)
{
	unsigned i;
	struct closure cl;

	closure_init_stack(&cl);

	trace_bcache_btree_set_root(b);

	BUG_ON(!b->written);

	for (i = 0; i < KEY_PTRS(&b->key); i++)
		BUG_ON(PTR_BUCKET(b->c, &b->key, i)->read_prio != BTREE_PRIO);

	mutex_lock(&b->c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&b->c->btree_cache_lock);

	b->c->root = b;

	bch_journal_meta(b->c, &cl);
	closure_sync(&cl);
}

/* Map across nodes or keys */

static int bch_btree_map_nodes_recurse(struct btree *b, struct btree_op *op,
				       struct bkey *from,
				       btree_map_nodes_fn *fn, int flags)
{
	int ret = MAP_CONTINUE;

	if (b->level) {
		struct bkey *k;
		struct btree_iter iter;

		bch_btree_iter_init(&b->keys, &iter, from);

		while ((k = bch_btree_iter_next_filter(&iter, &b->keys,
						       bch_ptr_bad))) {
			ret = btree(map_nodes_recurse, k, b,
				    op, from, fn, flags);
			from = NULL;

			if (ret != MAP_CONTINUE)
				return ret;
		}
	}

	if (!b->level || flags == MAP_ALL_NODES)
		ret = fn(op, b);

	return ret;
}

int __bch_btree_map_nodes(struct btree_op *op, struct cache_set *c,
			  struct bkey *from, btree_map_nodes_fn *fn, int flags)
{
	return btree_root(map_nodes_recurse, c, op, from, fn, flags);
}

static int bch_btree_map_keys_recurse(struct btree *b, struct btree_op *op,
				      struct bkey *from, btree_map_keys_fn *fn,
				      int flags)
{
	int ret = MAP_CONTINUE;
	struct bkey *k;
	struct btree_iter iter;

	bch_btree_iter_init(&b->keys, &iter, from);

	while ((k = bch_btree_iter_next_filter(&iter, &b->keys, bch_ptr_bad))) {
		ret = !b->level
			? fn(op, b, k)
			: btree(map_keys_recurse, k, b, op, from, fn, flags);
		from = NULL;

		if (ret != MAP_CONTINUE)
			return ret;
	}

	if (!b->level && (flags & MAP_END_KEY))
		ret = fn(op, b, NULL);

	return ret;
}

int bch_btree_map_keys(struct btree_op *op, struct cache_set *c,
		       struct bkey *from, btree_map_keys_fn *fn, int flags)
{
	return btree_root(map_keys_recurse, c, op, from, fn, flags);
}
