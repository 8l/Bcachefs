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
#include "gc.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"
#include "super.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/hash.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcache.h>

static int bch_btree_iter_traverse(struct btree_iter *);

static int __bch_btree_insert_node(struct btree *, struct btree_iter *,
				   struct keylist *, struct bch_replace_info *,
				   struct closure *, enum alloc_reserve,
				   struct keylist *, struct closure *);

static inline void mark_btree_node_intent_locked(struct btree_iter *iter,
						 unsigned level)
{
	iter->nodes_locked |= 1 << level;
	iter->nodes_intent_locked |= 1 << level;
}

static inline void mark_btree_node_read_locked(struct btree_iter *iter,
					       unsigned level)
{
	iter->nodes_locked |= 1 << level;
}

static inline bool btree_node_intent_locked(struct btree_iter *iter,
					    unsigned level)
{
	return iter->nodes_intent_locked & (1 << level);
}

static inline bool btree_node_read_locked(struct btree_iter *iter,
					  unsigned level)
{
	return btree_node_locked(iter, level) &&
		!btree_node_intent_locked(iter, level);
}

static inline bool btree_want_intent(struct btree_iter *iter, int level)
{
	return level <= iter->locks_want;
}

static void __btree_node_unlock(struct btree_iter *iter, unsigned level,
				struct btree *b)
{
	if (btree_node_intent_locked(iter, level))
		six_unlock_intent(&b->lock);
	else if (btree_node_read_locked(iter, level))
		six_unlock_read(&b->lock);

	mark_btree_node_unlocked(iter, level);
}

static void btree_node_unlock(struct btree_iter *iter, unsigned level)
{
	__btree_node_unlock(iter, level, iter->nodes[level]);
}

#define __btree_node_lock(b, iter, _level, check_if_raced, type)	\
({									\
	bool _raced;							\
									\
	six_lock_##type(&(b)->lock);					\
	if ((_raced = ((check_if_raced) || ((b)->level != _level))))	\
		six_unlock_##type(&(b)->lock);				\
	else								\
		mark_btree_node_##type##_locked((iter), (_level));	\
									\
	!_raced;							\
})

#define btree_node_lock(b, iter, level, check_if_raced)			\
	(!race_fault() &&						\
	 (btree_want_intent(iter, level)				\
	  ? __btree_node_lock(b, iter, level, check_if_raced, intent)	\
	  : __btree_node_lock(b, iter, level, check_if_raced, read)))

#define __btree_node_relock(b, iter, _level, type)			\
({									\
	bool _locked = six_relock_##type(&(b)->lock,			\
					 (iter)->lock_seq[_level]);	\
									\
	if (_locked)							\
		mark_btree_node_##type##_locked((iter), (_level));	\
									\
	_locked;							\
})

static bool btree_node_relock(struct btree_iter *iter, unsigned level)
{
	struct btree *b = iter->nodes[level];

	return btree_node_locked(iter, level) ||
		(!race_fault() &&
		 (btree_want_intent(iter, level)
		  ? __btree_node_relock(b, iter, level, intent)
		  : __btree_node_relock(b, iter, level, read)));
}

static bool btree_lock_upgrade(struct btree_iter *iter, unsigned level)
{
	struct btree *b = iter->nodes[level];

	if (btree_node_intent_locked(iter, level))
		return true;

	if (btree_node_locked(iter, level)
	    ? six_trylock_convert(&b->lock, read, intent)
	    : six_relock_intent(&b->lock, iter->lock_seq[level])) {
		mark_btree_node_intent_locked(iter, level);
		trace_bcache_btree_upgrade_lock(b, iter);
		return true;
	}

	trace_bcache_btree_upgrade_lock_fail(b, iter);
	return false;
}

bool bch_btree_iter_upgrade(struct btree_iter *iter)
{
	int i;

	BUG_ON(iter->locks_want > BTREE_MAX_DEPTH);

	for (i = iter->locks_want; i >= iter->level; --i)
		if (iter->nodes[i] && !btree_lock_upgrade(iter, i)) {
			do {
				btree_node_unlock(iter, i);
			} while (--i >= 0);

			/*
			 * Make sure btree_node_relock() in
			 * btree_iter_traverse() fails, so that we keep going up
			 * and get all the intent locks we need
			 */
			for (i = iter->locks_want - 1; i >= 0; --i)
				iter->lock_seq[i]--;

			return false;
		}

	return true;
}

static inline struct bset *write_block(struct btree *b)
{
	return ((void *) btree_bset_first(b)) + b->written * block_bytes(b->c);
}

/* Returns true if we sorted (i.e. invalidated iterators */
static void bch_btree_init_next(struct btree *b, struct btree_iter *iter)
{
	unsigned nsets = b->keys.nsets;
	bool sorted;

	BUG_ON(iter && iter->nodes[b->level] != b);

	/* If not a leaf node, always sort */
	if (b->level && b->keys.nsets)
		bch_btree_sort(&b->keys, NULL, &b->c->sort);
	else
		bch_btree_sort_lazy(&b->keys, NULL, &b->c->sort);

	sorted = nsets != b->keys.nsets;

	/*
	 * do verify if there was more than one set initially (i.e. we did a
	 * sort) and we sorted down to a single set:
	 */
	if (nsets && !b->keys.nsets)
		bch_btree_verify(b);

	if (b->written < btree_blocks(b->c)) {
		struct bset *i = write_block(b);

		bch_bset_init_next(&b->keys, i);
		i->magic = bset_magic(&b->c->sb);
	}

	if (iter && sorted)
		btree_iter_node_set(iter, b);
}

/* Btree IO */

static uint64_t btree_csum_set(struct btree *b, struct bset *i)
{
	const struct bkey_i_extent *e = bkey_i_to_extent_c(&b->key);
	u64 crc = e->v.ptr[0]._val;
	void *data = (void *) i + 8, *end = bset_bkey_last(i);

	crc = bch_checksum_update(BSET_CSUM_TYPE(i), crc, data, end - data);

	return crc ^ 0xffffffffffffffffULL;
}

#define btree_node_error(b, ca, ptr, fmt, ...)				\
	bch_cache_error(ca,						\
		"btree node error at btree %u level %u/%u bucket %zu block %u u64s %u: " fmt,\
		(b)->btree_id, (b)->level, btree_node_root(b)		\
			    ? btree_node_root(b)->level : -1,		\
		PTR_BUCKET_NR(ca, ptr), bset_block_offset(b, i),	\
		i->u64s, ##__VA_ARGS__)

void bch_btree_node_read_done(struct btree *b, struct cache *ca,
			      const struct bch_extent_ptr *ptr)
{
	struct cache_set *c = b->c;
	const char *err;
	struct bset *i = btree_bset_first(b);
	struct btree_node_iter *iter;
	struct bkey *k;

	iter = mempool_alloc(b->c->fill_iter, GFP_NOIO);
	iter->size = btree_blocks(c);
	iter->used = 0;
	iter->is_extents = b->keys.ops->is_extents;

#ifdef CONFIG_BCACHE_DEBUG
	iter->b = &b->keys;
#endif

	err = "dynamic fault";
	if (bch_meta_read_fault("btree"))
		goto err;

	err = "bad btree header";
	if (!i->seq)
		goto err;

	for (;
	     b->written < btree_blocks(c) && i->seq == b->keys.set[0].data->seq;
	     i = write_block(b)) {
		b->written += set_blocks(i, block_bytes(c));

		err = "unsupported bset version";
		if (i->version != BCACHE_BSET_VERSION)
			goto err;

		err = "bad magic";
		if (i->magic != bset_magic(&c->sb))
			goto err;

		err = "unknown checksum type";
		if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
			goto err;

		err = "bad btree header";
		if (b->written > btree_blocks(c))
			goto err;

		err = "bad checksum";
		if (i->csum != btree_csum_set(b, i))
			goto err;

		if (i != b->keys.set[0].data && !i->u64s)
			btree_node_error(b, ca, ptr, "empty set");

		for (k = i->start;
		     k != bset_bkey_last(i);) {
			if (!k->u64s) {
				btree_node_error(b, ca, ptr,
					"KEY_U64s 0: %zu bytes of metadata lost",
					(void *) bset_bkey_last(i) - (void *) k);

				i->u64s = (u64 *) k - i->_data;
				break;
			}

			if (bkey_next(k) > bset_bkey_last(i)) {
				btree_node_error(b, ca, ptr,
						 "key extends past end of bset");

				i->u64s = (u64 *) k - i->_data;
				break;
			}

			if (bkey_invalid(c, b->level
					 ? BKEY_TYPE_BTREE
					 : b->btree_id, k)) {
				char buf[80];

				bch_bkey_val_to_text(b, buf, sizeof(buf), k);
				btree_node_error(b, ca, ptr,
						 "invalid bkey %s", buf);

				i->u64s -= k->u64s;
				memmove(k, bkey_next(k),
					(void *) bset_bkey_last(i) - (void *) k);
				continue;
			}

			k = bkey_next(k);
		}

		bch_btree_node_iter_push(iter, i->start, bset_bkey_last(i));
	}

	err = "corrupted btree";
	for (i = write_block(b);
	     bset_sector_offset(&b->keys, i) < btree_sectors(c);
	     i = ((void *) i) + block_bytes(c))
		if (i->seq == b->keys.set[0].data->seq)
			goto err;

	bch_btree_sort_and_fix_extents(&b->keys, iter,
				       b->keys.ops->is_extents
				       ? bch_extent_sort_fix_overlapping
				       : bch_key_sort_fix_overlapping,
				       &c->sort);

	i = b->keys.set[0].data;
	err = "short btree key";
	if (b->keys.set[0].size &&
	    bkey_cmp(b->key.p, b->keys.set[0].end.p) < 0)
		goto err;

out:
	mempool_free(iter, c->fill_iter);
	return;
err:
	set_btree_node_io_error(b);
	btree_node_error(b, ca, ptr, "%s", err);
	goto out;
}

static void btree_node_read_endio(struct bio *bio, int error)
{
	bch_bbio_endio(to_bbio(bio), error, "reading btree");
}

static void bch_btree_node_read(struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bbio *bio;
	struct cache *ca;
	const struct bch_extent_ptr *ptr;

	trace_bcache_btree_read(b);

	closure_init_stack(&cl);

	ca = bch_btree_pick_ptr(b->c, b, &ptr);
	if (!ca) {
		set_btree_node_io_error(b);
		goto missing;
	}

	bio = to_bbio(bch_bbio_alloc(b->c));
	bio->bio.bi_rw			= REQ_META|READ_SYNC;
	bio->bio.bi_iter.bi_size	= btree_bytes(b->c);
	bio->bio.bi_end_io		= btree_node_read_endio;
	bio->bio.bi_private		= &cl;

	bch_bio_map(&bio->bio, b->keys.set[0].data);

	bio_get(&bio->bio);
	bch_submit_bbio(bio, ca, &b->key, ptr, true);

	closure_sync(&cl);

	if (!test_bit(BIO_UPTODATE, &bio->bio.bi_flags) ||
	    bch_meta_read_fault("btree"))
		set_btree_node_io_error(b);

	bch_bbio_free(&bio->bio, b->c);

	if (btree_node_io_error(b))
		goto err;

	bch_btree_node_read_done(b, ca, ptr);
	bch_time_stats_update(&b->c->btree_read_time, start_time);

	return;

missing:
	bch_cache_set_error(b->c, "no cache device for btree node");
	return;

err:
	bch_cache_error(ca, "IO error reading bucket %zu",
			PTR_BUCKET_NR(ca, ptr));
}

static void btree_complete_write(struct btree *b, struct btree_write *w)
{
	if (w->journal) {
		if (atomic_dec_and_test(w->journal))
			wake_up(&b->c->journal.wait);
	}

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
	struct cache_set *c = b->c;

	bch_bbio_free(b->bio, c);
	b->bio = NULL;
	btree_complete_write(b, w);

	if (btree_node_dirty(b) && c->btree_flush_delay)
		schedule_delayed_work(&b->work, c->btree_flush_delay * HZ);

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

	if (error || bch_meta_write_fault("btree"))
		set_btree_node_io_error(b);

	bch_bbio_endio(to_bbio(bio), error, "writing btree");
}

static void do_btree_node_write(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io);
	struct bset *i = btree_bset_last(b);
	BKEY_PADDED(key) k;
	struct bkey_i_extent *e;
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	size_t blocks_to_write = set_blocks(i, block_bytes(b->c));

	trace_bcache_btree_write(b);

	BUG_ON(b->written >= btree_blocks(b->c));
	BUG_ON(b->written + blocks_to_write > btree_blocks(b->c));
	BUG_ON(b->written && !i->u64s);
	BUG_ON(btree_bset_first(b)->seq != i->seq);

	cancel_delayed_work(&b->work);

	change_bit(BTREE_NODE_write_idx, &b->flags);

	b->written += blocks_to_write;

	i->version	= BCACHE_BSET_VERSION;

	SET_BSET_CSUM_TYPE(i, CACHE_PREFERRED_CSUM_TYPE(&b->c->sb));
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
	e = bkey_i_to_extent(&k.key);

	extent_for_each_ptr(e, ptr)
		SET_PTR_OFFSET(ptr, PTR_OFFSET(ptr) +
			       bset_sector_offset(&b->keys, i));

	rcu_read_lock();
	extent_for_each_online_device(b->c, e, ptr, ca)
		atomic_long_add(blocks_to_write * b->c->sb.block_size,
				&ca->btree_sectors_written);
	rcu_read_unlock();

	if (!bio_alloc_pages(b->bio, __GFP_NOWARN|GFP_NOWAIT)) {
		int j;
		struct bio_vec *bv;
		void *base = (void *) ((unsigned long) i & ~(PAGE_SIZE - 1));

		bio_for_each_segment_all(bv, b->bio, j)
			memcpy(page_address(bv->bv_page),
			       base + j * PAGE_SIZE, PAGE_SIZE);

		bch_submit_bbio_replicas(b->bio, b->c, &k.key, 0, true);
		continue_at(cl, btree_node_write_done, NULL);
	} else {
		trace_bcache_btree_bounce_write_fail(b);

		b->bio->bi_vcnt = 0;
		bch_bio_map(b->bio, i);

		bch_submit_bbio_replicas(b->bio, b->c, &k.key, 0, true);

		closure_sync(cl);
		continue_at_nobarrier(cl, __btree_node_write_done, NULL);
	}
}

static void __bch_btree_node_write(struct btree *b, struct closure *parent)
{
	/*
	 * can't be flipped back on without a write lock, we have at least a
	 * read lock:
	 */
	if (!test_and_clear_bit(BTREE_NODE_dirty, &b->flags))
		return;

	/*
	 * io_mutex ensures only a single IO in flight to a btree node at a
	 * time, and also protects use of the b->io closure.
	 * do_btree_node_write() will drop it asynchronously.
	 */
	down(&b->io_mutex);

	/*
	 * do_btree_node_write() must not run asynchronously (NULL is passed for
	 * workqueue) - it needs the lock we have on the btree node
	 */
	closure_call(&b->io, do_btree_node_write, NULL, parent ?: &b->c->cl);
}

void bch_btree_node_write(struct btree *b, struct closure *parent,
			  struct btree_iter *iter)
{
	__bch_btree_node_write(b, parent);

	six_lock_write(&b->lock);
	bch_btree_init_next(b, iter);
	six_unlock_write(&b->lock);
}

static void bch_btree_node_write_sync(struct btree *b, struct btree_iter *iter)
{
	struct closure cl;

	closure_init_stack(&cl);

	bch_btree_node_write(b, &cl, iter);
	closure_sync(&cl);
}

static void bch_btree_node_write_dirty(struct btree *b, struct closure *parent)
{
	six_lock_read(&b->lock);
	__bch_btree_node_write(b, parent);
	six_unlock_read(&b->lock);
}

static void btree_node_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);
	bch_btree_node_write_dirty(b, NULL);
}

/**
 * bch_btree_write_oldest - write all btree nodes with sequence numbers older
 * than @oldest_seq
 */
void bch_btree_write_oldest(struct cache_set *c, u64 oldest_seq)
{
	/*
	 * Try to find the btree node with that references the oldest journal
	 * entry, best is our current candidate and is locked if non NULL:
	 */
	struct btree *b;
	unsigned i;
	int written = 0;
	struct closure cl;

	closure_init_stack(&cl);

	trace_bcache_journal_write_oldest(c, oldest_seq);

	for_each_cached_btree(b, c, i)
		if (btree_current_write(b)->journal) {
			if (fifo_idx(&c->journal.pin,
				     btree_current_write(b)->journal)
				<= oldest_seq) {
				six_lock_read(&b->lock);
				if (btree_current_write(b)->journal) {
					written++;
					__bch_btree_node_write(b, &cl);
				}
				six_unlock_read(&b->lock);
			}
		}

	closure_sync(&cl);
	trace_bcache_journal_write_oldest_done(c, oldest_seq, written);
}

/*
 * Write all dirty btree nodes to disk, including roots
 */
void bch_btree_flush(struct cache_set *c)
{
	struct closure cl;
	struct btree *b;
	unsigned iter;

	closure_init_stack(&cl);
	for_each_cached_btree(b, c, iter)
		bch_btree_node_write_dirty(b, &cl);
	closure_sync(&cl);
}

/*
 * Btree in memory cache - allocation/freeing
 * mca -> memory cache
 */

void bch_recalc_btree_reserve(struct cache_set *c)
{
	unsigned i, reserve = 16;

	if (!c->btree_roots[0])
		reserve += 8;

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			reserve += min_t(unsigned, 1,
					 c->btree_roots[i]->level) * 8;

	c->btree_cache_reserve = reserve;
}

#define mca_can_free(c)						\
	max_t(int, 0, c->btree_cache_used - c->btree_cache_reserve)

static void mca_data_free(struct btree *b)
{
	BUG_ON(b->io_mutex.count != 1);

	bch_btree_keys_free(&b->keys);

	b->c->btree_cache_used--;
	list_move(&b->list, &b->c->btree_cache_freed);
}

static void mca_bucket_free(struct btree *b)
{
	BUG_ON(btree_node_dirty(b));

	bkey_i_to_extent(&b->key)->v.ptr[0]._val = 0;
	hlist_del_init_rcu(&b->hash);
	list_move(&b->list, &b->c->btree_cache_freeable);
}

static void mca_data_alloc(struct btree *b, gfp_t gfp)
{
	if (!bch_btree_keys_alloc(&b->keys, ilog2(b->c->btree_pages), gfp)) {
		b->c->btree_cache_used++;
		list_move(&b->list, &b->c->btree_cache);
	} else {
		list_move(&b->list, &b->c->btree_cache_freed);
	}
}

static struct btree *mca_bucket_alloc(struct cache_set *c, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	six_lock_init(&b->lock);
	INIT_LIST_HEAD(&b->list);
	INIT_DELAYED_WORK(&b->work, btree_node_write_work);
	b->c = c;
	sema_init(&b->io_mutex, 1);

	mca_data_alloc(b, gfp);
	return b;
}

/*
 * this version is for btree nodes that have already been freed (we're not
 * reaping a real btree node)
 */
static int mca_reap_notrace(struct btree *b, bool flush)
{
	struct closure cl;

	closure_init_stack(&cl);
	lockdep_assert_held(&b->c->btree_cache_lock);

	if (!six_trylock_intent(&b->lock))
		return -ENOMEM;

	if (!six_trylock_write(&b->lock))
		goto out_unlock_intent;

	BUG_ON(btree_node_dirty(b) && !b->keys.set[0].data);

	if (!flush) {
		if (btree_node_dirty(b))
			goto out_unlock;

		if (down_trylock(&b->io_mutex))
			goto out_unlock;
		up(&b->io_mutex);
	}

	if (btree_node_dirty(b))
		__bch_btree_node_write(b, &cl);

	closure_sync(&cl);

	/* wait for any in flight btree write */
	down(&b->io_mutex);
	up(&b->io_mutex);

	return 0;
out_unlock:
	six_unlock_write(&b->lock);
out_unlock_intent:
	six_unlock_intent(&b->lock);
	return -ENOMEM;
}

static int mca_reap(struct btree *b, bool flush)
{
	int ret = mca_reap_notrace(b, flush);

	trace_bcache_mca_reap(b, ret);
	return ret;
}

static unsigned long bch_mca_scan(struct shrinker *shrink,
				  struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set,
					   btree_cache_shrink);
	struct btree *b, *t;
	unsigned long nr = sc->nr_to_scan;
	unsigned long can_free;
	unsigned long touched = 0;
	unsigned long freed = 0;
	unsigned i;

	u64 start_time = local_clock();

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
	can_free = mca_can_free(c);
	nr = min_t(unsigned long, nr, can_free);

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		touched++;

		if (freed >= nr)
			break;

		if (++i > 3 &&
		    !mca_reap_notrace(b, false)) {
			mca_data_free(b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		}
	}

	list_for_each_entry_safe(b, t, &c->btree_cache, list) {
		touched++;

		if (freed >= nr) {
			/* Save position */
			if (&t->list != &c->btree_cache)
				list_move_tail(&c->btree_cache, &t->list);
			break;
		}

		if (!b->accessed &&
		    !mca_reap(b, false)) {
			mca_bucket_free(b);
			mca_data_free(b);
			six_unlock_write(&b->lock);
			six_unlock_intent(&b->lock);
			freed++;
		} else
			b->accessed = 0;
	}

	mutex_unlock(&c->btree_cache_lock);

	bch_time_stats_update(&c->mca_scan_time, start_time);

	trace_bcache_mca_scan(c,
			      touched * c->btree_pages,
			      freed * c->btree_pages,
			      can_free * c->btree_pages,
			      sc->nr_to_scan);

	return (unsigned long) freed * c->btree_pages;
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
	unsigned i;

	closure_init_stack(&cl);

	if (c->btree_cache_shrink.list.next)
		unregister_shrinker(&c->btree_cache_shrink);

	mutex_lock(&c->btree_cache_lock);

#ifdef CONFIG_BCACHE_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);

	free_pages((unsigned long) c->verify_ondisk, ilog2(c->btree_pages));
#endif

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			list_add(&c->btree_roots[i]->list, &c->btree_cache);

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

	mutex_unlock(&c->btree_cache_lock);
}

int bch_btree_cache_alloc(struct cache_set *c)
{
	unsigned i;

	bch_recalc_btree_reserve(c);

	for (i = 0; i < c->btree_cache_reserve; i++)
		if (!mca_bucket_alloc(c, GFP_KERNEL))
			return -ENOMEM;

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHE_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_ondisk = (void *)
		__get_free_pages(GFP_KERNEL, ilog2(c->btree_pages));

	c->verify_data = mca_bucket_alloc(c, GFP_KERNEL);

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

static inline u64 PTR_HASH(const struct bkey *k)
{
	return bkey_i_to_extent_c(k)->v.ptr[0]._val;
}

static struct hlist_head *mca_hash(struct cache_set *c, const struct bkey *k)
{
	return &c->bucket_hash[hash_32(PTR_HASH(k), BUCKET_HASH_BITS)];
}

static inline struct btree *mca_find(struct cache_set *c, const struct bkey *k)
{
	struct btree *b;

	rcu_read_lock();
	hlist_for_each_entry_rcu(b, mca_hash(c, k), hash)
		if (PTR_HASH(&b->key) == PTR_HASH(k))
			goto out;
	b = NULL;
out:
	rcu_read_unlock();
	return b;
}

static int mca_cannibalize_lock(struct cache_set *c, struct closure *cl)
{
	struct task_struct *old;

	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old == NULL || old == current)
		goto success;

	if (!cl) {
		trace_bcache_mca_cannibalize_lock_fail(c, cl);
		return -EINTR;
	}

	closure_wait(&c->mca_wait, cl);

	/* Try again, after adding ourselves to waitlist */
	old = cmpxchg(&c->btree_cache_alloc_lock, NULL, current);
	if (old == NULL || old == current) {
		/* We raced */
		closure_wake_up(&c->mca_wait);
		goto success;
	}

	trace_bcache_mca_cannibalize_lock_fail(c, cl);
	return -EAGAIN;

success:
	trace_bcache_mca_cannibalize_lock(c, cl);
	return 0;
}

static struct btree *mca_cannibalize(struct cache_set *c, struct closure *cl)
{
	struct btree *b;
	int ret;

	ret = mca_cannibalize_lock(c, cl);
	if (ret)
		return ERR_PTR(ret);

	trace_bcache_mca_cannibalize(c, cl);

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, false))
			return b;

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, true))
			return b;

	WARN(1, "btree cache cannibalize failed\n");
	return ERR_PTR(-ENOMEM);
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
		trace_bcache_mca_cannibalize_unlock(c);
		c->btree_cache_alloc_lock = NULL;
		closure_wake_up(&c->mca_wait);
	}
}

static struct btree *mca_alloc(struct cache_set *c, const struct bkey *k,
			       int level, enum btree_id id, struct closure *cl)
{
	struct btree *b = NULL;

	u64 start_time = local_clock();

	mutex_lock(&c->btree_cache_lock);

	if (mca_find(c, k))
		goto out_unlock;

	/* btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (!mca_reap_notrace(b, false))
			goto out;

	/* We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap_notrace(b, false)) {
			mca_data_alloc(b, __GFP_NOWARN|GFP_NOIO);
			if (!b->keys.set[0].data)
				goto err;
			else
				goto out;
		}

	b = mca_bucket_alloc(c, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!six_trylock_intent(&b->lock));
	BUG_ON(!six_trylock_write(&b->lock));
	if (!b->keys.set->data)
		goto err;
out:
	BUG_ON(b->io_mutex.count != 1);

	bkey_copy(&b->key, k);
	list_move(&b->list, &c->btree_cache);
	hlist_del_init_rcu(&b->hash);
	hlist_add_head_rcu(&b->hash, mca_hash(c, k));

	b->flags	= 0;
	b->written	= 0;
	b->level	= level;
	b->btree_id	= id;

	bch_btree_keys_init(&b->keys, b->level
			    ? &bch_btree_interior_node_ops
			    : bch_btree_ops[id],
			    &b->c->expensive_debug_checks);

out_unlock:
	mutex_unlock(&c->btree_cache_lock);

	bch_time_stats_update(&c->mca_alloc_time, start_time);

	return b;
err:
	if (b) {
		six_unlock_write(&b->lock);
		six_unlock_intent(&b->lock);
	}

	b = mca_cannibalize(c, cl);
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
 * the @write parameter.
 */
static struct btree *bch_btree_node_get(struct btree_iter *iter,
					const struct bkey *k,
					int level)
{
	int i = 0;
	struct btree *b;
	BKEY_PADDED(k) tmp;

	/* k points into the parent which we'll unlock, save us a copy */
	bkey_copy(&tmp.k, k);
	k = &tmp.k;

	BUG_ON(level < 0);
retry:
	b = mca_find(iter->c, k);
	if (unlikely(!b)) {
		b = mca_alloc(iter->c, k, level, iter->btree_id, &iter->cl);
		if (!b)
			goto retry;
		if (IS_ERR(b))
			return b;

		/*
		 * If the btree node wasn't cached, we can't drop our lock on
		 * the parent until after it's added to the cache - because
		 * otherwise we could race with a btree_split() freeing the node
		 * we're trying to lock.
		 *
		 * But the deadlock described below doesn't exist in this case,
		 * so it's safe to not drop the parent lock until here:
		 */
		if (btree_node_read_locked(iter, level + 1))
			btree_node_unlock(iter, level + 1);

		bch_btree_node_read(b);
		six_unlock_write(&b->lock);

		if (btree_want_intent(iter, level)) {
			mark_btree_node_intent_locked(iter, level);
		} else {
			mark_btree_node_read_locked(iter, level);
			BUG_ON(!six_trylock_convert(&b->lock, intent, read));
		}
	} else {
		/*
		 * There's a potential deadlock with splits and insertions into
		 * interior nodes we have to avoid:
		 *
		 * The other thread might be holding an intent lock on the node
		 * we want, and they want to update its parent node so they're
		 * going to upgrade their intent lock on the parent node to a
		 * write lock.
		 *
		 * But if we're holding a read lock on the parent, and we're
		 * trying to get the intent lock they're holding, we deadlock.
		 *
		 * So to avoid this we drop the read locks on parent nodes when
		 * we're starting to take intent locks - and handle the race.
		 *
		 * The race is that they might be about to free the node we
		 * want, and dropping our read lock lets them add the
		 * replacement node's pointer to the parent and then free the
		 * old node (the node we're trying to lock).
		 *
		 * After we take the intent lock on the node we want (which
		 * protects against it being freed), we check if we might have
		 * raced (and the node was freed before we locked it) with a
		 * global sequence number for freed btree nodes.
		 */
		if (btree_node_read_locked(iter, level + 1))
			btree_node_unlock(iter, level + 1);

		if (!btree_node_lock(b, iter, level,
				     PTR_HASH(&b->key) != PTR_HASH(k))) {
			if (!btree_node_relock(iter, level + 1)) {
				trace_bcache_btree_intent_lock_fail(b, iter);
				return ERR_PTR(-EINTR);
			}

			goto retry;
		}

		BUG_ON(b->level != level);
	}

	b->accessed = 1;

	for (; i <= b->keys.nsets && b->keys.set[i].size; i++) {
		prefetch(b->keys.set[i].tree);
		prefetch(b->keys.set[i].data);
	}

	for (; i <= b->keys.nsets; i++)
		prefetch(b->keys.set[i].data);

	if (btree_node_io_error(b)) {
		__btree_node_unlock(iter, level, b);
		return ERR_PTR(-EIO);
	}

	BUG_ON(!b->written);

	return b;
}

/* Btree alloc */

void btree_node_free(struct btree *b)
{
	trace_bcache_btree_node_free(b);

	BUG_ON(b == btree_node_root(b));

	six_lock_write(&b->lock);

	if (btree_node_dirty(b))
		btree_complete_write(b, btree_current_write(b));
	clear_bit(BTREE_NODE_dirty, &b->flags);

	cancel_delayed_work(&b->work);

	bch_bucket_free(b->c, &b->key);

	mutex_lock(&b->c->btree_cache_lock);
	mca_bucket_free(b);
	mutex_unlock(&b->c->btree_cache_lock);

	six_unlock_write(&b->lock);
}

/**
 * bch_btree_set_root - update the root in memory and on disk
 *
 * To ensure forward progress, the current task must not be holding any
 * btree node write locks. However, you must hold an intent lock on the
 * old root.
 *
 * Frees the old root.
 *
 * Note: This allocates a journal entry but doesn't add any keys to
 * it.  All the btree roots are part of every journal write, so there
 * is nothing new to be done.  This just guarantees that there is a
 * journal write.
 */
static void bch_btree_set_root(struct btree *b)
{
	struct cache_set *c = b->c;
	struct journal_res res;
	struct closure cl;
	struct btree *old;

	memset(&res, 0, sizeof(res));

	trace_bcache_btree_set_root(b);
	BUG_ON(!b->written);

	old = btree_node_root(b);
	if (old) {
		unsigned u64s = jset_u64s(0);
		bch_journal_res_get(c, &res, u64s, u64s);
		six_lock_write(&old->lock);
	}

	/* Root nodes cannot be reaped */
	mutex_lock(&c->btree_cache_lock);
	list_del_init(&b->list);
	mutex_unlock(&c->btree_cache_lock);

	spin_lock(&c->btree_root_lock);
	btree_node_root(b) = b;
	spin_unlock(&c->btree_root_lock);

	bch_recalc_btree_reserve(c);

	if (old) {
		if (res.ref) {
			closure_init_stack(&cl);
			bch_journal_set_dirty(c);
			bch_journal_res_put(c, &res, &cl);
			closure_sync(&cl);
		}

		six_unlock_write(&old->lock);
	}
}

static struct btree *bch_btree_node_alloc(struct cache_set *c, int level,
					  enum btree_id id,
					  enum alloc_reserve reserve)
{
	BKEY_PADDED(key) k;
	struct btree *b;

	BUG_ON(reserve > RESERVE_METADATA_LAST);

	if (bch_bucket_alloc_set(c, reserve, &k.key,
				 CACHE_SET_META_REPLICAS_WANT(&c->sb),
				 &c->cache_all, NULL))
		BUG();

	BUG_ON(k.key.size);

	b = mca_alloc(c, &k.key, level, id, NULL);
	BUG_ON(IS_ERR_OR_NULL(b));

	bch_check_mark_super(c, &b->key, true);

	b->accessed = 1;
	bch_bset_init_next(&b->keys, b->keys.set->data);
	b->keys.set->data->magic = bset_magic(&c->sb);
	set_btree_node_dirty(b);

	trace_bcache_btree_node_alloc(b);
	return b;
}

struct btree *btree_node_alloc_replacement(struct btree *b,
					   enum alloc_reserve reserve)
{
	struct btree *n;

	n = bch_btree_node_alloc(b->c, b->level, b->btree_id, reserve);
	bch_btree_sort_into(&n->keys, &b->keys,
			    b->keys.ops->key_normalize,
			    &b->c->sort);

	n->key.p = b->key.p;
	trace_bcache_btree_node_alloc_replacement(b, n);

	return n;
}

static int __btree_check_reserve(struct cache_set *c,
				 enum alloc_reserve reserve,
				 unsigned required,
				 struct closure *cl)
{
	struct cache *ca;
	unsigned i;
	int ret;

	rcu_read_lock();

	for_each_cache_rcu(ca, c, i) {
		if (CACHE_STATE(&ca->mi) != CACHE_ACTIVE)
			continue;

		spin_lock(&ca->freelist_lock);

		if (fifo_used(&ca->free[reserve]) < required) {
			trace_bcache_btree_check_reserve_fail(ca, reserve,
					fifo_used(&ca->free[reserve]),
					required, cl);

			if (cl) {
				closure_wait(&c->freelist_wait, cl);
				ret = -EAGAIN;
			} else {
				ret = -ENOSPC;
			}

			spin_unlock(&ca->freelist_lock);
			rcu_read_unlock();
			return ret;
		}

		spin_unlock(&ca->freelist_lock);
	}

	rcu_read_unlock();

	return mca_cannibalize_lock(c, cl);
}

int btree_check_reserve(struct btree *b, struct btree_iter *iter,
			enum alloc_reserve reserve,
			unsigned extra_nodes)
{
	unsigned depth = btree_node_root(b)->level - b->level;

	return __btree_check_reserve(b->c, reserve,
			btree_reserve_required_nodes(depth) + extra_nodes,
			iter ? &iter->cl : NULL);
}

int bch_btree_root_alloc(struct cache_set *c, enum btree_id id,
			 struct closure *writes)
{
	struct closure cl;
	struct btree *b;

	closure_init_stack(&cl);

	while (__btree_check_reserve(c, id, 1, &cl))
		closure_sync(&cl);

	b = bch_btree_node_alloc(c, 0, id, id);

	b->key.p = POS_MAX;
	six_unlock_write(&b->lock);

	bch_btree_node_write(b, writes, NULL);

	bch_btree_set_root(b);
	six_unlock_intent(&b->lock);

	return 0;
}

int bch_btree_root_read(struct cache_set *c, enum btree_id id,
			const struct bkey *k, unsigned level)
{
	struct closure cl;
	struct btree *b;

	closure_init_stack(&cl);

	while (IS_ERR(b = mca_alloc(c, k, level, id, &cl))) {
		if (PTR_ERR(b) != -EAGAIN)
			return PTR_ERR(b);
		closure_sync(&cl);
	}
	BUG_ON(!b);

	bch_btree_node_read(b);
	six_unlock_write(&b->lock);

	if (btree_node_io_error(b)) {
		six_unlock_intent(&b->lock);
		return -EIO;
	}

	bch_btree_set_root(b);
	six_unlock_intent(&b->lock);

	return 0;
}

/**
 * bch_btree_node_rewrite - Rewrite/move a btree node
 *
 * Returns 0 on success, -EINTR or -EAGAIN on failure (i.e.
 * btree_check_reserve() has to wait)
 */
int bch_btree_node_rewrite(struct btree *b, struct btree_iter *iter, bool wait)
{
	struct btree *n, *parent = iter->nodes[b->level + 1];
	int ret;

	iter->locks_want = BTREE_MAX_DEPTH;
	if (!bch_btree_iter_upgrade(iter))
		return -EINTR;

	ret = btree_check_reserve(b, wait ? iter : NULL, iter->btree_id, 1);
	if (ret) {
		trace_bcache_btree_gc_rewrite_node_fail(b);
		return ret;
	}

	n = btree_node_alloc_replacement(b, iter->btree_id);
	six_unlock_write(&n->lock);

	trace_bcache_btree_gc_rewrite_node(b);

	bch_btree_node_write_sync(n, NULL);

	if (parent) {
		ret = bch_btree_insert_node(parent, iter,
					    &keylist_single(&n->key),
					    NULL, NULL, iter->btree_id);
		BUG_ON(ret);
	} else {
		bch_btree_set_root(n);
	}

	btree_node_free(b);

	BUG_ON(iter->nodes[b->level] != b);

	six_unlock_intent(&b->lock);
	btree_iter_node_set(iter, n);
	return 0;
}

/* Btree insertion */

/**
 * bch_btree_insert_and_journal - insert a non-overlapping key into a btree node
 *
 * This is called from bch_insert_fixup_extent().
 *
 * The insert is journalled.
 */
void bch_btree_insert_and_journal(struct btree *b,
				  struct btree_node_iter *node_iter,
				  struct bkey *insert,
				  struct journal_res *res)
{
	struct cache_set *c = b->c;

	bch_bset_insert(&b->keys, node_iter, insert);

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);

		if (c->btree_flush_delay)
			schedule_delayed_work(&b->work,
					      c->btree_flush_delay * HZ);
	}

	if (res->ref ||
	    !test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags)) {
		struct btree_write *w = btree_current_write(b);

		if (!w->journal) {
			w->journal = c->journal.cur_pin;
			atomic_inc(w->journal);
		}
	}

	if (res->ref)
		bch_journal_add_keys(c, res, b->btree_id, insert, b->level);
}

/**
 * btree_insert_key - insert a key into a btree node, handling overlapping extents.
 *
 * The insert is journalled.
 */
static bool btree_insert_key(struct btree_iter *iter, struct btree *b,
			     struct keylist *insert_keys,
			     struct bch_replace_info *replace,
			     struct journal_res *res)
{
	bool dequeue = false;
	struct btree_node_iter *node_iter = &iter->node_iters[b->level];
	struct bkey *insert = bch_keylist_front(insert_keys);
	BKEY_PADDED(key) temp;
	struct bpos done;
	s64 newsize, oldsize = bch_count_data(&b->keys);
	bool do_insert;
	struct bkey *orig = insert;

	BUG_ON(bkey_deleted(insert) && bkey_val_u64s(insert));
	BUG_ON(write_block(b) != btree_bset_last(b));
	BUG_ON(!b->level &&
	       bkey_cmp(bkey_start_pos(insert), iter->pos) < 0);
	bch_btree_node_iter_verify(&b->keys, node_iter);

	if (b->keys.ops->is_extents) {
		bkey_copy(&temp.key, insert);
		insert = &temp.key;

		if (bkey_cmp(insert->p, b->key.p) > 0)
			bch_cut_back(b->key.p, insert);

		do_insert = bch_insert_fixup_extent(b, insert, node_iter,
						    replace, &done, res);
		bch_cut_front(done, orig);
		dequeue = (orig->size == 0);
	} else {
		BUG_ON(bkey_cmp(insert->p, b->key.p) > 0);

		do_insert = bch_insert_fixup_key(b, insert, node_iter,
						 replace, &done, res);
		dequeue = true;
	}

	if (dequeue)
		bch_keylist_dequeue(insert_keys);

	newsize = bch_count_data(&b->keys);
	BUG_ON(newsize != -1 && newsize < oldsize);

	trace_bcache_btree_insert_key(b, insert, replace != NULL, do_insert);

	return do_insert;
}

enum btree_insert_status {
	BTREE_INSERT_NO_INSERT,
	BTREE_INSERT_INSERTED,
	BTREE_INSERT_NEED_SPLIT,
};

static bool have_enough_space(struct btree *b, struct keylist *insert_keys)
{
	/*
	 * For updates to interior nodes, everything on the
	 * keylist has to be inserted atomically.
	 *
	 * For updates to extents, bch_insert_fixup_extent()
	 * needs room for at least three keys to make forward
	 * progress.
	 */
	unsigned u64s = b->level
		? bch_keylist_nkeys(insert_keys)
		: b->keys.ops->is_extents
		? BKEY_EXTENT_MAX_U64s * 3
		: bch_keylist_front(insert_keys)->u64s;

	return u64s <= bch_btree_keys_u64s_remaining(&b->keys);
}

static void verify_keys_sorted(struct keylist *l)
{
#ifdef CONFIG_BCACHE_DEBUG
	struct bkey *k;

	for (k = l->bot;
	     k < l->top && bkey_next(k) < l->top;
	     k = bkey_next(k))
		BUG_ON(bkey_cmp(k->p, bkey_next(k)->p) > 0);
#endif
}

/**
 * bch_btree_insert_keys - insert keys from @insert_keys into btree node @b,
 * until the node is full.
 *
 * If keys couldn't be inserted because @b was full, the caller must split @b
 * and bch_btree_insert_keys() will be called again from btree_split().
 *
 * Caller must either be holding an intent lock on this node only, or intent
 * locks on all nodes all the way up to the root. Caller must not be holding
 * read locks on any nodes.
 */
static enum btree_insert_status
bch_btree_insert_keys(struct btree *b,
		      struct btree_iter *iter,
		      struct keylist *insert_keys,
		      struct bch_replace_info *replace,
		      struct closure *persistent)
{
	bool done = false, inserted = false, need_split = false;
	struct journal_res res = { 0, 0 };
	struct bkey *k = bch_keylist_front(insert_keys);

	verify_keys_sorted(insert_keys);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(iter->nodes[b->level] != b);

	while (!done && !bch_keylist_empty(insert_keys)) {
		/*
		 * We need room to insert at least two keys in the journal
		 * reservation -- the insert key itself, as well as a subset
		 * of it, in the bkey_cmpxchg() or handle_existing_key_newer()
		 * cases
		 */
		unsigned n_min = bch_keylist_front(insert_keys)->u64s;
		unsigned n_max = bch_keylist_nkeys(insert_keys);

		unsigned actual_min = jset_u64s(n_min) * 2;
		unsigned actual_max = max_t(unsigned, actual_min,
					    jset_u64s(n_max));

		if (!b->level &&
		    test_bit(JOURNAL_REPLAY_DONE, &iter->c->journal.flags))
			bch_journal_res_get(iter->c, &res,
					    actual_min, actual_max);

		six_lock_write(&b->lock);

		/* just wrote a set? */
		if (write_block(b) != btree_bset_last(b) &&
		    b->keys.last_set_unwritten)
			bch_btree_init_next(b, iter);

		while (!bch_keylist_empty(insert_keys)) {
			k = bch_keylist_front(insert_keys);

			/* finished for this node */
			if (b->keys.ops->is_extents
			    ? bkey_cmp(bkey_start_pos(k), b->key.p) >= 0
			    : bkey_cmp(k->p, b->key.p) > 0) {
				done = true;
				break;
			}

			if (!have_enough_space(b, insert_keys)) {
				done = true;
				need_split = true;
				break;
			}

			if (!b->level && journal_res_full(&res, k))
				break;

			if (btree_insert_key(iter, b, insert_keys,
					     replace, &res))
				inserted = true;
		}

		six_unlock_write(&b->lock);

		if (res.ref)
			bch_journal_res_put(iter->c, &res,
					    bch_keylist_empty(insert_keys)
					    ? persistent : NULL);
	}

	if (inserted && b->written) {
		/*
		 * Force write if set is too big (or if it's an interior
		 * node, since those aren't journalled yet)
		 */
		if (b->level)
			bch_btree_node_write_sync(b, iter);
		else {
			unsigned long bytes = set_bytes(btree_bset_last(b));

			if (b->io_mutex.count > 0 &&
			    ((max(roundup(bytes, block_bytes(iter->c)),
				  PAGE_SIZE) - bytes < 48) ||
			     bytes > (16 << 10)))
				bch_btree_node_write(b, NULL, iter);
		}
	}

	iter->lock_seq[b->level] = b->lock.state.seq;

	BUG_ON(!bch_keylist_empty(insert_keys) && inserted && b->level);

	return need_split ? BTREE_INSERT_NEED_SPLIT :
		 inserted ? BTREE_INSERT_INSERTED : BTREE_INSERT_NO_INSERT;
}

static int btree_split(struct btree *b,
		       struct btree_iter *iter,
		       struct keylist *insert_keys,
		       struct bch_replace_info *replace,
		       struct closure *persistent,
		       struct keylist *parent_keys,
		       struct closure *stack_cl,
		       enum alloc_reserve reserve)
{
	struct btree *parent = iter->nodes[b->level + 1];
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	struct bset *set1, *set2;
	uint64_t start_time = local_clock();
	struct bkey *k;
	enum btree_insert_status status;
	int ret;

	BUG_ON(!parent && (b != btree_node_root(b)));
	BUG_ON(!btree_node_intent_locked(iter, btree_node_root(b)->level));

	/* After this check we cannot return -EAGAIN anymore */
	ret = btree_check_reserve(b, iter, reserve, 0);
	if (ret) {
		/* If splitting an interior node, we've already split a leaf,
		 * so we should have checked for sufficient reserve. We can't
		 * just restart splitting an interior node since we've already
		 * modified the btree. */
		if (!b->level)
			return ret;
		else
			WARN(1, "insufficient reserve for split\n");
	}

	n1 = btree_node_alloc_replacement(b, reserve);
	set1 = btree_bset_first(n1);

	/*
	 * For updates to interior nodes, we've got to do the insert before we
	 * split because the stuff we're inserting has to be inserted
	 * atomically. Post split, the keys might have to go in different nodes
	 * and the split would no longer be atomic.
	 *
	 * But for updates to leaf nodes (in the extent btree, anyways) - we
	 * can't update the new replacement node while the old node is still
	 * visible. Reason being as we do the update we're updating garbage
	 * collection information on the fly, possibly causing a bucket to
	 * become unreferenced and available to the allocator to reuse - we
	 * don't want that to happen while other threads can still use the old
	 * version of the btree node.
	 */
	if (b->level) {
		six_unlock_write(&n1->lock);

		btree_iter_node_set(iter, n1); /* set temporarily for insert */
		status = bch_btree_insert_keys(n1, iter, insert_keys,
					       replace, persistent);
		BUG_ON(status != BTREE_INSERT_INSERTED);

		iter->nodes[b->level] = b; /* still have b locked */

		six_lock_write(&n1->lock);

		/*
		 * There might be duplicate (deleted) keys after the
		 * bch_btree_insert_keys() call - we need to remove them before
		 * we split, as it would be rather bad if we picked a duplicate
		 * for the pivot.
		 *
		 * Additionally, inserting might overwrite a bunch of existing
		 * keys (i.e. a big discard when there were a bunch of small
		 * extents previously) - we might not want to split after the
		 * insert. Splitting a node that's too small to be split would
		 * be bad (if the node had only one key, we wouldn't be able to
		 * assign the new node a key different from the original node)
		 */
		k = set1->start;
		while (k != bset_bkey_last(set1))
			if (bkey_deleted(k)) {
				set1->u64s -= k->u64s;
				memmove(k, bkey_next(k),
					(void *) bset_bkey_last(set1) -
					(void *) k);
			} else
				k = bkey_next(k);
	}

	/*
	 * Note that on recursive parent_keys == insert_keys, so we can't start
	 * adding new keys to parent_keys before emptying it out (by doing the
	 * insert, which we just did above)
	 */

	if (set_blocks(set1, block_bytes(n1->c)) > btree_blocks(iter->c) * 3 / 4) {
		trace_bcache_btree_node_split(b, set1->u64s);

		n2 = bch_btree_node_alloc(iter->c, b->level,
					  iter->btree_id, reserve);
		set2 = btree_bset_first(n2);

		if (!parent) {
			n3 = bch_btree_node_alloc(iter->c, b->level + 1,
						  iter->btree_id, reserve);

			n3->key.p = POS_MAX;
			six_unlock_write(&n3->lock);
		}

		/*
		 * Has to be a linear search because we don't have an auxiliary
		 * search tree yet
		 */
		for (k = set1->start;
		     ((u64 *) k - set1->_data) < (set1->u64s * 3) / 5;
		     k = bkey_next(k))
			;

		n1->key.p = k->p;

		k = bkey_next(k);

		set2->u64s = (u64 *) bset_bkey_last(set1) - (u64 *) k;
		set1->u64s -= set2->u64s;

		n1->keys.nr_live_u64s = set1->u64s;
		n2->keys.nr_live_u64s = set2->u64s;

		BUG_ON(!set1->u64s);
		BUG_ON(!set2->u64s);

		memcpy(set2->start,
		       bset_bkey_last(set1),
		       set2->u64s * sizeof(u64));

		n2->key.p = b->key.p;

		six_unlock_write(&n1->lock);
		six_unlock_write(&n2->lock);

		bch_keylist_add(parent_keys, &n1->key);
		bch_keylist_add(parent_keys, &n2->key);

		bch_btree_node_write(n2, stack_cl, NULL);

		/*
		 * Just created a new node - if gc is still going to visit the
		 * old node, but not the node we just created, mark it:
		 */
		six_lock_write(&b->lock);
		if (gc_will_visit_node(b->c, n2) &&
		    !gc_will_visit_node(b->c, n1))
			btree_gc_mark_node(b->c, n1, NULL);
		six_unlock_write(&b->lock);
	} else {
		trace_bcache_btree_node_compact(b, set1->u64s);

		six_unlock_write(&n1->lock);
		bch_keylist_add(parent_keys, &n1->key);
	}

	bch_btree_node_write(n1, stack_cl, NULL);

	if (n3) {
		/* Depth increases, make a new root */
		mark_btree_node_intent_locked(iter, n3->level);
		btree_iter_node_set(iter, n3);

		bch_btree_insert_keys(n3, iter, parent_keys, NULL, false);
		btree_iter_node_set(iter, n3);

		bch_btree_node_write(n3, stack_cl, NULL);

		closure_sync(stack_cl);

		bch_btree_set_root(n3);
	} else if (!parent) {
		BUG_ON(parent_keys->start_keys_p
		       != &parent_keys->inline_keys[0]);
		bch_keylist_init(parent_keys);

		/* Root filled up but didn't need to be split */
		closure_sync(stack_cl);

		bch_btree_set_root(n1);
	} else {
		/* Split a non root node */
		closure_sync(stack_cl);

		ret = __bch_btree_insert_node(parent, iter, parent_keys,
					      NULL, NULL, reserve,
					      parent_keys, stack_cl);
		BUG_ON(ret || !bch_keylist_empty(parent_keys));
	}

	btree_node_free(b);

	/* Update iterator, and finish insert now that new nodes are visible: */
	BUG_ON(iter->nodes[b->level] != b);

	six_unlock_intent(&b->lock);
	btree_iter_node_set(iter, n1);

	if (!n1->level)
		bch_btree_insert_keys(n1, iter, insert_keys,
				      replace, persistent);

	if (n2 &&
	    bkey_cmp(iter->pos, n1->key.p) > 0) {
		six_unlock_intent(&n1->lock);
		btree_iter_node_set(iter, n2);

		if (!n2->level)
			bch_btree_insert_keys(n2, iter, insert_keys,
					      replace, persistent);
	} else if (n2) {
		six_unlock_intent(&n2->lock);
	}

	bch_time_stats_update(&iter->c->btree_split_time, start_time);

	return 0;
}

static int __bch_btree_insert_node(struct btree *b,
				   struct btree_iter *iter,
				   struct keylist *insert_keys,
				   struct bch_replace_info *replace,
				   struct closure *persistent,
				   enum alloc_reserve reserve,
				   struct keylist *split_keys,
				   struct closure *stack_cl)
{
	BUG_ON(iter->nodes[b->level] != b);
	BUG_ON(!btree_node_intent_locked(iter, b->level));
	BUG_ON(b->level &&
	       !btree_node_intent_locked(iter, btree_node_root(b)->level));
	BUG_ON(b->level && replace);
	BUG_ON(!b->written);

	if (bch_btree_insert_keys(b, iter, insert_keys, replace,
				  persistent) == BTREE_INSERT_NEED_SPLIT) {
		if (!b->level) {
			iter->locks_want = BTREE_MAX_DEPTH;
			if (!bch_btree_iter_upgrade(iter))
				return -EINTR;
		}

		return btree_split(b, iter, insert_keys, replace, persistent,
				   split_keys, stack_cl, reserve);
	}

	return 0;
}

/**
 * bch_btree_insert_node - insert bkeys into a given btree node
 *
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 * @persistent:		if not null, @persistent will wait on journal write
 * @reserve:		btree node reserve
 *
 * Inserts as many keys as it can into a given btree node, splitting it if full.
 * If a split occurred, this function will return early. This can only happen for
 * leaf nodes -- inserts into interior nodes have to be atomic.
 */
int bch_btree_insert_node(struct btree *b,
			  struct btree_iter *iter,
			  struct keylist *insert_keys,
			  struct bch_replace_info *replace,
			  struct closure *persistent,
			  enum alloc_reserve reserve)
{
	struct closure stack_cl;
	struct keylist split_keys;

	closure_init_stack(&stack_cl);
	bch_keylist_init(&split_keys);

	if (!reserve)
		reserve = iter->btree_id;

	return __bch_btree_insert_node(b, iter, insert_keys, replace,
				       persistent, reserve,
				       &split_keys, &stack_cl);
}

/**
 * bch_btree_insert_at - insert bkeys starting at a given btree node
 * @iter:		btree iterator
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 * @persistent:		if not null, @persistent will wait on journal write
 * @reserve:		btree node reserve
 * @flags:		insert flags, currently only BTREE_INSERT_ATOMIC
 *
 * This is top level for common btree insertion/index update code. The control
 * flow goes roughly like:
 *
 * bch_btree_insert_at -- split keys that span interior nodes
 *   bch_btree_insert_node -- split btree nodes when full
 *     btree_split
 *     bch_btree_insert_keys -- get and put journal reservations
 *       btree_insert_key -- call fixup and remove key from keylist
 *         bch_insert_fixup_extent -- handle overlapping extents
 *           bch_btree_insert_and_journal -- add the key to the journal
 *             bch_bset_insert -- actually insert into the bset
 *
 * This function will split keys that span multiple nodes, calling
 * bch_btree_insert_node() for each one. It will not return until all keys
 * have been inserted, or an insert has failed.
 *
 * @persistent will only wait on the journal write if the full keylist was
 * inserted.
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again.
 * -EROFS: cache set read only
 */
int bch_btree_insert_at(struct btree_iter *iter,
			struct keylist *insert_keys,
			struct bch_replace_info *replace,
			struct closure *persistent,
			enum alloc_reserve reserve,
			unsigned flags)
{
	int ret = -EINTR;

	BUG_ON(iter->level);

	if (!percpu_ref_tryget(&iter->c->writes))
		return -EROFS;

	iter->locks_want = 0;
	if (!bch_btree_iter_upgrade(iter))
		goto traverse;

	while (1) {
		ret = bch_btree_insert_node(iter->nodes[0], iter, insert_keys,
					    replace, persistent, reserve);
traverse:
		if (ret == -EAGAIN)
			bch_btree_iter_unlock(iter);

		if (bch_keylist_empty(insert_keys) ||
		    (flags & BTREE_INSERT_ATOMIC) ||
		    ret == -EROFS)
			break;

		bch_btree_iter_set_pos(iter,
			bkey_start_pos(bch_keylist_front(insert_keys)));

		ret = bch_btree_iter_traverse(iter);
		if (ret)
			break;
	}
	percpu_ref_put(&iter->c->writes);

	return ret;
}

/**
 * bch_btree_insert_check_key - insert dummy key into btree
 *
 * We insert a random key on a cache miss, then compare exchange on it
 * once the cache promotion or backing device read completes. This
 * ensures that if this key is written to after the read, the read will
 * lose and not overwrite the key with stale data.
 *
 * Return values:
 * -EAGAIN: @iter->cl was put on a waitlist waiting for btree node allocation
 * -EINTR: btree node was changed while upgrading to write lock
 */
int bch_btree_insert_check_key(struct btree_iter *iter, struct bkey *check_key)
{
	struct bkey_i_cookie *cookie;
	BKEY_PADDED(key) tmp;

	check_key->type = KEY_TYPE_COOKIE;
	set_bkey_val_bytes(check_key, sizeof(struct bch_cookie));

	cookie = bkey_i_to_cookie(check_key);
	get_random_bytes(&cookie->v, sizeof(cookie->v));

	bkey_copy(&tmp.key, check_key);

	bch_btree_node_iter_init(&iter->nodes[0]->keys,
				 &iter->node_iters[0],
				 bkey_start_pos(check_key));

	return bch_btree_insert_at(iter, &keylist_single(&tmp.key), NULL,
				   NULL, iter->btree_id, BTREE_INSERT_ATOMIC);
}

/**
 * bch_btree_insert - insert keys into the extent btree
 * @c:			pointer to struct cache_set
 * @id:			btree to insert into
 * @reserve:		reserve to allocate btree node from
 * @insert_keys:	list of keys to insert
 * @replace:		old key for compare exchange (+ stats)
 */
int bch_btree_insert(struct cache_set *c, enum btree_id id,
		     struct keylist *keys, struct bch_replace_info *replace,
		     struct closure *persistent)
{
	struct btree_iter iter;
	int ret, ret2;

	bch_btree_iter_init(&iter, c, id,
			    bkey_start_pos(bch_keylist_front(keys)));

	ret = bch_btree_iter_traverse(&iter);
	if (unlikely(ret))
		goto out;

	ret = bch_btree_insert_at(&iter, keys, replace, persistent, 0, 0);
out:	ret2 = bch_btree_iter_unlock(&iter);

	return ret ?: ret2;
}

/* Btree iterator: */

int bch_btree_iter_unlock(struct btree_iter *iter)
{
	unsigned l;

	for (l = 0; l < ARRAY_SIZE(iter->nodes); l++)
		btree_node_unlock(iter, l);

	bch_cannibalize_unlock(iter->c);
	closure_sync(&iter->cl);

	return iter->error;
}

/* peek_all() doesn't skip deleted keys */
static const struct bkey *__btree_iter_peek_all(struct btree_iter *iter)
{
	struct bkey *k =
		bch_btree_node_iter_peek_all(&iter->node_iters[iter->level]);

	if (k && expensive_debug_checks(iter->c))
		bkey_debugcheck(iter->nodes[iter->level], k);

	return k;
}

static const struct bkey *__btree_iter_peek(struct btree_iter *iter)
{
	const struct bkey *ret;

	while (1) {
		ret = __btree_iter_peek_all(iter);
		if (!ret || !bkey_deleted(ret))
			break;

		bch_btree_node_iter_next_all(&iter->node_iters[iter->level]);
	}

	return ret;
}

static bool btree_iter_cmp(struct btree_iter *iter,
			   struct bpos pos, struct bpos k)
{
	return iter->is_extents
		? bkey_cmp(pos, k) < 0
		: bkey_cmp(pos, k) <= 0;
}

static inline bool is_btree_node(struct btree_iter *iter, unsigned l)
{
	return ((unsigned long) iter->nodes[l]) > 1;
}

static void btree_iter_lock_root(struct btree_iter *iter, struct bpos pos)
{
	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	memset(iter->nodes, 0, sizeof(iter->nodes));

	while (1) {
		struct btree *b = iter->c->btree_roots[iter->btree_id];

		iter->level = b->level;

		if (btree_node_lock(b, iter, iter->level,
				    (b != iter->c->btree_roots[iter->btree_id]))) {
			__btree_iter_node_set(iter, b, pos);
			break;
		}
	}
}

static int btree_iter_down(struct btree_iter *iter, struct bpos pos)
{
	const struct bkey *k = __btree_iter_peek(iter);
	struct btree *b = bch_btree_node_get(iter, k, iter->level - 1);

	if (unlikely(IS_ERR(b)))
		return PTR_ERR(b);

	--iter->level;
	__btree_iter_node_set(iter, b, pos);
	return 0;
}

static void btree_iter_up(struct btree_iter *iter)
{
	btree_node_unlock(iter, iter->level++);
}

/*
 * This is the main state machine for walking down the btree - walks down to a
 * specified depth
 */
static int __bch_btree_iter_traverse(struct btree_iter *iter, unsigned l,
				     struct bpos pos)
{
	if (!iter->nodes[iter->level])
		return 0;

	cond_resched();
retry:
	/*
	 * If the current node isn't locked, go up until we have a locked node
	 * or run out of nodes:
	 */
	while (iter->nodes[iter->level] &&
	       !(is_btree_node(iter, iter->level) &&
		 btree_node_relock(iter, iter->level) &&
		 btree_iter_cmp(iter, pos, iter->nodes[iter->level]->key.p)))
		btree_iter_up(iter);

	if (iter->nodes[iter->level]) {
		const struct bkey *k;

		while ((k = __btree_iter_peek_all(iter)) &&
		       !btree_iter_cmp(iter, pos, k->p))
			bch_btree_node_iter_next_all(&iter->node_iters[iter->level]);
	}

	/*
	 * Note: iter->nodes[iter->level] may be temporarily NULL here - that
	 * would indicate to other code that we got to the end of the btree,
	 * here it indicates that relocking the root failed - it's critical that
	 * btree_iter_lock_root() comes next and that it can't fail
	 */
	while (iter->level > l)
		if (iter->nodes[iter->level]) {
			int ret = btree_iter_down(iter, pos);
			if (unlikely(ret)) {
				bch_btree_iter_unlock(iter);

				/*
				 * We just dropped all our locks - so if we need
				 * intent locks, make sure to get them again:
				 */
				if (ret == -EAGAIN || ret == -EINTR) {
					bch_btree_iter_upgrade(iter);
					goto retry;
				}

				iter->error = ret;
				iter->level = BTREE_MAX_DEPTH;
				return ret;
			}
		} else {
			btree_iter_lock_root(iter, pos);
		}

	return 0;
}

static int bch_btree_iter_traverse(struct btree_iter *iter)
{
	return __bch_btree_iter_traverse(iter, iter->level, iter->pos);
}

/* Iterate across nodes (leaf and interior nodes) */

struct btree *bch_btree_iter_peek_node(struct btree_iter *iter)
{
	struct btree *b;

	BUG_ON(iter->is_extents);

	bch_btree_iter_traverse(iter);

	if ((b = iter->nodes[iter->level])) {
		BUG_ON(bkey_cmp(b->key.p, iter->pos) < 0);
		iter->pos = b->key.p;
	}

	return b;
}

struct btree *bch_btree_iter_next_node(struct btree_iter *iter)
{
	struct btree *b;
	int ret;

	BUG_ON(iter->is_extents);

	btree_iter_up(iter);

	if (!iter->nodes[iter->level])
		return NULL;

	/* parent node usually won't be locked: redo traversal if necessary */
	ret = bch_btree_iter_traverse(iter);
	if (ret)
		return NULL;

	b = iter->nodes[iter->level];

	if (bkey_cmp(iter->pos, b->key.p) < 0) {
		struct bpos pos = bkey_successor(iter->pos);

		__bch_btree_iter_traverse(iter, 0, pos);
		b = iter->nodes[iter->level];
	}

	iter->pos = b->key.p;

	return b;
}

/* Iterate across keys (in leaf nodes only) */

void bch_btree_iter_set_pos(struct btree_iter *iter, struct bpos new_pos)
{
	BUG_ON(bkey_cmp(new_pos, iter->pos) < 0);
	iter->pos = new_pos;
}

static struct bpos __bch_btree_iter_advance_pos(struct btree_iter *iter,
						struct bpos pos)
{
	if (iter->btree_id == BTREE_ID_INODES) {
		pos.inode++;
		pos.offset = 0;
	} else if (iter->btree_id != BTREE_ID_EXTENTS) {
		pos = bkey_successor(pos);
	}

	return pos;
}

void bch_btree_iter_advance_pos(struct btree_iter *iter)
{
	bch_btree_iter_set_pos(iter,
		__bch_btree_iter_advance_pos(iter, iter->k.p));
}

const struct bkey *bch_btree_iter_peek(struct btree_iter *iter)
{
	const struct bkey *k;
	struct bpos pos = iter->pos;
	int ret;

	while (1) {
		ret = __bch_btree_iter_traverse(iter, 0, pos);
		if (ret)
			return NULL;

		if (likely(k = __btree_iter_peek(iter))) {
			BUG_ON(bkey_cmp(k->p, pos) < 0);
			iter->k = *k;
			return k;
		}

		pos = iter->nodes[0]->key.p;

		if (!bkey_cmp(pos, POS_MAX))
			return NULL;

		pos = __bch_btree_iter_advance_pos(iter, pos);
	}
}

const struct bkey *bch_btree_iter_peek_with_holes(struct btree_iter *iter)
{
	const struct bkey *k;
	int ret;

	while (1) {
		ret = __bch_btree_iter_traverse(iter, 0, iter->pos);
		if (ret)
			return NULL;

		k = bch_btree_node_iter_peek_all(iter->node_iters);
recheck:
		if (!k || bkey_cmp(bkey_start_pos(k), iter->pos) > 0) {
			/* hole */
			bkey_init(&iter->k);
			iter->k.p = iter->pos;

			if (!k)
				k = &iter->nodes[0]->key;

			if (iter->btree_id == BTREE_ID_EXTENTS) {
				if (iter->k.p.offset == KEY_OFFSET_MAX) {
					iter->pos = bkey_successor(iter->pos);
					goto recheck;
				}

				bch_key_resize(&iter->k,
				       min_t(u64, KEY_SIZE_MAX,
					     (k->p.inode == iter->k.p.inode
					      ? bkey_start_offset(k) : KEY_OFFSET_MAX) -
					     iter->k.p.offset));

				BUG_ON(!iter->k.size);
			}

			return &iter->k;
		} else if (!bkey_deleted(k)) {
			iter->k = *k;
			return k;
		} else {
			bch_btree_node_iter_next_all(iter->node_iters);
		}
	}

	BUG_ON(!iter->error &&
	       (iter->btree_id != BTREE_ID_INODES
		? bkey_cmp(iter->pos, POS_MAX)
		: iter->pos.inode != KEY_INODE_MAX));

	return NULL;
}

void bch_btree_iter_init(struct btree_iter *iter, struct cache_set *c,
			 enum btree_id btree_id, struct bpos pos)
{
	closure_init_stack(&iter->cl);

	iter->level			= 0;
	iter->is_extents		= btree_id == BTREE_ID_EXTENTS;
	iter->nodes_locked		= 0;
	iter->nodes_intent_locked	= 0;
	iter->locks_want		= -1;
	iter->btree_id			= btree_id;
	iter->error			= 0;
	iter->c				= c;
	iter->pos			= pos;
	iter->nodes[iter->level]	= (void *) 1;
	iter->nodes[iter->level + 1]	= NULL;
}
