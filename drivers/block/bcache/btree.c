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
#include "btree.h"
#include "debug.h"
#include "request.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/hash.h>
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
 * Make sure all allocations get charged to the root cgroup
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

const char * const bcache_insert_types[] = {
	"read", "write", "writeback", "undirty", "replay"
};

#define MAX_NEED_GC		64
#define MAX_SAVE_PRIO		72

#define PTR_DIRTY_BIT		(((uint64_t) 1 << 36))

#define PTR_HASH(c, k)							\
	(((k)->ptr[0] >> c->bucket_bits) | PTR_GEN(k, 0))

static struct workqueue_struct *btree_wq;

void btree_op_init_stack(struct btree_op *op)
{
	memset(op, 0, sizeof(struct btree_op));
	closure_init_stack(&op->cl);
	op->lock = -1;
	keylist_init(&op->keys);
}

/* Btree key manipulation */

static void bkey_put(struct cache_set *c, struct bkey *k, int write, int level)
{
	if ((level && k->key) ||
	    (!level && write != INSERT_UNDIRTY))
		__bkey_put(c, k);
}

/* Btree IO */

static uint64_t btree_csum_set(struct btree *b, struct bset *i)
{
	uint64_t crc = b->key.ptr[0];
	void *data = (void *) i + 8, *end = end(i);

	crc = crc64_update(crc, data, end - data);
	return crc ^ 0xffffffffffffffff;
}

static void btree_bio_endio(struct bio *bio, int error)
{
	struct btree *b = container_of(bio->bi_private, struct btree, io.cl);

	if (error)
		set_btree_node_io_error(b);

	bcache_endio(b->c, bio, error, (bio->bi_rw & WRITE)
		     ? "writing btree" : "reading btree");
}

static void btree_bio_init(struct btree *b)
{
	BUG_ON(b->bio);
	b->bio = bbio_alloc(b->c);

	bio_get(b->bio);
	b->bio->bi_end_io	= btree_bio_endio;
	b->bio->bi_private	= &b->io.cl;
}

void btree_read_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io.cl);
	struct bset *i = b->sets[0].data;
	struct btree_iter *iter = b->c->fill_iter;
	const char *err = "bad btree header";
	BUG_ON(b->nsets || b->written);

	bbio_free(b->bio, b->c);
	b->bio = NULL;

	mutex_lock(&b->c->fill_lock);
	iter->used = 0;

	if (btree_node_io_error(b) ||
	    !i->seq)
		goto err;

	for (;
	     b->written < btree_blocks(b) && i->seq == b->sets[0].data->seq;
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
		if (i != b->sets[0].data && !i->keys)
			goto err;

		btree_iter_push(iter, i->start, end(i));

		b->written += set_blocks(i, b->c);
	}

	err = "corrupted btree";
	for (i = write_block(b);
	     index(i, b) < btree_blocks(b);
	     i = ((void *) i) + block_bytes(b->c))
		if (i->seq == b->sets[0].data->seq)
			goto err;

	__btree_sort(b, 0, NULL, iter, true);

	i = b->sets[0].data;
	err = "short btree key";
	if (b->sets[0].size &&
	    bkey_cmp(&b->key, &b->sets[0].end) < 0)
		goto err;

	if (0) {
err:		set_btree_node_io_error(b);
		cache_set_error(b->c, "%s at bucket %lu, block %zu, %u keys",
				err, PTR_BUCKET_NR(b->c, &b->key, 0),
				index(i, b), i->keys);
	}

	mutex_unlock(&b->c->fill_lock);

	spin_lock(&b->c->btree_read_time_lock);
	time_stats_update(&b->c->btree_read_time, b->io_start_time);
	spin_unlock(&b->c->btree_read_time_lock);

	smp_wmb(); /* read_done is our write lock */
	set_btree_node_read_done(b);

	closure_return(cl);
}

static void btree_read_resubmit(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io.cl);

	submit_bbio_split(b->bio, b->c, &b->key, 0);
	continue_at(&b->io.cl, btree_read_done, system_wq);
}

void btree_read(struct btree *b)
{
	BUG_ON(b->nsets || b->written);

	if (!closure_trylock(&b->io.cl, &b->c->cl))
		BUG();

	b->io_start_time = local_clock();

	btree_bio_init(b);
	b->bio->bi_rw	= REQ_META|READ_SYNC;
	b->bio->bi_size	= KEY_SIZE(&b->key) << 9;

	bio_map(b->bio, b->sets[0].data);

	pr_debug("%s", pbtree(b));
	trace_bcache_btree_read(b->bio);

	if (submit_bbio_split(b->bio, b->c, &b->key, 0))
		continue_at(&b->io.cl, btree_read_resubmit, system_wq);

	continue_at(&b->io.cl, btree_read_done, system_wq);
}

static void btree_complete_write(struct btree *b, struct btree_write *w)
{
	if (w->prio_blocked &&
	    !atomic_sub_return(w->prio_blocked, &b->c->prio_blocked))
		closure_wake_up(&b->c->bucket_wait);

	if (w->journal) {
		atomic_dec_bug(w->journal);
		__closure_wake_up(&b->c->journal.wait);
	}

	if (w->owner)
		closure_put(w->owner);

	w->prio_blocked	= 0;
	w->journal	= NULL;
	w->owner	= NULL;
}

static void __btree_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io.cl);
	struct btree_write *w = btree_prev_write(b);

	bbio_free(b->bio, b->c);
	b->bio = NULL;
	btree_complete_write(b, w);

	if (btree_node_dirty(b))
		queue_delayed_work(btree_wq, &b->work,
				   msecs_to_jiffies(30000));

	closure_return(cl);
}

static void btree_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io.cl);
	struct bio_vec *bv;
	int n;

	__bio_for_each_segment(bv, b->bio, n, 0)
		__free_page(bv->bv_page);

	__btree_write_done(cl);
}

static void do_btree_write(struct btree *b)
{
	struct closure *cl = &b->io.cl;
	struct bset *i = b->sets[b->nsets].data;
	BKEY_PADDED(key) k;

	i->version	= BCACHE_BSET_VERSION;
	i->csum		= btree_csum_set(b, i);

	btree_bio_init(b);
	b->bio->bi_rw	= REQ_META|WRITE_SYNC;
	b->bio->bi_size	= set_blocks(i, b->c) * block_bytes(b->c);
	bio_map(b->bio, i);

	bkey_copy(&k.key, &b->key);
	SET_PTR_OFFSET(&k.key, 0, PTR_OFFSET(&k.key, 0) + bset_offset(b, i));

	if (!bio_alloc_pages(b->bio, GFP_NOIO)) {
		int j;
		struct bio_vec *bv;
		void *base = (void *) ((unsigned long) i & ~(PAGE_SIZE - 1));

		bio_for_each_segment(bv, b->bio, j)
			memcpy(page_address(bv->bv_page),
			       base + j * PAGE_SIZE, PAGE_SIZE);

		trace_bcache_btree_write(b->bio);
		submit_bbio_split(b->bio, b->c, &k.key, 0);

		continue_at(cl, btree_write_done, NULL);
	} else {
		bio_map(b->bio, i);

		trace_bcache_btree_write(b->bio);
		submit_bbio_split(b->bio, b->c, &k.key, 0);

		closure_sync(cl);
		__btree_write_done(cl);
	}
}

static void __btree_write(struct btree *b)
{
	struct bset *i = b->sets[b->nsets].data;

	BUG_ON(current->bio_list);

	closure_lock(&b->io, &b->c->cl);
	__cancel_delayed_work(&b->work);

	clear_bit(BTREE_NODE_dirty,	 &b->flags);
	change_bit(BTREE_NODE_write_idx, &b->flags);

	check_key_order(b, i);
	BUG_ON(b->written && !i->keys);

	do_btree_write(b);

	pr_debug("%s block %i keys %i", pbtree(b), b->written, i->keys);

	b->written += set_blocks(i, b->c);
	atomic_long_add(set_blocks(i, b->c) * b->c->sb.block_size,
			&PTR_CACHE(b->c, &b->key, 0)->btree_sectors_written);

	if (!btree_sort_lazy(b))
		bset_build_tree(b, &b->sets[b->nsets]);
}

static void btree_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);

	down_write(&b->lock);

	if (btree_node_dirty(b))
		__btree_write(b);
	up_write(&b->lock);
}

void btree_write(struct btree *b, bool now, struct btree_op *op)
{
	struct bset *i = b->sets[b->nsets].data;
	struct btree_write *w = btree_current_write(b);

	BUG_ON(!now && !op);
	BUG_ON(b->written &&
	       (b->written >= btree_blocks(b) ||
		i->seq != b->sets[0].data->seq ||
		!i->keys));

	if (!btree_node_dirty(b)) {
		set_btree_node_dirty(b);
		queue_delayed_work(btree_wq, &b->work,
				   msecs_to_jiffies(30000));
	}

	w->prio_blocked += b->prio_blocked;
	b->prio_blocked = 0;

	if (op && op->journal && !b->level) {
		if (w->journal &&
		    journal_pin_cmp(b->c, w, op)) {
			atomic_dec_bug(w->journal);
			w->journal = NULL;
		}

		if (!w->journal) {
			w->journal = op->journal;
			atomic_inc(w->journal);
		}
	}

	/* Force write if set is too big */
	if (now ||
	    b->level ||
	    set_bytes(i) > PAGE_SIZE - 48) {
		if (op && now) {
			/* Must wait on multiple writes */
			BUG_ON(w->owner);
			w->owner = &op->cl;
			closure_get(&op->cl);
		}

		__btree_write(b);
	}
	BUG_ON(!b->written);
}

/*
 * Btree in memory cache - allocation/freeing
 * mca -> memory cache
 */

#define mca_reserve(c)	((c->root ? c->root->level : 1) * 8 + 16)
#define mca_can_free(c)						\
	max_t(int, 0, c->bucket_cache_used - mca_reserve(c))

static void mca_data_free(struct btree *b)
{
	struct bset_tree *t = b->sets;
	BUG_ON(!closure_is_unlocked(&b->io.cl));

	if (bset_prev_bytes(b) < PAGE_SIZE)
		kfree(t->prev);
	else
		free_pages((unsigned long) t->prev,
			   get_order(bset_prev_bytes(b)));

	if (bset_tree_bytes(b) < PAGE_SIZE)
		kfree(t->tree);
	else
		free_pages((unsigned long) t->tree,
			   get_order(bset_tree_bytes(b)));

	free_pages((unsigned long) t->data, b->page_order);

	t->prev = NULL;
	t->tree = NULL;
	t->data = NULL;
	list_move(&b->list, &b->c->btree_cache_freed);
	b->c->bucket_cache_used--;
}

static void mca_bucket_free(struct btree *b)
{
	BUG_ON(btree_node_dirty(b));

	b->key.ptr[0] = 0;
	hlist_del_init_rcu(&b->hash);
	list_move(&b->list, &b->c->btree_cache_freeable);
}

static void mca_data_alloc(struct btree *b, struct bkey *k, gfp_t gfp)
{
	struct bset_tree *t = b->sets;
	BUG_ON(t->data);

	b->page_order = ilog2(max_t(unsigned, b->c->btree_pages,
				    KEY_SIZE(k) / PAGE_SECTORS ?: 1));

	t->data = (void *) __get_free_pages(gfp, b->page_order);
	if (!t->data)
		goto err;

	t->tree = bset_tree_bytes(b) < PAGE_SIZE
		? kmalloc(bset_tree_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_tree_bytes(b)));
	if (!t->tree)
		goto err;

	t->prev = bset_prev_bytes(b) < PAGE_SIZE
		? kmalloc(bset_prev_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_prev_bytes(b)));
	if (!t->prev)
		goto err;

	list_move(&b->list, &b->c->btree_cache);
	b->c->bucket_cache_used++;
	return;
err:
	mca_data_free(b);
}

static struct btree *mca_bucket_alloc(struct cache_set *c,
				      struct bkey *k, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	init_rwsem(&b->lock);
	INIT_LIST_HEAD(&b->list);
	INIT_DELAYED_WORK(&b->work, btree_write_work);
	b->c = c;
	closure_init_unlocked(&b->io);

	mca_data_alloc(b, k, gfp);
	return b->sets[0].data ? b : NULL;
}

static int mca_reap(struct btree *b, struct closure *cl)
{
	lockdep_assert_held(&b->c->bucket_lock);

	if (!down_write_trylock(&b->lock))
		return -1;

	BUG_ON(btree_node_dirty(b) && !b->sets[0].data);

	if (cl && btree_node_dirty(b))
		btree_write(b, true, NULL);

	if (cl)
		closure_wait_event_async(&b->io.wait, cl,
			 atomic_read(&b->io.cl.remaining) == -1);

	if (btree_node_dirty(b) ||
	    atomic_read(&b->io.cl.remaining) != -1 ||
	    work_pending(&b->work.work)) {
		rw_unlock(true, b);
		return -EAGAIN;
	}

	return 0;
}

static int bcache_shrink_buckets(struct shrinker *shrink,
				 struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set, shrink);
	struct btree *b, *t;
	unsigned i;
	int nr, orig_nr = sc->nr_to_scan;

	if (c->shrinker_disabled)
		return 0;

	/*
	 * If nr == 0, we're supposed to return the number of items we have
	 * cached. Not allowed to return -1.
	 */
	if (!orig_nr)
		goto out;

	/* Return -1 if we can't do anything right now */
	if (!mutex_trylock(&c->bucket_lock))
		return -1;

	if (c->try_harder) {
		mutex_unlock(&c->bucket_lock);
		return -1;
	}

	if (list_empty(&c->btree_cache)) {
		/*
		 * Can happen right when we first start up, before we've read in
		 * any btree nodes
		 */
		mutex_unlock(&c->bucket_lock);
		return 0;
	}

	orig_nr /= c->btree_pages;
	nr = orig_nr = min_t(int, orig_nr, mca_can_free(c));

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		if (!nr)
			break;

		if (++i > 3 &&
		    !mca_reap(b, NULL)) {
			mca_data_free(b);
			rw_unlock(true, b);
			--nr;
		}
	}

	for (i = c->bucket_cache_used;
	     i && nr;
	     --i) {
		b = list_first_entry(&c->btree_cache, struct btree, list);
		list_rotate_left(&c->btree_cache);

		if (!b->accessed &&
		    !mca_reap(b, NULL)) {
			mca_bucket_free(b);
			mca_data_free(b);
			rw_unlock(true, b);
			--nr;
		} else
			b->accessed = 0;
	}

	mutex_unlock(&c->bucket_lock);
out:
	return mca_can_free(c) * c->btree_pages;
}

void bcache_btree_cache_free(struct cache_set *c)
{
	struct btree *b;
	struct closure cl;
	closure_init_stack(&cl);

	if (c->shrink.list.next)
		unregister_shrinker(&c->shrink);

	mutex_lock(&c->bucket_lock);

#ifdef CONFIG_BCACHE_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);
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

	mutex_unlock(&c->bucket_lock);
}

int bcache_btree_cache_alloc(struct cache_set *c)
{
	/* XXX: doesn't check for errors */

	closure_init_unlocked(&c->gc);

	for (int i = 0; i < mca_reserve(c); i++)
		mca_bucket_alloc(c, &ZERO_KEY, GFP_KERNEL);

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHE_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_data = mca_bucket_alloc(c, &ZERO_KEY, GFP_KERNEL);

	if (c->verify_data &&
	    c->verify_data->sets[0].data)
		list_del_init(&c->verify_data->list);
	else
		c->verify_data = NULL;
#endif

	c->shrink.shrink = bcache_shrink_buckets;
	c->shrink.seeks = 3;
	register_shrinker(&c->shrink);

	return 0;
}

/* Btree in memory cache - hash table */

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

static struct btree *alloc_bucket(struct cache_set *c, struct bkey *k,
				  int level, struct closure *cl)
{
	struct btree *b, *i;
	unsigned page_order = ilog2(KEY_SIZE(k) / PAGE_SECTORS ?: 1);

	lockdep_assert_held(&c->bucket_lock);
retry:
	if (find_bucket(c, k))
		return NULL;

	/* btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (page_order <= b->page_order &&
		    !b->key.ptr[0] &&
		    !mca_reap(b, NULL))
			goto out;

	/* We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap(b, NULL)) {
			mca_data_alloc(b, k, __GFP_NOWARN|GFP_NOIO);
			if (!b->sets[0].data) {
				rw_unlock(true, b);
				goto err;
			} else
				goto out;
		}

	b = mca_bucket_alloc(c, k, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!down_write_trylock(&b->lock));
out:
	BUG_ON(!closure_is_unlocked(&b->io.cl));

	bkey_copy(&b->key, k);
	list_move(&b->list, &c->btree_cache);
	hlist_del_init_rcu(&b->hash);
	hlist_add_head_rcu(&b->hash, hash_bucket(c, k));
	lock_set_subclass(&b->lock.dep_map, level + 1, _THIS_IP_);

	b->flags	= 0;
	b->level	= level;
	b->written	= 0;
	b->nsets	= 0;
	for (int i = 0; i < MAX_BSETS; i++)
		b->sets[i].size = 0;
	for (int i = 1; i < MAX_BSETS; i++)
		b->sets[i].data = NULL;

	return b;
err:
	if (current->bio_list)
		return ERR_PTR(-EAGAIN);

	if (!cl)
		return ERR_PTR(-ENOMEM);

	if (c->try_harder && c->try_harder != cl) {
		closure_wait_event_async(&c->try_wait, cl, !c->try_harder);
		return ERR_PTR(-EAGAIN);
	}

	/* XXX: tracepoint */
	c->try_harder = cl;
	c->try_harder_start = local_clock();
	b = ERR_PTR(-ENOMEM);

	list_for_each_entry_reverse(i, &c->btree_cache, list)
		if (page_order <= i->page_order) {
			int e = mca_reap(i, cl);
			if (e == -EAGAIN)
				b = ERR_PTR(-EAGAIN);
			if (!e) {
				b = i;
				goto out;
			}
		}

	if (b == ERR_PTR(-EAGAIN) &&
	    closure_blocking(cl)) {
		mutex_unlock(&c->bucket_lock);
		closure_sync(cl);
		mutex_lock(&c->bucket_lock);
		goto retry;
	}

	return b;
}

struct btree *get_bucket(struct cache_set *c, struct bkey *k,
			 int level, struct btree_op *op)
{
	int i = 0;
	bool write = level <= op->lock;
	struct btree *b;

	BUG_ON(level < 0);
retry:
	b = find_bucket(c, k);

	if (!b) {
		mutex_lock(&c->bucket_lock);
		b = alloc_bucket(c, k, level, &op->cl);
		mutex_unlock(&c->bucket_lock);

		if (!b)
			goto retry;
		if (IS_ERR(b))
			return b;

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

	b->accessed = 1;

	for (; i <= b->nsets && b->sets[i].size; i++) {
		prefetch(b->sets[i].tree);
		prefetch(b->sets[i].data);
	}

	for (; i <= b->nsets; i++)
		prefetch(b->sets[i].data);

	if (!closure_wait_event(&b->io.wait, &op->cl,
				btree_node_read_done(b))) {
		rw_unlock(write, b);
		b = ERR_PTR(-EAGAIN);
	} else if (btree_node_io_error(b)) {
		rw_unlock(write, b);
		b = ERR_PTR(-EIO);
	} else
		BUG_ON(!b->written);

	return b;
}

static void prefetch_bucket(struct cache_set *c, struct bkey *k, int level)
{
	struct btree *b;

	mutex_lock(&c->bucket_lock);
	b = alloc_bucket(c, k, level, NULL);
	mutex_unlock(&c->bucket_lock);

	if (!IS_ERR_OR_NULL(b)) {
		btree_read(b);
		rw_unlock(true, b);
	}
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

	if (btree_node_dirty(b))
		btree_complete_write(b, btree_current_write(b));
	clear_bit(BTREE_NODE_dirty, &b->flags);

	if (b->prio_blocked &&
	    !atomic_sub_return(b->prio_blocked, &b->c->prio_blocked))
		closure_wake_up(&b->c->bucket_wait);

	b->prio_blocked = 0;

	__cancel_delayed_work(&b->work);

	mutex_lock(&b->c->bucket_lock);

	for (unsigned i = 0; i < KEY_PTRS(&b->key); i++) {
		BUG_ON(atomic_read(&PTR_BUCKET(b->c, &b->key, i)->pin));

		inc_gen(PTR_CACHE(b->c, &b->key, i),
			PTR_BUCKET(b->c, &b->key, i));
	}

	unpop_bucket(b->c, &b->key);
	mca_bucket_free(b);
	mutex_unlock(&b->c->bucket_lock);
}

struct btree *bcache_btree_alloc(struct cache_set *c, int level,
				 struct closure *cl)
{
	BKEY_PADDED(key) k;
	struct btree *b = ERR_PTR(-EAGAIN);

	mutex_lock(&c->bucket_lock);
retry:
	if (__pop_bucket_set(c, btree_prio, &k.key, 1, cl))
		goto err;

	SET_KEY_SIZE(&k.key, c->btree_pages * PAGE_SECTORS);

	b = alloc_bucket(c, &k.key, level, cl);
	if (IS_ERR(b))
		goto err_free;

	if (!b) {
		cache_bug(c, "Tried to allocate bucket"
			  " that was in btree cache");
		__bkey_put(c, &k.key);
		goto retry;
	}

	set_btree_node_read_done(b);
	b->accessed = 1;
	bset_init(b, b->sets[0].data);

	mutex_unlock(&c->bucket_lock);
	return b;
err_free:
	unpop_bucket(c, &k.key);
	__bkey_put(c, &k.key);
err:
	mutex_unlock(&c->bucket_lock);
	return b;
}

static struct btree *btree_alloc_replacement(struct btree *b,
					     struct closure *cl)
{
	struct btree *n = bcache_btree_alloc(b->c, b->level, cl);

	if (!IS_ERR_OR_NULL(n)) {
		btree_sort(b, 0, n->sets[0].data);
		bkey_copy_key(&n->key, &b->key);
		n->sets->size = 0;
	}

	return n;
}

/* Garbage collection */

void __btree_mark_key(struct cache_set *c, int level, struct bkey *k)
{
	if (!k->key || !KEY_SIZE(k))
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

static int btree_gc_mark(struct btree *b, unsigned *keys, struct gc_stat *gc)
{
	uint8_t stale = 0;
	unsigned last_dev = -1;
	struct bcache_device *d = NULL;

	struct btree_iter iter;
	btree_iter_init(b, &iter, NULL);

	gc->nodes++;

	while (1) {
		struct bkey *k = btree_iter_next(&iter);
		if (!k)
			break;

		if (last_dev != KEY_DEV(k)) {
			last_dev = KEY_DEV(k);

			d = b->c->devices[last_dev];
		}

		if (ptr_invalid(b, k))
			continue;

		for (unsigned i = 0; i < KEY_PTRS(k); i++) {
			stale = max(stale, ptr_stale(b->c, k, i));

			btree_bug_on(gen_after(PTR_BUCKET(b->c, k, i)->last_gc,
					       PTR_GEN(k, i)),
				     b, "found old gen in gc");
		}

		btree_mark_key(b, k);

		if (ptr_bad(b, k))
			continue;

		*keys += bkey_u64s(k);

		gc->key_bytes += bkey_u64s(k);
		gc->nkeys++;

		gc->data += KEY_SIZE(k);
		if (KEY_DIRTY(k)) {
			gc->dirty += KEY_SIZE(k);
			if (d)
				d->sectors_dirty_gc += KEY_SIZE(k);
		}
	}

	for (struct bset_tree *t = b->sets; t <= &b->sets[b->nsets]; t++)
		btree_bug_on(t->size &&
			     t->data != write_block(b) &&
			     bkey_cmp(&b->key, &t->end) < 0,
			     b, "found short btree key in gc");

	return stale;
}

static struct btree *btree_gc_alloc(struct btree *b, struct bkey *k,
				    struct btree_op *op)
{
	/*
	 * We block priorities from being written for the duration of garbage
	 * collection, so we can't sleep in btree_alloc() -> pop_bucket(), or
	 * we'd risk deadlock - so we don't pass it our closure.
	 */
	struct btree *n = btree_alloc_replacement(b, NULL);

	if (!IS_ERR_OR_NULL(n)) {
		swap(b, n);

		memcpy(k->ptr, b->key.ptr,
		       sizeof(uint64_t) * KEY_PTRS(&b->key));

		__bkey_put(b->c, &b->key);
		atomic_inc(&b->c->prio_blocked);
		b->prio_blocked++;

		btree_free(n, op);
		__up_write(&n->lock);

		b->lock.writer_task = NULL;
		rwsem_release(&b->lock.dep_map, 1, _THIS_IP_);
	}

	return b;
}

/*
 * Leaving this at 2 until we've got incremental garbage collection done; it
 * could be higher (and has been tested with 4) except that garbage collection
 * could take much longer, adversely affecting latency.
 */
#define GC_MERGE_NODES	2

struct gc_merge_info {
	struct btree	*b;
	struct bkey	*k;
	unsigned	keys;
};

static void btree_gc_coalesce(struct btree *b, struct btree_op *op,
			      struct gc_stat *gc, struct gc_merge_info *r)
{
	unsigned nodes = 0, keys = 0, blocks, i;

	while (nodes < GC_MERGE_NODES && r[nodes].b)
		keys += r[nodes++].keys;

	blocks = btree_default_blocks(b->c) * 2 / 3;

	if (nodes < 2 ||
	    __set_blocks(b->sets[0].data, keys, b->c) > blocks * (nodes - 1))
		return;

	for (i = nodes - 1; i; --i) {
		if (r[i].b->written)
			r[i].b = btree_gc_alloc(r[i].b, r[i].k, op);

		if (r[i].b->written)
			return;
	}

	for (i = nodes - 1; i; --i) {
		struct bset *n1 = r[i].b->sets->data;
		struct bset *n2 = r[i - 1].b->sets->data;
		struct bkey *last = NULL;

		keys = 0;

		if (i == 1) {
			/*
			 * Last node we're not getting rid of - we're getting
			 * rid of the node at r[0]. Have to try and fit all of
			 * the remaining keys into this node; we can't ensure
			 * they will always fit due to rounding and variable
			 * length keys (shouldn't be possible in practice,
			 * though)
			 */
			if (__set_blocks(n1, n1->keys + r->keys,
					 b->c) > btree_blocks(r[i].b))
				return;

			if (r->b->written) {
				/*
				 * We're about to free this node, and we have to
				 * make btree_sort() remove stale ptrs
				 */
				r->b->written = 0;
				btree_sort(r->b, 0, NULL);
				n2 = r->b->sets->data;
			}

			keys = n2->keys;
			last = &r->b->key;
		} else
			for (struct bkey *k = n2->start;
			     k < end(n2);
			     k = next(k)) {
				if (__set_blocks(n1, n1->keys + keys +
						 bkey_u64s(k), b->c) > blocks)
					break;

				last = k;
				keys += bkey_u64s(k);
			}

		BUG_ON(__set_blocks(n1, n1->keys + keys,
				    b->c) > btree_blocks(r[i].b));

		if (last) {
			bkey_copy_key(&r[i].b->key, last);
			bkey_copy_key(r[i].k, last);
		}

		memcpy(end(n1),
		       n2->start,
		       (void *) node(n2, keys) - (void *) n2->start);

		n1->keys += keys;

		memmove(n2->start,
			node(n2, keys),
			(void *) end(n2) - (void *) node(n2, keys));

		n2->keys -= keys;

		r[i].keys	= n1->keys;
		r[i - 1].keys	= n2->keys;
	}

	btree_free(r->b, op);
	__up_write(&r->b->lock);

	pr_debug("coalesced %u nodes", nodes);

	gc->nodes--;
	nodes--;

	memmove(&r[0], &r[1], sizeof(struct gc_merge_info) * nodes);
	memset(&r[nodes], 0, sizeof(struct gc_merge_info));
}

static int btree_gc_recurse(struct btree *b, struct btree_op *op,
			    struct closure *writes, struct gc_stat *gc)
{
	void write(struct btree *r)
	{
		if (!r->written)
			btree_write(r, true, op);
		else if (btree_node_dirty(r)) {
			BUG_ON(btree_current_write(r)->owner);
			btree_current_write(r)->owner = writes;
			closure_get(writes);

			btree_write(r, true, NULL);
		}

		__up_write(&r->lock);
	}

	int ret = 0, stale;
	struct gc_merge_info r[GC_MERGE_NODES];

	memset(r, 0, sizeof(r));

	while ((r->k = next_recurse_key(b, &b->c->gc_done))) {
		r->b = get_bucket(b->c, r->k, b->level - 1, op);

		if (IS_ERR(r->b)) {
			ret = PTR_ERR(r->b);
			break;
		}

		/*
		 * Fake out lockdep, because I'm a terrible person: it's just
		 * not possible to express our lock ordering to lockdep, because
		 * lockdep works at most in terms of a small fixed number of
		 * subclasses, and we're just iterating through all of them in a
		 * fixed order.
		 */
		r->b->lock.writer_task = NULL;
		rwsem_release(&r->b->lock.dep_map, 1, _THIS_IP_);

		r->keys	= 0;
		stale = btree_gc_mark(r->b, &r->keys, gc);

		if (!b->written &&
		    (r->b->level || stale > 10 ||
		     b->c->gc_always_rewrite))
			r->b = btree_gc_alloc(r->b, r->k, op);

		if (r->b->level)
			ret = btree_gc_recurse(r->b, op, writes, gc);

		if (ret) {
			write(r->b);
			break;
		}

		bkey_copy_key(&b->c->gc_done, r->k);

		if (!b->written)
			btree_gc_coalesce(b, op, gc, r);

		if (r[GC_MERGE_NODES - 1].b)
			write(r[GC_MERGE_NODES - 1].b);

		memmove(&r[1], &r[0],
			sizeof(struct gc_merge_info) * (GC_MERGE_NODES - 1));

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

	for (unsigned i = 1; i < GC_MERGE_NODES && r[i].b; i++)
		write(r[i].b);

	/* Might have freed some children, must remove their keys */
	if (!b->written)
		btree_sort(b, 0, NULL);

	return ret;
}

static int btree_gc_root(struct btree *b, struct btree_op *op,
			 struct closure *writes, struct gc_stat *gc)
{
	struct btree *n = NULL;
	unsigned keys = 0;
	int ret = 0, stale = btree_gc_mark(b, &keys, gc);

	if (b->level || stale > 10)
		n = btree_alloc_replacement(b, NULL);

	if (!IS_ERR_OR_NULL(n))
		swap(b, n);

	if (b->level)
		ret = btree_gc_recurse(b, op, writes, gc);

	if (!b->written || btree_node_dirty(b)) {
		atomic_inc(&b->c->prio_blocked);
		b->prio_blocked++;
		btree_write(b, true, n ? op : NULL);
	}

	if (!IS_ERR_OR_NULL(n)) {
		closure_sync(&op->cl);
		bcache_btree_set_root(b);
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

	mutex_lock(&c->bucket_lock);

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
			/*
			 * the c->journal.cur check is a hack because when we're
			 * called from run_cache_set() gc_gen isn't going to be
			 * correct
			 */
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

	for (struct bcache_device **d = c->devices;
	     d < c->devices + c->nr_uuids;
	     d++)
		if (*d) {
			unsigned long last =
				atomic_long_read(&((*d)->sectors_dirty));
			long difference = (*d)->sectors_dirty_gc - last;

			pr_debug("sectors dirty off by %li", difference);

			(*d)->sectors_dirty_last += difference;

			atomic_long_set(&((*d)->sectors_dirty),
					(*d)->sectors_dirty_gc);
		}

	mutex_unlock(&c->bucket_lock);
	return available;
}

static void btree_gc(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, gc.cl);
	int ret;
	unsigned long available;
	struct bucket *b;
	struct cache *ca;

	struct gc_stat stats;
	struct closure writes;
	struct btree_op op;

	uint64_t start_time = local_clock();
	trace_bcache_gc_start(c->sb.set_uuid);

	memset(&stats, 0, sizeof(struct gc_stat));
	closure_init_stack(&writes);
	btree_op_init_stack(&op);
	op.lock = SHRT_MAX;

	blktrace_msg_all(c, "Starting gc");

	mutex_lock(&c->bucket_lock);
	for_each_cache(ca, c)
		free_some_buckets(ca);

	if (c->gc_mark_valid) {
		c->gc_mark_valid = 0;
		c->gc_done = ZERO_KEY;

		for_each_cache(ca, c)
			for_each_bucket(b, ca)
				if (!atomic_read(&b->pin))
					b->mark = 0;

		for (struct bcache_device **d = c->devices;
		     d < c->devices + c->nr_uuids;
		     d++)
			if (*d)
				(*d)->sectors_dirty_gc = 0;
	}
	mutex_unlock(&c->bucket_lock);

	ret = btree_root(gc_root, c, &op, &writes, &stats);
	closure_sync(&op.cl);
	closure_sync(&writes);

	if (ret) {
		blktrace_msg_all(c, "Stopped gc");
		printk(KERN_WARNING "bcache: gc failed!\n");

		continue_at(cl, btree_gc, bcache_wq);
	}

	/* Possibly wait for new UUIDs or whatever to hit disk */
	bcache_journal_meta(c, &op.cl);
	closure_sync(&op.cl);

	available = btree_gc_finish(c);

	time_stats_update(&c->btree_gc_time, start_time);

	stats.key_bytes *= sizeof(uint64_t);
	stats.dirty	<<= 9;
	stats.data	<<= 9;
	stats.in_use	= (c->nbuckets - available) * 100 / c->nbuckets;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));
	blktrace_msg_all(c, "Finished gc");

	trace_bcache_gc_end(c->sb.set_uuid);
	closure_wake_up(&c->bucket_wait);

	closure_return(cl);
}

void bcache_queue_gc(struct cache_set *c)
{
	if (closure_trylock(&c->gc.cl, &c->cl))
		continue_at(&c->gc.cl, btree_gc, bcache_wq);
}

/* Initial partial gc */

static int btree_check_recurse(struct btree *b, struct btree_op *op,
			       unsigned long **seen)
{
	int ret;
	struct bkey *k;

	for_each_key_filter(b, k, ptr_invalid) {
		for (unsigned i = 0; i < KEY_PTRS(k); i++) {
			struct bucket *g = PTR_BUCKET(b->c, k, i);

			if (!__test_and_set_bit(PTR_BUCKET_NR(b->c, k, i),
						seen[PTR_DEV(k, i)]) ||
			    !ptr_stale(b->c, k, i)) {
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
				prefetch_bucket(b->c, p, b->level - 1);

			ret = btree(check_recurse, k, b, op, seen);
			if (ret)
				return ret;

			k = p;
		}
	}

	return 0;
}

int btree_check(struct cache_set *c, struct btree_op *op)
{
	int ret = -ENOMEM;
	unsigned long *seen[MAX_CACHES_PER_SET];

	memset(seen, 0, sizeof(seen));

	for (int i = 0; c->cache[i]; i++) {
		size_t n = DIV_ROUND_UP(c->cache[i]->sb.nbuckets, 8);
		seen[i] = kmalloc(n, GFP_KERNEL);
		if (!seen[i])
			goto err;

		/* Disables the seen array until prio_read() uses it too */
		memset(seen[i], 0xFF, n);
	}

	ret = btree_root(check_recurse, c, op, seen);
err:
	for (int i = 0; i < MAX_CACHES_PER_SET; i++)
		kfree(seen[i]);
	return ret;
}

/* Btree insertion */

static void shift_keys(struct btree *b, struct bkey *where, struct bkey *insert)
{
	struct bset *i = b->sets[b->nsets].data;

	memmove((uint64_t *) where + bkey_u64s(insert),
		where,
		(void *) end(i) - (void *) where);

	i->keys += bkey_u64s(insert);
	bkey_copy(where, insert);
	bset_fix_lookup_table(b, where);
}

static bool fix_overlapping_extents(struct btree *b,
				    struct bkey *check,
				    struct btree_iter *iter,
				    struct btree_op *op)
{
	void subtract_dirty(struct bkey *k, int sectors)
	{
		struct bcache_device *d = b->c->devices[KEY_DEV(k)];

		if (KEY_DIRTY(k) && d)
			atomic_long_sub(sectors, &d->sectors_dirty);
	}

	while (1) {
		struct bkey *k = btree_iter_next(iter);
		if (!k ||
		    bkey_cmp(check, &START_KEY(k)) <= 0)
			break;

		if (bkey_cmp(k, &START_KEY(check)) <= 0)
			continue;

		if (op->insert_type == INSERT_READ &&
		    KEY_SIZE(k) &&
		    (!KEY_PTRS(k) ||
		     !ptr_bad(b, k))) {
			/*
			 * Could split this key in two if necessary: since we
			 * don't, we have to check if we can use the start of
			 * the key we're inserting first. Otherwise, we could
			 * adjust a stale key that hasn't been written to disk
			 * and not insert anything in its place.
			 */
			if (bkey_cmp(&START_KEY(k), &START_KEY(check)) > 0)
				cut_back(&START_KEY(k), check);
			else if (bkey_cmp(k, check) < 0)
				cut_front(k, check);
			else {
				mark_cache_miss_collision(op);
				return true;
			}

			BUG_ON(!KEY_SIZE(check));
			continue;
		}

		if (op->insert_type == INSERT_UNDIRTY) {
			if (k->header != (check->header | PTR_DIRTY_BIT) ||
			    memcmp(&k->key, &check->key, bkey_bytes(check) - 8))
				goto wb_failed;

			subtract_dirty(k, KEY_SIZE(k));

			cut_front(check, k);
			atomic_long_inc(&b->c->writeback_keys_done);
			return false;
		}

		if (bkey_cmp(check, k) < 0 &&
		    bkey_cmp(&START_KEY(check), &START_KEY(k)) > 0) {
			/*
			 * We overlapped in the middle of an existing key: that
			 * means we have to split the old key. But we have to do
			 * slightly different things depending on whether the
			 * old key has been written out yet.
			 */

			struct bkey *top;

			subtract_dirty(k, KEY_SIZE(check));

			if (k < write_block(b)->start) {
				/*
				 * We insert a new key to cover the top of the
				 * old key, and the old key is modified in place
				 * to represent the bottom split.
				 *
				 * It's completely arbitrary whether the new key
				 * is the top or the bottom, but it has to match
				 * up with what btree_sort_fixup() does - it
				 * doesn't check for this kind of overlap, it
				 * depends on us inserting a new key for the top
				 * here.
				 */
				top = bset_search(b, &b->sets[b->nsets], check);
				shift_keys(b, top, k);
			} else {
				BKEY_PADDED(key) temp;
				bkey_copy(&temp.key, k);
				shift_keys(b, k, &temp.key);
				top = next(k);
			}

			cut_front(check, top);
			cut_back(&START_KEY(check), k);
			bset_fix_invalidated_key(b, k);
			return false;
		}

		if (bkey_cmp(check, k) < 0) {
			if (bkey_cmp(check, &START_KEY(k)) > 0)
				subtract_dirty(k, check->key - KEY_START(k));

			cut_front(check, k);
		} else {
			if (bkey_cmp(k, &START_KEY(check)) > 0)
				subtract_dirty(k, k->key - KEY_START(check));

			if (k < write_block(b)->start &&
			    bkey_cmp(&START_KEY(check), &START_KEY(k)) <= 0)
				/*
				 * Completely overwrote, so we don't have to
				 * invalidate the binary search tree
				 */
				cut_front(k, k);
			else {
				__cut_back(&START_KEY(check), k);
				bset_fix_invalidated_key(b, k);
			}
		}
	}

	if (op->insert_type == INSERT_UNDIRTY) {
wb_failed:	atomic_long_inc(&b->c->writeback_keys_failed);
		return true;
	}

	return false;
}

bool bcache_btree_insert_keys(struct btree *b, struct btree_op *op)
{
	/* If a read generates a cache miss, and a write to the same location
	 * finishes before the new data is added to the cache, the write will
	 * be overwritten with stale data. We can catch this by never
	 * overwriting good data if it came from a read.
	 */
	bool ret = false;
	struct bset *i = b->sets[b->nsets].data;
	struct bkey *k, *m, *prev;
	unsigned oldsize = count_data(b);

	while ((k = keylist_pop(&op->keys))) {
		const char *status = "insert";

		BUG_ON(b->level && !KEY_PTRS(k));
		BUG_ON(!b->level && !k->key);
		BUG_ON(!b->level && op->insert_type != INSERT_REPLAY &&
		       (!KEY_DIRTY(k) ==
			(op->insert_type == INSERT_WRITEBACK)));

		bkey_put(b->c, k, op->insert_type, b->level);

		if (!b->level) {
			struct btree_iter iter;

			struct bkey search = KEY(KEY_DEV(k), KEY_START(k), 0);

			/*
			 * bset_search() returns the first key that is strictly
			 * greater than the search key - but for back merging,
			 * we want to find the first key that is greater than or
			 * equal to KEY_START(k) - unless KEY_START(k) is 0.
			 */
			if (search.key)
				search.key--;

			prev = NULL;
			m = btree_iter_init(b, &iter, &search);

			if (fix_overlapping_extents(b, k, &iter, op))
				continue;

			while (m != end(i) &&
			       bkey_cmp(k, &START_KEY(m)) > 0)
				prev = m, m = next(m);

			if (key_merging_disabled(b->c))
				goto insert;

			/* prev is in the tree, if we merge we're done */
			status = "back merging";
			if (prev &&
			    bkey_try_merge(b, prev, k))
				goto merged;

			status = "overwrote front";
			if (m != end(i) &&
			    KEY_PTRS(m) == KEY_PTRS(k) && !KEY_SIZE(m))
				goto copy;

			status = "front merge";
			if (m != end(i) &&
			    bkey_try_merge(b, k, m))
				goto copy;
		} else
			m = bset_search(b, &b->sets[b->nsets], k);

insert:		shift_keys(b, m, k);
copy:		bkey_copy(m, k);
merged:		ret = true;

		check_keys(b, "%s for %s at %s: %s", status,
			   insert_type(op), pbtree(b), pkey(k));
		check_key_order_msg(b, i, "%s for %s at %s: %s", status,
				    insert_type(op), pbtree(b), pkey(k));

		if (b->level && !k->key)
			b->prio_blocked++;

		pr_debug("%s for %s at %s: %s", status,
			 insert_type(op), pbtree(b), pkey(k));
	}

	BUG_ON(count_data(b) < oldsize);
	return ret;
}

static int btree_split(struct btree *b, struct btree_op *op)
{
	bool split, root = b == b->c->root;
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	uint64_t start_time = local_clock();

	if (b->level)
		set_closure_blocking(&op->cl);

	n1 = btree_alloc_replacement(b, &op->cl);
	if (IS_ERR(n1))
		goto err;

	split = set_blocks(n1->sets[0].data, n1->c) > (btree_blocks(b) * 4) / 5;

	pr_debug("%ssplitting at %s keys %i", split ? "" : "not ",
		 pbtree(b), n1->sets[0].data->keys);

	if (split) {
		unsigned keys = 0;

		n2 = bcache_btree_alloc(b->c, b->level, &op->cl);
		if (IS_ERR(n2))
			goto err_free1;

		if (root) {
			n3 = bcache_btree_alloc(b->c, b->level + 1, &op->cl);
			if (IS_ERR(n3))
				goto err_free2;
		}

		bcache_btree_insert_keys(n1, op);

		/* Has to be a linear search because we don't have an auxiliary
		 * search tree yet
		 */

		while (keys < (n1->sets[0].data->keys * 3) / 5)
			keys += bkey_u64s(node(n1->sets[0].data, keys));

		bkey_copy_key(&n1->key, node(n1->sets[0].data, keys));
		keys += bkey_u64s(node(n1->sets[0].data, keys));

		n2->sets[0].data->keys = n1->sets[0].data->keys - keys;
		n1->sets[0].data->keys = keys;

		memcpy(n2->sets[0].data->start,
		       end(n1->sets[0].data),
		       n2->sets[0].data->keys * sizeof(uint64_t));

		bkey_copy_key(&n2->key, &b->key);

		keylist_add(&op->keys, &n2->key);
		btree_write(n2, true, op);
		rw_unlock(true, n2);
	} else
		bcache_btree_insert_keys(n1, op);

	keylist_add(&op->keys, &n1->key);
	btree_write(n1, true, op);

	if (n3) {
		bkey_copy_key(&n3->key, &MAX_KEY);
		bcache_btree_insert_keys(n3, op);
		btree_write(n3, true, op);

		closure_sync(&op->cl);
		bcache_btree_set_root(n3);
		rw_unlock(true, n3);
	} else if (root) {
		op->keys.top = op->keys.bottom;
		closure_sync(&op->cl);
		bcache_btree_set_root(n1);
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

	time_stats_update(&b->c->btree_split_time, start_time);

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

		if (write_block(b) != b->sets[b->nsets].data) {
			bset_init(b, write_block(b));
			bset_build_tree(b, &b->sets[b->nsets]);
		}

		if (bcache_btree_insert_keys(b, op))
			btree_write(b, false, op);
	}

	return 0;
}

int bcache_btree_insert(struct btree_op *op, struct cache_set *c)
{
	int ret = 0;
	struct cache *ca;
	struct keylist stack_keys;

	/*
	 * Don't want to block with the btree locked unless we have to,
	 * otherwise we get deadlocks with try_harder and between split/gc
	 */
	clear_closure_blocking(&op->cl);

	BUG_ON(keylist_empty(&op->keys));
	keylist_copy(&stack_keys, &op->keys);
	keylist_init(&op->keys);

	while (c->need_gc > MAX_NEED_GC) {
		closure_lock(&c->gc, &c->cl);
		btree_gc(&c->gc.cl);
	}

	for_each_cache(ca, c)
		while (ca->need_save_prio > MAX_SAVE_PRIO) {
			mutex_lock(&c->bucket_lock);
			free_some_buckets(ca);
			mutex_unlock(&c->bucket_lock);

			closure_wait_event_sync(&c->bucket_wait, &op->cl,
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

void bcache_btree_set_root(struct btree *b)
{
	BUG_ON(!b->written);
	BUG_ON(!current_is_writer(&b->c->root->lock));

	for (unsigned i = 0; i < KEY_PTRS(&b->key); i++)
		BUG_ON(PTR_BUCKET(b->c, &b->key, i)->prio != btree_prio);

	mutex_lock(&b->c->bucket_lock);
	list_del_init(&b->list);
	mutex_unlock(&b->c->bucket_lock);

	b->c->root = b;
	__bkey_put(b->c, &b->key);

	bcache_journal_meta(b->c, NULL);
	pr_debug("%s for %pf", pbtree(b), __builtin_return_address(0));
}

/* Cache lookup */

/*
 * Read from a single key, handling the initial cache miss if the key starts in
 * the middle of the bio
 */
static int submit_partial_cache_hit(struct btree *b, struct btree_op *op,
				    struct bkey *k)
{
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;

	unsigned sectors, ptr;
	struct bio *n;
	int ret = 0;
	int offset(void)	{ return bio->bi_sector - KEY_START(k); }

	while (offset() < 0) {
		sectors = min_t(unsigned, -offset(), bio_max_sectors(bio));

		ret = s->op.d->cache_miss(s, bio, sectors);
		if (ret)
			return ret;
	}

	/* XXX: figure out best pointer - for multiple cache devices */
	ptr = 0;

	PTR_BUCKET(b->c, k, ptr)->prio = initial_prio;

	do {
		struct bkey *bio_key;
		struct block_device *bdev = PTR_CACHE(b->c, k, ptr)->bdev;

		sector_t sector = PTR_OFFSET(k, ptr) + offset();

		sectors = min_t(unsigned, k->key - bio->bi_sector,
				__bio_max_sectors(bio, bdev, sector));

		n = bio_split_get(bio, sectors, op->d);
		if (!n)
			return -EAGAIN;

		if (n == bio)
			s->cache_hit_done = true;

		bio_key = &container_of(n, struct bbio, bio)->key;

		/*
		 * The bucket we're reading from might be reused while our bio
		 * is in flight, and we could then end up reading the wrong
		 * data.
		 *
		 * We guard against this by checking (in cache_read_endio()) if
		 * the pointer is stale again; if so, we treat it as an error
		 * and reread from the backing device (but we don't pass that
		 * error up anywhere).
		 */

		bkey_copy_single_ptr(bio_key, k, ptr);
		SET_PTR_OFFSET(bio_key, 0, sector);

		n->bi_end_io = cache_read_endio;

		trace_bcache_cache_hit(n);
		__submit_bbio(n, b->c);
	} while (!s->cache_hit_done &&
		 bio->bi_sector < k->key);

	return 0;
}

int btree_search_recurse(struct btree *b, struct btree_op *op, unsigned *reada)
{
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;

	int ret = 0;
	struct bkey *k;
	struct btree_iter iter;
	btree_iter_init(b, &iter, &KEY(op->d->id, bio->bi_sector, 0));

	pr_debug("at %s searching for %u:%llu", pbtree(b), op->d->id,
		 (uint64_t) bio->bi_sector);

	do {
		k = btree_iter_next(&iter);
		if (!k) {
			btree_bug_on(b->level, b,
				     "no key to recurse on at level %i/%i",
				     b->level, b->c->root->level);
			break;
		}

		if (!b->level && KEY_DEV(k) != op->d->id)
			break;

		if (ptr_bad(b, k))
			continue;

		if (!b->level && bio_end(bio) <= KEY_START(k)) {
			*reada = min_t(unsigned, *reada,
				       KEY_START(k) - bio_end(bio));
			break;
		}

		ret = b->level
			? btree(search_recurse, k, b, op, reada)
			: submit_partial_cache_hit(b, op, k);
	} while (!ret &&
		 !s->cache_hit_done &&
		 bkey_cmp(k, &KEY(op->d->id, bio_end(bio), 0)) < 0);

	return ret;
}

void bcache_btree_exit(void)
{
	if (btree_wq)
		destroy_workqueue(btree_wq);
}

int __init bcache_btree_init(void)
{
	btree_wq = create_singlethread_workqueue("bcache_btree_io");
	if (!btree_wq)
		return -ENOMEM;

	return 0;
}
