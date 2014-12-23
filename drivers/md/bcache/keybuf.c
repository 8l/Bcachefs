
#include "bcache.h"
#include "btree.h"
#include "gc.h"
#include "keybuf.h"

#include <trace/events/bcache.h>

/*
 * For buffered iteration over the btree, with predicates and ratelimiting and
 * whatnot
 */

static inline int keybuf_cmp(struct keybuf_key *l, struct keybuf_key *r)
{
	/* Overlapping keys compare equal */
	if (bkey_cmp(&l->key, &START_KEY(&r->key)) <= 0)
		return -1;
	if (bkey_cmp(&START_KEY(&l->key), &r->key) >= 0)
		return 1;
	return 0;
}

static inline int keybuf_nonoverlapping_cmp(struct keybuf_key *l,
					    struct keybuf_key *r)
{
	return clamp_t(int64_t, bkey_cmp(&l->key, &r->key), -1, 1);
}

/*
 * keybuf_alloc and keybuf_free assume that the keybuf lock is held.
 */

static struct keybuf_key *keybuf_alloc(struct keybuf *buf)
{
	struct keybuf_key *w;

	BUG_ON(buf->pool == NULL);
	lockdep_assert_held(&buf->lock);
	w = mempool_alloc(buf->pool, GFP_NOWAIT);

	if (w != NULL)
		buf->size += 1;

	return w;
}

static void keybuf_free(struct keybuf_key *w, struct keybuf *buf)
{
	lockdep_assert_held(&buf->lock);
	buf->size -= 1;
	mempool_free(w, buf->pool);
	return;
}

void bch_refill_keybuf(struct cache_set *c, struct keybuf *buf,
		       struct bkey *end, keybuf_pred_fn *pred)
{
	struct bkey start = buf->last_scanned;
	struct btree_iter iter;
	struct bkey *k;
	unsigned nr_found = 0;

	cond_resched();

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, k, &buf->last_scanned) {
		if (bkey_cmp(k, end) >= 0) {
			buf->last_scanned = *k;
			goto done;
		}

		if (pred(buf, k)) {
			struct keybuf_key *w;

			spin_lock(&buf->lock);

			w = keybuf_alloc(buf);
			if (!w) {
				spin_unlock(&buf->lock);
				goto done;
			}

			bkey_copy(&w->key, k);
			atomic_set(&w->ref, -1); /* -1 means hasn't started */

			if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
				keybuf_free(w, buf);
			else
				nr_found++;

			spin_unlock(&buf->lock);
		}

		buf->last_scanned = *k;
	}

	/* If we end up here, it means:
	 * - the map_fn didn't fill up the keybuf
	 * - the map_fn didn't see the end key
	 * - there were no more keys to map over
	 * Therefore, we are at the end of the key space */
	buf->last_scanned = MAX_KEY;
done:
	bch_btree_iter_unlock(&iter);

	trace_bcache_keyscan(nr_found,
			     KEY_INODE(&start), KEY_OFFSET(&start),
			     KEY_INODE(&buf->last_scanned),
			     KEY_OFFSET(&buf->last_scanned));

	spin_lock(&buf->lock);

	if (!RB_EMPTY_ROOT(&buf->keys)) {
		struct keybuf_key *w;
		w = RB_FIRST(&buf->keys, struct keybuf_key, node);
		buf->start	= START_KEY(&w->key);

		w = RB_LAST(&buf->keys, struct keybuf_key, node);
		buf->end	= w->key;
	} else {
		buf->start	= MAX_KEY;
		buf->end	= MAX_KEY;
	}

	spin_unlock(&buf->lock);
}

static void bch_keybuf_del(struct keybuf *buf, struct keybuf_key *w)
{
	rb_erase(&w->node, &buf->keys);
	keybuf_free(w, buf);
}

void bch_keybuf_put(struct keybuf *buf, struct keybuf_key *w)
{
	BUG_ON(atomic_read(&w->ref) <= 0);

	if (atomic_dec_and_test(&w->ref)) {
		up(&buf->in_flight);

		spin_lock(&buf->lock);
		bch_keybuf_del(buf, w);
		spin_unlock(&buf->lock);
	}
}

/**
 * bch_mark_keybuf_keys - update oldest generation pointer into a bucket
 *
 * This prevents us from wrapping around gens for a bucket only referenced from
 * the writeback keybufs. We don't actually care that the data in those buckets
 * is marked live, only that we don't wrap the gens.
 */
void bch_mark_keybuf_keys(struct cache_set *c, struct keybuf *buf)
{
	struct keybuf_key *w, *n;

	spin_lock(&buf->lock);
	rcu_read_lock();
	rbtree_postorder_for_each_entry_safe(w, n,
				&buf->keys, node)
		bch_btree_mark_last_gc(c, &w->key);
	rcu_read_unlock();
	spin_unlock(&buf->lock);
}

bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bkey *start,
				  struct bkey *end)
{
	bool ret = false;
	struct keybuf_key *w, *next, s = { .key = *start };

	if (bkey_cmp(end, &buf->start) <= 0 ||
	    bkey_cmp(start, &buf->end) >= 0)
		return false;

	spin_lock(&buf->lock);

	for (w = RB_GREATER(&buf->keys, s, node, keybuf_nonoverlapping_cmp);
	     w && bkey_cmp(&START_KEY(&w->key), end) < 0;
	     w = next) {
		next = RB_NEXT(w, node);

		if (atomic_read(&w->ref) == -1)
			bch_keybuf_del(buf, w);
		else
			ret = true;
	}

	spin_unlock(&buf->lock);
	return ret;
}

struct keybuf_key *bch_keybuf_next(struct keybuf *buf)
{
	struct keybuf_key *w;
	spin_lock(&buf->lock);

	w = RB_FIRST(&buf->keys, struct keybuf_key, node);

	while (w && atomic_read(&w->ref) != -1)
		w = RB_NEXT(w, node);

	if (!w) {
		spin_unlock(&buf->lock);
		return NULL;
	}

	atomic_set(&w->ref, 1);
	spin_unlock(&buf->lock);

	down(&buf->in_flight);

	return w;
}

struct keybuf_key *bch_keybuf_next_rescan(struct cache_set *c,
					  struct keybuf *buf,
					  struct bkey *end,
					  keybuf_pred_fn *pred)
{
	struct keybuf_key *ret;

	while (1) {
		ret = bch_keybuf_next(buf);
		if (ret)
			break;

		if (bkey_cmp(&buf->last_scanned, end) >= 0) {
			pr_debug("scan finished");
			break;
		}

		bch_refill_keybuf(c, buf, end, pred);
	}

	return ret;
}

void bch_keybuf_resize(struct keybuf *buf, unsigned new_size)
{
	spin_lock(&buf->lock);
	if (mempool_resize(buf->pool, new_size, GFP_KERNEL) == 0)
	    buf->reserve = new_size;
	spin_unlock(&buf->lock);
	return;
}

void bch_keybuf_resize_ios(struct keybuf *buf, unsigned new_ios)
{
	spin_lock(&buf->lock);

	/* up should not block */
	while (new_ios > buf->max_in_flight) {
		up(&buf->in_flight);
		buf->max_in_flight += 1;
	}

	/* down can block, so we unlock around it */
	while (new_ios < buf->max_in_flight) {
		buf->max_in_flight -= 1;
		spin_unlock(&buf->lock);
		down(&buf->in_flight);
		spin_lock(&buf->lock);
	}

	spin_unlock(&buf->lock);
	return;
}

/*
 * We don't use buf->lock here because the keybuf should not be shared
 * until it has been initialized, and hence we are the single user
 * at this time.
 */

void bch_keybuf_init(struct keybuf *buf, unsigned size, unsigned in_flight)
{
	spin_lock_init(&buf->lock);
	sema_init(&buf->in_flight, in_flight);

	buf->last_scanned	= MAX_KEY;
	buf->keys		= RB_ROOT;

	buf->size = 0;
	buf->pool = mempool_create_kmalloc_pool(size,
						sizeof(struct keybuf_key));
	BUG_ON(buf->pool == NULL);
	buf->reserve = size;
	return;
}

/*
 * When bch_keybuf_destroy is called, not all the
 * nodes may have been returned to the pool, but the rest of the nodes
 * should be in the red/black tree.
 *
 * The calls to spin_lock/spin_unlock below should be unnecessary,
 * but it is cleanest to always do it, and the tear down code should not
 * be perf. critical.
 */

void bch_keybuf_free(struct keybuf *buf)
{
	/* Free up the red/black tree */
	if (buf->keys.rb_node != ((struct rb_node *) NULL)) {
		struct rb_node *ptr, *next;
		struct keybuf_key *kbk;

		spin_lock(&buf->lock);
		BUG_ON(buf->size == 0);
		spin_unlock(&buf->lock);

		ptr = (rb_first_postorder(&buf->keys));
		while (ptr != NULL) {
			next = (rb_next_postorder(ptr));
			kbk = (container_of(ptr, struct keybuf_key, node));
			BUG_ON(((atomic_read(&kbk->ref)) != 0)
			       && ((atomic_read(&kbk->ref)) != -1));
			spin_lock(&buf->lock);
			keybuf_free(kbk, buf);
			spin_unlock(&buf->lock);
			ptr = next;
		}
	}

	spin_lock(&buf->lock);
	BUG_ON(buf->size != 0);
	buf->reserve = 0;
	mempool_destroy(buf->pool);
	buf->pool = NULL;
	spin_unlock(&buf->lock);

	return;
}

bool bch_keybuf_full(struct keybuf * buf)
{
	/* For now, never full. */
	return false;
}
