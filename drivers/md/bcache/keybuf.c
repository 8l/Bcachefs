
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
	if (bkey_cmp(l->key.k.p, bkey_start_pos(&r->key.k)) <= 0)
		return -1;
	if (bkey_cmp(bkey_start_pos(&l->key.k), r->key.k.p) >= 0)
		return 1;
	return 0;
}

static inline int keybuf_nonoverlapping_cmp(struct keybuf_key *l,
					    struct keybuf_key *r)
{
	return clamp_t(int64_t, bkey_cmp(l->key.k.p, r->key.k.p), -1, 1);
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
		       struct bpos end, keybuf_pred_fn *pred)
{
	struct bpos start = buf->last_scanned;
	struct btree_iter iter;
	struct bkey_s_c k;
	unsigned nr_found = 0;

	cond_resched();

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, k, buf->last_scanned) {
		if (bkey_cmp(k.k->p, end) >= 0) {
			buf->last_scanned = k.k->p;
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

			bkey_reassemble(&w->key, k);
			atomic_set(&w->ref, -1); /* -1 means hasn't started */

			if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
				keybuf_free(w, buf);
			else
				nr_found++;

			spin_unlock(&buf->lock);
		}

		buf->last_scanned = k.k->p;
	}

	/* If we end up here, it means:
	 * - the map_fn didn't fill up the keybuf
	 * - the map_fn didn't see the end key
	 * - there were no more keys to map over
	 * Therefore, we are at the end of the key space */
	buf->last_scanned = POS_MAX;
done:
	bch_btree_iter_unlock(&iter);

	trace_bcache_keyscan(nr_found,
			     start.inode, start.offset,
			     buf->last_scanned.inode,
			     buf->last_scanned.offset);

	spin_lock(&buf->lock);

	if (!RB_EMPTY_ROOT(&buf->keys)) {
		struct keybuf_key *w;
		w = RB_FIRST(&buf->keys, struct keybuf_key, node);
		buf->start	= bkey_start_pos(&w->key.k);

		w = RB_LAST(&buf->keys, struct keybuf_key, node);
		buf->end	= w->key.k.p;
	} else {
		buf->start	= POS_MAX;
		buf->end	= POS_MAX;
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

void bch_keybuf_recalc_oldest_gens(struct cache_set *c, struct keybuf *buf)
{
	struct keybuf_key *w, *n;

	spin_lock(&buf->lock);
	rcu_read_lock();
	rbtree_postorder_for_each_entry_safe(w, n,
				&buf->keys, node)
		bch_btree_key_recalc_oldest_gen(c,
					bkey_i_to_s_c_extent(&w->key));
	rcu_read_unlock();
	spin_unlock(&buf->lock);
}

bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bpos start,
				  struct bpos end)
{
	bool ret = false;
	struct keybuf_key *w, *next, s = { .key.k.p = start };

	if (bkey_cmp(end, buf->start) <= 0 ||
	    bkey_cmp(start, buf->end) >= 0)
		return false;

	spin_lock(&buf->lock);

	for (w = RB_GREATER(&buf->keys, s, node, keybuf_nonoverlapping_cmp);
	     w && bkey_cmp(bkey_start_pos(&w->key.k), end) < 0;
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

	buf->last_scanned	= POS_MAX;
	buf->start		= POS_MIN;
	buf->end		= POS_MIN;

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
