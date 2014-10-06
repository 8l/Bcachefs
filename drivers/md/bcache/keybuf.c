
#include "bcache.h"
#include "btree.h"
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

struct refill {
	struct btree_op	op;
	unsigned	nr_found;
	struct keybuf	*buf;
	struct bkey	*end;
	keybuf_pred_fn	*pred;
};

static int refill_keybuf_fn(struct btree_op *op, struct btree *b,
			    struct bkey *k)
{
	struct refill *refill = container_of(op, struct refill, op);
	struct keybuf *buf = refill->buf;
	int ret = MAP_CONTINUE;

	if (bkey_cmp(k, refill->end) >= 0) {
		ret = MAP_DONE;
		goto out;
	}

	if (refill->pred(buf, k)) {
		struct keybuf_key *w;

		spin_lock(&buf->lock);

		w = freelist_alloc(&buf->freelist);
		if (!w) {
			spin_unlock(&buf->lock);
			return MAP_DONE;
		}

		bkey_copy(&w->key, k);
		atomic_set(&w->ref, -1); /* -1 means hasn't started */

		if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
			freelist_free(&buf->freelist, w);
		else
			refill->nr_found++;

		if (freelist_empty(&buf->freelist))
			ret = MAP_DONE;

		spin_unlock(&buf->lock);
	}
out:
	buf->last_scanned = *k;
	return ret;
}

void bch_refill_keybuf(struct cache_set *c, struct keybuf *buf,
		       struct bkey *end, keybuf_pred_fn *pred)
{
	struct bkey start = buf->last_scanned;
	struct refill refill;
	int ret;

	cond_resched();

	bch_btree_op_init(&refill.op, BTREE_ID_EXTENTS, -1);
	refill.nr_found	= 0;
	refill.buf	= buf;
	refill.end	= end;
	refill.pred	= pred;

	ret = bch_btree_map_keys(&refill.op, c,
				 &buf->last_scanned,
				 refill_keybuf_fn, 0);
	if (ret == MAP_CONTINUE) {
		/* If we end up here, it means:
		 * - the map_fn didn't fill up the keybuf
		 * - the map_fn didn't see the end key
		 * - there were no more keys to map over
		 * Therefore, we are at the end of the key space */
		buf->last_scanned = MAX_KEY;
	}

	trace_bcache_keyscan(refill.nr_found,
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
	freelist_free(&buf->freelist, w);
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

/* NOTE-2014.10.07:
   - To avoid grabbing the lock, we could make target_size atomic.
   Note, however, that it is not currently necessary to grab the lock
   as this is only called from sysfs which has a mutex with itself and
   is the only thing that can change the target size.
   However, this is cleaner, and sysfs perf. is not critical.
*/

unsigned bch_keybuf_size(struct keybuf *buf)
{
	unsigned ret;

	spin_lock(&buf->lock);
	ret = ((freelist_get_target_size (&buf->freelist)) >> 1);
	spin_unlock(&buf->lock);

	return ret;
}

/* NOTE-2014.10.07: bch_keybuf_resize breaks the freelist abstraction
   due to the requirement that the semaphore's count hold 1/2 of the
   resources of the pool.

   This can only be called during initialization, when the structure is not
   yet 'published' and hence there is no concurrency issue, or while holding
   some mutex that prevents this routine from running more than once.
   Apparently sysfs has such a mutex, and hence we don't implement a mutex
   of our own.

   When growing the keybuf,
   - we allocate all new nodes up front (during this call).
   - we increase the semaphore's resource count to match.
   Note that because we allocate the nodes up front, freelist_alloc
   will never call kmalloc for these freelists but is retained in the code
   for other possible users.

   When shriking the keybuf,
   - we decrease the semaphore's resource count to match.
   - we de-allocate as many nodes as we can.
   - we let the rest of the nodes be de-allocated as they are freed.

   The invariants are:
   - target_size is always even.
   - target_size (>>1) is always the number of resources in the semaphore.
   - current_size is the number of nodes allocated.  It may be odd.
   - length(free_list) = (current_size - in_use)
*/

static void bch_keybuf_resize_internal(struct keybuf *buf,
				       unsigned new_tgt_size,
				       bool update_semaphore)
{
	unsigned i, delta_sem;
	unsigned cur_tgt_size = (bch_keybuf_size(buf));

	if (new_tgt_size == cur_tgt_size)
		return;

	if (new_tgt_size > cur_tgt_size) {
		/* Allocate the new nodes in pairs,
		   upping current_size and target_size as we go.
		   Upgrade the semaphore per pair allocated.
		*/

		while (1) {
			typeof(buf->freelist.free_list) _ptr1, _ptr2;

			_ptr1 = ((typeof(buf->freelist.free_list))
				 (kmalloc((sizeof(*_ptr1)), GFP_KERNEL)));
			_ptr2 = ((typeof(buf->freelist.free_list))
				 (kmalloc((sizeof(*_ptr2)), GFP_KERNEL)));

			if ((_ptr1 == NULL) || (_ptr2 == NULL)) {
				if (_ptr1 != NULL)
					kfree(_ptr1);
				if (_ptr2 != NULL)
					kfree(_ptr2);
				break;
			}

			*((typeof(buf->freelist.free_list) *) _ptr1) = _ptr2;

			spin_lock(&buf->lock);

			if ((buf->freelist.current_size)
			    >= (new_tgt_size << 1)) {
				spin_unlock(&buf->lock);
				kfree(_ptr1);
				kfree(_ptr2);
				break;
			}

			*((typeof(buf->freelist.free_list) *) _ptr2)
				= (buf->freelist.free_list);

			buf->freelist.free_list = _ptr1;
			buf->freelist.current_size += (1 << 1);
			buf->freelist.target_size += (1 << 1);

			spin_unlock(&buf->lock);

			/* Increase the semaphore's resource count to match.
			   This can spinlock, but not sleep.
			*/
			if (update_semaphore)
				up(&buf->in_flight);
		}
	} else {
		/* 1st, reduce the semaphore's resource count.
		   down will sleep as necessary.
		 */
		delta_sem = (cur_tgt_size - new_tgt_size);

		if (update_semaphore) {
			for (i = 0; (i < delta_sem); i++)
				down(&buf->in_flight);
		}

		/* Now set the target size to match.
		   The moment we do this, freelist_free can start
		   actually de-allocating nodes.
		   We update the target size under lock as otherwise we'd have
		   to make it atomic since bcache is reading it as it runs.
		   Using the spin lock is fine as sysfs perf. is not critical.
		 */

		spin_lock(&buf->lock);
		freelist_set_target_size((&buf->freelist),
					 (new_tgt_size << 1));
		spin_unlock(&buf->lock);

		/* Now de-allocate as many nodes as we can, being careful
		   to sample current_size and free_list under lock.
		   We unlock after every de-allocation to allow the bcache
		   code to run.
		   The rest of the nodes will be de-allocated by freelist_free
		   as the bcache code runs.
		*/

		while (1) {
			typeof(buf->freelist.free_list) _ptr;

			spin_lock(&buf->lock);

			_ptr = (buf->freelist.free_list);

			if ((_ptr == NULL)
			    || ((buf->freelist.current_size) <= new_tgt_size)) {
				spin_unlock(&buf->lock);
				break;
			}

			buf->freelist.free_list =
				(*((typeof(buf->freelist.free_list) *) _ptr));
			buf->freelist.current_size -= 1;
			spin_unlock(&buf->lock);

			kfree(_ptr);
		}
	}
	return;
}

void bch_keybuf_resize(struct keybuf *buf, unsigned new_tgt_size)
{
	bch_keybuf_resize_internal(buf, new_tgt_size, true);
	return;
}

void bch_keybuf_init(struct keybuf *buf, unsigned dflt_tgt_size)
{
	/* We initialize everything to 0 */

	sema_init(&buf->in_flight, 0);

	buf->last_scanned	= MAX_KEY;
	buf->keys		= RB_ROOT;

	spin_lock_init(&buf->lock);
	freelist_allocator_init(&buf->freelist, 0);

	/* Now we resize everything to the default size.
	   This allocates all the nodes and ups the semaphore resource count
	   accordingly.
	*/
	bch_keybuf_resize_internal(buf, dflt_tgt_size, true);
	return;
}

/* NOTE-2014.10.07: When bch_keybuf_destroy is called, not all the
   nodes may have been returned to the freelist, but the freelist should
   be quiesced, and the rest of the nodes should be in the red/black tree.

   If it is not quiesced, bad things will happen (possible deadlock).
   The calls to spin_lock/spin_unlock below should be unnecessary,
   but it is cleanest to always do it, and the tear down code should not
   be perf. critical.
*/

void bch_keybuf_free(struct keybuf *buf)
{
	/* 1st resize, freeing up the free list */
	bch_keybuf_resize_internal(buf, 0, false);
	BUG_ON(buf->freelist.free_list != NULL);

	/* Now free up the red/black tree */
	if (buf->keys.rb_node != ((struct rb_node *) NULL)) {
		struct rb_node *ptr, *next;
		struct keybuf_key *kbk;

		BUG_ON(buf->freelist.current_size == 0);
		BUG_ON(buf->freelist.in_use == 0);
		ptr = (rb_first_postorder(&buf->keys));
		while (ptr != NULL) {
			next = (rb_next_postorder(ptr));
			kbk = (container_of(ptr, struct keybuf_key, node));
			BUG_ON(((atomic_read(&kbk->ref)) != 0)
			       && ((atomic_read(&kbk->ref)) != -1));
			kfree(kbk);
			spin_lock(&buf->lock);
			buf->freelist.in_use -= 1;
			buf->freelist.current_size -= 1;
			spin_unlock(&buf->lock);
			ptr = next;
		}
	}

	spin_lock(&buf->lock);
	BUG_ON(buf->freelist.free_list != NULL);
	BUG_ON(buf->freelist.current_size != 0);
	BUG_ON(buf->freelist.in_use != 0);
	spin_unlock(&buf->lock);

	return;
}
