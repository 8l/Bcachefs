
#include "bcache.h"

/* Journalling */

static void btree_journal_read_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	bio_put(bio);
	closure_put(cl, bcache_wq);
}

static int btree_journal_read_bucket(struct cache *ca, struct list_head *list,
				     struct btree_op *op, sector_t bucket)
{
	struct bio *bio = &ca->journal_bio;
	struct journal_replay *i;
	struct jset *j, *data = ca->set->journal.w[0].data;
	unsigned len, left, offset = 0;
	int ret = 0;

	pr_debug("reading %llu", (uint64_t) bucket);
	bucket = bucket_to_sector(ca->set, ca->sb.d[bucket]);

	while (offset < ca->sb.bucket_size) {
reread:		left = ca->sb.bucket_size - offset;
		len = min_t(unsigned, left, PAGE_SECTORS * 8);

		bio_reset(bio);
		bio->bi_sector	= bucket + offset;
		bio->bi_bdev	= ca->bdev;
		bio->bi_rw	= READ;
		bio->bi_size	= len << 9;

		bio->bi_end_io	= btree_journal_read_endio;
		bio->bi_private = &op->cl;
		bio_map(bio, data);

		closure_get(&op->cl);
		closure_bio_submit(bio, &op->cl, ca->set->bio_split);
		closure_sync(&op->cl);

		/* This function could be simpler now since we no longer write
		 * journal entries that overlap bucket boundaries; this means
		 * the start of a bucket will always have a valid journal entry
		 * if it has any journal entries at all.
		 */

		j = data;
		while (len) {
			struct list_head *where;
			size_t blocks, bytes = set_bytes(j);

			if (j->magic != jset_magic(ca->set))
				return ret;

			if (bytes > left << 9)
				return ret;

			if (bytes > len << 9)
				goto reread;

			if (j->csum != csum_set(j))
				return ret;

			blocks = set_blocks(j, ca->set);

			while (!list_empty(list)) {
				i = list_first_entry(list,
					struct journal_replay, list);
				if (i->j.seq >= j->last_seq)
					break;
				list_del(&i->list);
				kfree(i);
			}

			list_for_each_entry_reverse(i, list, list) {
				if (j->seq == i->j.seq)
					goto next_set;

				if (j->seq < i->j.last_seq)
					goto next_set;

				if (j->seq > i->j.seq) {
					where = &i->list;
					goto add;
				}
			}

			where = list;
add:
			i = kmalloc(offsetof(struct journal_replay, j) +
				    bytes, GFP_KERNEL);
			if (!i)
				return -ENOMEM;
			memcpy(&i->j, j, bytes);
			list_add(&i->list, where);
			ret = 1;
next_set:
			offset	+= blocks * ca->sb.block_size;
			len	-= blocks * ca->sb.block_size;
			j = ((void *) j) + blocks * block_bytes(ca);
		}
	}

	return ret;
}

int btree_journal_read(struct cache_set *c, struct list_head *list,
		       struct btree_op *op)
{
#define read_bucket(b)							\
	({								\
		int ret = btree_journal_read_bucket(ca, list, op, b);	\
		__set_bit(b, bitmap);					\
		if (ret < 0)						\
			goto err;					\
		ret;							\
	})

	struct cache *ca;

	for_each_cache(ca, c) {
		unsigned long bitmap[SB_JOURNAL_BUCKETS / BITS_PER_LONG];
		unsigned l, r, m;

		bitmap_zero(bitmap, SB_JOURNAL_BUCKETS);
		pr_debug("%u journal buckets", ca->sb.njournal_buckets);

		/* Read journal buckets ordered by golden ratio hash to quickly
		 * find a sequence of buckets with valid journal entries
		 */
		for (unsigned i = 0; i < ca->sb.njournal_buckets; i++) {
			l = (i * 2654435769U) % ca->sb.njournal_buckets;

			if (test_bit(l, bitmap))
				break;

			if (read_bucket(l))
				goto bsearch;
		}

		/* If that fails, check all the buckets we haven't checked
		 * already
		 */
		pr_debug("falling back to linear search");

		for (l = 0; l < ca->sb.njournal_buckets; l++) {
			if (test_bit(l, bitmap))
				continue;

			if (read_bucket(l))
				goto bsearch;
		}
bsearch:
		/* Binary search */
		m = r = find_next_bit(bitmap, ca->sb.njournal_buckets, l + 1);
		pr_debug("starting binary search, l %u r %u", l, r);

		while (l + 1 < r) {
			m = (l + r) >> 1;

			if (read_bucket(m))
				l = m;
			else
				r = m;
		}

		/* Read buckets in reverse order until we stop finding more
		 * journal entries
		 */
		pr_debug("finishing up");
		l = m;

		while (1) {
			if (!l--)
				l = ca->sb.njournal_buckets - 1;

			if (l == m)
				break;

			if (test_bit(l, bitmap))
				continue;

			if (!read_bucket(l))
				break;
		}
	}
err:
	return 0;
}

void btree_journal_mark(struct cache_set *c, struct list_head *list)
{
	atomic_t p = { 0 };
	struct journal_replay *i =
		list_first_entry(list, struct journal_replay, list);
	uint64_t last = i->j.seq - 1;

	list_for_each_entry(i, list, list) {
		while (++last != i->j.seq) {
			BUG_ON(!fifo_push(&c->journal.pin, p));
			atomic_set(&fifo_back(&c->journal.pin), 0);
		}

		BUG_ON(!fifo_push(&c->journal.pin, p));
		atomic_set(&fifo_back(&c->journal.pin), 1);

		i->pin = &fifo_back(&c->journal.pin);

		for (struct bkey *k = i->j.start; k < end(&i->j); k = next(k)) {
			for (unsigned j = 0; j < KEY_PTRS(k); j++) {
				struct bucket *g = PTR_BUCKET(c, k, j);
				atomic_inc(&g->pin);

				if (g->prio == btree_prio &&
				    !ptr_stale(c, k, j))
					g->prio = initial_prio;
			}

			__btree_mark_key(c, 0, k);
		}
	}
}

int btree_journal_replay(struct cache_set *s, struct list_head *list,
			 struct btree_op *op)
{
	int ret = 0, keys = 0, entries = 0;
	struct journal_replay *i =
		list_entry(list->prev, struct journal_replay, list);

	uint64_t start = i->j.last_seq, end = i->j.seq, last = start - 1;

	op->insert_type = INSERT_REPLAY;

	list_for_each_entry(i, list, list) {
		BUG_ON(atomic_read(i->pin) != 1);

		last++;
		BUG_ON(last > i->j.seq);
		if (last != i->j.seq)
			err_printk("journal entries %llu-%llu "
				   "missing! (replaying %llu-%llu)\n",
				   last, i->j.seq, start, end);

		for (struct bkey *k = i->j.start; k < end(&i->j); k = next(k)) {
			pr_debug("%s", pkey(k));
			bkey_copy(op->keys.top, k);
			keylist_push(&op->keys);

			op->journal = i->pin;
			atomic_inc(op->journal);

			ret = __btree_insert_async(op, s);
			if (ret)
				goto err;

			BUG_ON(!keylist_empty(&op->keys));
			keys++;
		}

		atomic_dec(i->pin);
		last = i->j.seq;
		entries++;
	}

	printk(KERN_INFO "bcache: journal replay done, %i keys in %i "
	       "entries, seq %llu-%llu\n", keys, entries, start, end);

	while (!list_empty(list)) {
		i = list_first_entry(list, struct journal_replay, list);
		list_del(&i->list);
		kfree(i);
	}
err:
	closure_sync(&op->cl);
	return ret;
}

void btree_flush_write(struct cache_set *s)
{
	struct btree *b, *i;

	while (!s->root->level) {
		i = s->root;
		rw_lock(true, i, 0);

		if (i == s->root)
			goto found;
		rw_unlock(true, i);
	}

	spin_lock(&s->bucket_lock);

	i = NULL;
	list_for_each_entry(b, &s->lru, lru) {
		if (!down_write_trylock(&b->lock))
			continue;

		if (!b->write || !b->write->journal)
			goto next;

		if (i && journal_pin_cmp(s, i->write, b->write)) {
			rw_unlock_nowrite(true, i);
			i = NULL;
		}

		if (!i) {
			i = b;
			continue;
		}
next:
		rw_unlock_nowrite(true, b);
	}

	if (!i) {
		/* We can't find the best btree, just pick the first */
		list_for_each_entry(b, &s->lru, lru)
			if (!b->level && b->write) {
				i = b;
				break;
			}

		spin_unlock(&s->bucket_lock);
		if (!i)
			return;

		rw_lock(true, i, i->level);
	} else
		spin_unlock(&s->bucket_lock);
found:
	i->expires = jiffies;
	if (i->work.timer.function)
		mod_timer_pending(&i->work.timer, i->expires);

	rw_unlock(true, i);
	pr_debug("");
}

static void btree_journal_alloc(struct cache_set *s)
{
	struct journal_write *w = s->journal.cur;
	struct cache *c;
	unsigned n = 0, free;

	s->journal.sectors_free = UINT_MAX;

	/* XXX: Sort by free journal space */

	for_each_cache(c, s) {
		if (c->journal_start == c->journal_end)
			continue;

		if (c->journal_start == c->journal_area_end)
			c->journal_start = c->journal_area_start;

		w->key.ptr[n++] = PTR(0, c->journal_start, c->sb.nr_this_dev);

		free = c->journal_start < c->journal_end
			? c->journal_end
			: c->journal_area_end;
		free -= c->journal_start;

		free = min_t(unsigned, free, c->sb.bucket_size -
			     bucket_remainder(s, c->journal_start));
		BUG_ON(!free);

		s->journal.sectors_free = min(s->journal.sectors_free, free);
	}

	if (n)
		closure_run_wait(&w->c->journal.wait, bcache_wq);

	w->key.header = KEY_HEADER(0, 0);
	SET_KEY_PTRS(&w->key, n);
}

#define last_seq(j)	((j)->seq - fifo_used(&(j)->pin) + 1)

static void btree_journal_reclaim(struct cache_set *s)
{
	struct cache *c;
	struct journal_seq j;
	atomic_t p;
	bool popped = false, full = journal_full(s);

	while (fifo_used(&s->journal.pin) > 1 &&
	       !atomic_read(&fifo_front(&s->journal.pin))) {
		fifo_pop(&s->journal.pin, p);
		popped = true;
	}

	if (!popped)
		return;

	if (full)
		pr_debug("journal_pin popped");

	for_each_cache(c, s)
		while (!fifo_empty(&c->journal) &&
		       fifo_front(&c->journal).sector != c->journal_start &&
		       fifo_front(&c->journal).seq < last_seq(&s->journal)) {
			fifo_pop(&c->journal, j);
			c->journal_end = j.sector;
		}

	if (!KEY_PTRS(&s->journal.cur->key)) {
		pr_debug("allocating");
		btree_journal_alloc(s);
	}

	closure_run_wait(&s->journal.wait, bcache_wq);
}

static void __btree_journal_meta(struct cache_set *c)
{
	struct cache *ca;
	struct journal_write *w = c->journal.cur;

	w->data->btree_level = c->root->level;

	bkey_copy(&w->data->btree_root, &c->root->key);
	bkey_copy(&w->data->uuid_bucket, &c->uuid_bucket);

	for_each_cache(ca, c)
		w->data->prio_bucket[ca->sb.nr_this_dev] = ca->prio_start;

	w->data->magic = jset_magic(c);
}

void btree_journal_next(struct cache_set *s)
{
	struct journal_write *w = s->journal.cur;
	atomic_t p = { 0 };

	for (unsigned i = 0; i < KEY_PTRS(&w->key); i++) {
		struct cache *c = PTR_CACHE(s, &w->key, i);
		struct journal_seq seq = { .seq = w->data->seq };

		c->journal_start += set_blocks(w->data, s) * s->sb.block_size;
		BUG_ON(c->journal_start > c->journal_area_end);

		seq.sector = c->journal_start;
		BUG_ON(!fifo_push(&c->journal, seq));
	}

	w = s->journal.cur = w == s->journal.w
		? &s->journal.w[1]
		: &s->journal.w[0];

	BUG_ON(!fifo_push(&s->journal.pin, p));
	atomic_set(&fifo_back(&s->journal.pin), 0);

	w->need_write		= false;
	w->data->keys		= 0;
	w->data->seq		= ++s->journal.seq;
	w->data->last_seq	= last_seq(&s->journal);

	__btree_journal_meta(s);

	if (fifo_full(&s->journal.pin))
		pr_debug("journal_pin full (%zu)", fifo_used(&s->journal.pin));

	btree_journal_alloc(s);
}

static void btree_journal_endio(struct bio *bio, int error)
{
	struct journal_write *w = bio->bi_private;
	bio_put(bio);

	cache_set_err_on(error, w->c, "journal io error");

	if (!atomic_dec_and_test(&w->c->journal.io))
		return;

	closure_run_wait(&w->wait, bcache_wq);
	atomic_set(&w->c->journal.io, -1);
	schedule_work(&w->c->journal.work);
}

static void btree_journal_write(struct cache_set *s, struct journal_write *w)
{
	w->data->csum = csum_set(w->data);

	for (unsigned i = 0; i < KEY_PTRS(&w->key); i++) {
		struct cache *c = PTR_CACHE(s, &w->key, i);
		struct bio *bio = &c->journal_bio;

		atomic_long_add(set_blocks(w->data, s) * c->sb.block_size,
				&c->meta_sectors_written);

		bio_reset(bio);
		bio->bi_sector	= PTR_OFFSET(&w->key, i);
		bio->bi_bdev	= c->bdev;
		bio->bi_rw	= REQ_WRITE|REQ_SYNC|REQ_META;
		bio->bi_size	= set_blocks(w->data, s) * block_bytes(s);

		bio->bi_end_io	= btree_journal_endio;
		bio->bi_private = w;
		bio_map(bio, w->data);

		pr_debug("write to sector %llu", (uint64_t) bio->bi_sector);
		atomic_inc(&s->journal.io);
		bio_submit_split(bio, &s->journal.io, s->bio_split);
	}
}

static void __btree_journal_try_write(struct cache_set *c, bool noflush)
{
	struct journal_write *w = c->journal.cur;

	if (!w->need_write)
		spin_unlock(&c->journal.lock);
	else if (journal_full(c)) {
		btree_journal_reclaim(c);
		spin_unlock(&c->journal.lock);

		if (!noflush)
			btree_flush_write(c);
		schedule_work(&c->journal.work);
	} else if (atomic_cmpxchg(&c->journal.io, -1, 0) == -1) {
		btree_journal_next(c);
		spin_unlock(&c->journal.lock);
		btree_journal_write(c, w);
	} else
		spin_unlock(&c->journal.lock);
}

#define btree_journal_try_write(c)	__btree_journal_try_write(c, false)

void btree_journal_work(struct work_struct *work)
{
	struct journal *j = container_of(work, struct journal, work);
	struct cache_set *c = container_of(j, struct cache_set, journal);

	spin_lock(&c->journal.lock);
	btree_journal_try_write(c);
}

void btree_journal_wait(struct cache_set *c, struct closure *cl)
{
	struct journal_write *w;

	spin_lock(&c->journal.lock);
	w = c->journal.cur;
	if (w->need_write)
		BUG_ON(!closure_wait(&w->wait, cl));

	btree_journal_try_write(c);
}

void btree_journal_meta(struct cache_set *c, struct closure *cl)
{
	if (CACHE_SYNC(&c->sb)) {
		spin_lock(&c->journal.lock);
		c->journal.cur->need_write = true;

		if (cl)
			BUG_ON(!closure_wait(&c->journal.cur->wait, cl));

		__btree_journal_meta(c);
		__btree_journal_try_write(c, true);
	}
}

void btree_journal(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct cache_set *c = op->d->c;
	struct journal_write *w;
	size_t b, n = ((uint64_t *) op->keys.top) - op->keys.list;

	if (!(op->insert_type & INSERT_WRITE) ||
	    !CACHE_SYNC(&c->sb))
		goto out;

	spin_lock(&c->journal.lock);

	btree_journal_reclaim(c);

	if (journal_full(c)) {
		/* XXX: tracepoint */
		BUG_ON(!closure_wait(&c->journal.wait, cl));
		spin_unlock(&c->journal.lock);

		btree_flush_write(c);
		return_f(cl, btree_journal);
	}

	w = c->journal.cur;
	b = __set_blocks(w->data, w->data->keys + n, c);

	if (b * c->sb.block_size > PAGE_SECTORS << JSET_BITS ||
	    b * c->sb.block_size > c->journal.sectors_free) {
		/* XXX: tracepoint */
		BUG_ON(!closure_wait(&w->wait, cl));

		btree_journal_try_write(c);
		return_f(cl, btree_journal);
	}

	memcpy(end(w->data), op->keys.list, n * sizeof(uint64_t));
	w->data->keys += n;
	w->need_write = true;

	op->journal = &fifo_back(&c->journal.pin);
	atomic_inc(op->journal);

	/* XXX: if bio_insert doesn't finish on the first loop through this may
	 * bug
	 */
	BUG_ON(!closure_wait(&w->wait, cl->parent));

	btree_journal_try_write(c);
out:
	btree_insert_async(cl);
}

