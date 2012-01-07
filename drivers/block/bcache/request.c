
#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "request.h"

#include <linux/cgroup.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <linux/random.h>
#include "blk-cgroup.h"

#include <trace/events/bcache.h>

#define CUTOFF_CACHE_ADD	95
#define CUTOFF_CACHE_READA	90
#define CUTOFF_WRITEBACK	50
#define CUTOFF_WRITEBACK_SYNC	75

struct bio_passthrough {
	struct closure		cl;
	struct cached_dev	*d;
	struct bio		*bio;
	bio_end_io_t		*bi_end_io;
	void			*bi_private;
};

struct kmem_cache *passthrough_cache;

struct kmem_cache *search_cache;

static void bio_invalidate(struct search *);
static void __request_read(struct closure *);

/* Cgroup interface */

#ifdef CONFIG_CGROUP_BCACHE

static struct bcache_cgroup {
	struct cgroup_subsys_state	css;
	/*
	 * We subtract one from the index into bcache_cache_modes[], so that
	 * default == -1; this makes it so the rest match up with d->cache_mode,
	 * and we use d->cache_mode if cgrp->cache_mode < 0
	 */
	short				cache_mode;
	bool				verify;
	union {

		atomic_t		stats[2][2];
		struct {
			atomic_t	cache_hits;
			atomic_t	cache_misses;
			atomic_t	cache_bypass_hits;
			atomic_t	cache_bypass_misses;
		};
	};
} bcache_default_cgroup = { .cache_mode = -1 };

static struct bcache_cgroup *cgroup_to_bcache(struct cgroup *cgroup)
{
	struct cgroup_subsys_state *css;
	return cgroup &&
		(css = cgroup_subsys_state(cgroup, bcache_subsys_id))
		? container_of(css, struct bcache_cgroup, css)
		: &bcache_default_cgroup;
}

static struct bcache_cgroup *bio_to_cgroup(struct bio *bio)
{
	return cgroup_to_bcache(get_bio_cgroup(bio));
}

static ssize_t cache_mode_read(struct cgroup *cgrp, struct cftype *cft,
			struct file *file,
			char __user *buf, size_t nbytes, loff_t *ppos)
{
	char tmp[1024];
	int len = sprint_string_list(tmp, bcache_cache_modes,
				     cgroup_to_bcache(cgrp)->cache_mode + 1);

	if (len < 0)
		return len;

	return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
}

static int cache_mode_write(struct cgroup *cgrp, struct cftype *cft,
			    const char *buf)
{
	int v = read_string_list(buf, bcache_cache_modes);
	if (v < 0)
		return v;

	cgroup_to_bcache(cgrp)->cache_mode = v - 1;
	return 0;
}

static u64 bcache_verify_read(struct cgroup *cgrp, struct cftype *cft)
{
	return cgroup_to_bcache(cgrp)->verify;
}

static int bcache_verify_write(struct cgroup *cgrp, struct cftype *cft, u64 val)
{
	cgroup_to_bcache(cgrp)->verify = val;
	return 0;
}

static u64 bcache_cache_hits_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct bcache_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->cache_hits);
}

static u64 bcache_cache_misses_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct bcache_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->cache_misses);
}

static u64 bcache_cache_bypass_hits_read(struct cgroup *cgrp,
					 struct cftype *cft)
{
	struct bcache_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->cache_bypass_hits);
}

static u64 bcache_cache_bypass_misses_read(struct cgroup *cgrp,
					   struct cftype *cft)
{
	struct bcache_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->cache_bypass_misses);
}

struct cftype bcache_files[] = {
	{
		.name		= "cache_mode",
		.read		= cache_mode_read,
		.write_string	= cache_mode_write,
	},
	{
		.name		= "verify",
		.read_u64	= bcache_verify_read,
		.write_u64	= bcache_verify_write,
	},
	{
		.name		= "cache_hits",
		.read_u64	= bcache_cache_hits_read,
	},
	{
		.name		= "cache_misses",
		.read_u64	= bcache_cache_misses_read,
	},
	{
		.name		= "cache_bypass_hits",
		.read_u64	= bcache_cache_bypass_hits_read,
	},
	{
		.name		= "cache_bypass_misses",
		.read_u64	= bcache_cache_bypass_misses_read,
	},
};

static void init_bcache_cgroup(struct bcache_cgroup *cg)
{
	cg->cache_mode = -1;
}

static struct cgroup_subsys_state *
bcachecg_create(struct cgroup_subsys *subsys, struct cgroup *cgroup)
{
	struct bcache_cgroup *cg;

	cg = kzalloc(sizeof(*cg), GFP_KERNEL);
	if (!cg)
		return ERR_PTR(-ENOMEM);
	init_bcache_cgroup(cg);
	return &cg->css;
}

static void bcachecg_destroy(struct cgroup_subsys *subsys,
			     struct cgroup *cgroup)
{
	struct bcache_cgroup *cg = cgroup_to_bcache(cgroup);
	free_css_id(&bcache_subsys, &cg->css);
	kfree(cg);
}

static int bcachecg_populate(struct cgroup_subsys *subsys,
			     struct cgroup *cgroup)
{
	return cgroup_add_files(cgroup, subsys, bcache_files,
				ARRAY_SIZE(bcache_files));
}

struct cgroup_subsys bcache_subsys = {
	.create		= bcachecg_create,
	.destroy	= bcachecg_destroy,
	.populate	= bcachecg_populate,
	.subsys_id	= bcache_subsys_id,
	.name		= "bcache",
	.module		= THIS_MODULE,
};
EXPORT_SYMBOL_GPL(bcache_subsys);
#endif

static unsigned cache_mode(struct search *s)
{
#ifdef CONFIG_CGROUP_BCACHE
	int r = bio_to_cgroup(s->orig_bio)->cache_mode;
	if (r >= 0)
		return r;
#endif
	return BDEV_CACHE_MODE(&s->op.d->sb);
}

static bool verify(struct search *s)
{
	if (s->op.d->verify)
		return true;
#ifdef CONFIG_CGROUP_BCACHE
	return bio_to_cgroup(s->orig_bio)->verify;
#else
	return 0;
#endif
}

static void bio_csum(struct bio *bio, struct bkey *k)
{
	struct bio_vec *bv;
	uint64_t csum = 0;
	int i;

	bio_for_each_segment(bv, bio, i) {
		void *d = kmap(bv->bv_page) + bv->bv_offset;
		csum = crc64_update(csum, d, bv->bv_len);
		kunmap(bv->bv_page);
	}

	k->ptr[KEY_PTRS(k)] = csum & (~0ULL >> 1);
}

/* Insert data into cache */

struct open_bucket {
	struct list_head	list;
	struct task_struct	*last;
	unsigned		sectors_free;
	BKEY_PADDED(key);
};

void bcache_open_buckets_free(struct cache_set *c)
{
	struct open_bucket *b;

	while (!list_empty(&c->data_buckets)) {
		b = list_first_entry(&c->data_buckets,
				     struct open_bucket, list);
		list_del(&b->list);
		kfree(b);
	}
}

int bcache_open_buckets_alloc(struct cache_set *c)
{
	spin_lock_init(&c->data_bucket_lock);

	for (int i = 0; i < 6; i++) {
		struct open_bucket *b = kzalloc(sizeof(*b), GFP_KERNEL);
		if (!b)
			return -ENOMEM;

		list_add(&b->list, &c->data_buckets);
	}

	return 0;
}

static void put_data_bucket(struct open_bucket *b, struct cache_set *c,
			    struct bkey *k, struct bio *bio)
{
	unsigned split = min(bio_sectors(bio), b->sectors_free);

	for (unsigned i = 0; i < KEY_PTRS(&b->key); i++)
		split = min(split, __bio_max_sectors(bio,
				      PTR_CACHE(c, &b->key, i)->bdev,
				      PTR_OFFSET(&b->key, i)));

	b->key.key += split;

	bkey_copy(k, &b->key);
	SET_KEY_SIZE(k, split);

	b->sectors_free	-= split;

	/* If we're closing this open bucket, get_data_bucket()'s refcount now
	 * belongs to the key that's being inserted
	 */
	if (b->sectors_free < c->sb.block_size)
		b->sectors_free = 0;
	else
		for (unsigned i = 0; i < KEY_PTRS(&b->key); i++)
			atomic_inc(&PTR_BUCKET(c, &b->key, i)->pin);

	for (unsigned i = 0; i < KEY_PTRS(&b->key); i++) {
		atomic_long_add(split,
				&PTR_CACHE(c, &b->key, i)->sectors_written);

		SET_PTR_OFFSET(&b->key, i, PTR_OFFSET(&b->key, i) + split);
	}

	spin_unlock(&c->data_bucket_lock);
}

static struct open_bucket *get_data_bucket(struct bkey *search,
					   struct search *s)
{
	struct closure cl, *w = NULL;
	struct cache_set *c = s->op.d->c;
	struct open_bucket *l, *ret, *ret_task;

	BKEY_PADDED(key) alloc;
	struct bkey *k = NULL;

	if (s->op.insert_type == INSERT_WRITEBACK) {
		closure_init_stack(&cl);
		w = &cl;
	}
again:
	ret = ret_task = NULL;

	spin_lock(&c->data_bucket_lock);
	list_for_each_entry_reverse(l, &c->data_buckets, list)
		if (!bkey_cmp(&l->key, search)) {
			ret = l;
			goto found;
		} else if (l->last == s->task)
			ret_task = l;

	ret = ret_task ?: list_first_entry(&c->data_buckets,
					   struct open_bucket, list);
found:
	if (!ret->sectors_free) {
		if (!k) {
			spin_unlock(&c->data_bucket_lock);
			k = &alloc.key;

			if (pop_bucket_set(c, initial_prio, k, 1, w))
				return NULL;

			goto again;
		}

		bkey_copy(&ret->key, k);
		k = NULL;

		ret->sectors_free = c->sb.bucket_size;
	} else
		for (unsigned i = 0; i < KEY_PTRS(&ret->key); i++)
			EBUG_ON(ptr_stale(c, &ret->key, i));

	if (k)
		__bkey_put(c, k);

	if (w)
		for (unsigned i = 0; i < KEY_PTRS(&ret->key); i++)
			PTR_BUCKET(c, &ret->key, i)->mark = GC_MARK_DIRTY;

	ret->last = s->task;
	bkey_copy_key(&ret->key, search);

	list_move_tail(&ret->list, &c->data_buckets);
	return ret;
}

static void bio_insert_error(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);

	/*
	 * Our data write just errored, which means we've got a bunch of keys to
	 * insert that point to data that wasn't succesfully written.
	 *
	 * We don't have to insert those keys but we still have to invalidate
	 * that region of the cache - so, if we just strip off all the pointers
	 * from the keys we'll accomplish just that.
	 */

	struct bkey *src = op->keys.bottom, *dst = op->keys.bottom;

	while (src != op->keys.top) {
		struct bkey *n = next(src);

		SET_KEY_PTRS(src, 0);
		bkey_copy(dst, src);

		dst = next(dst);
		src = n;
	}

	op->keys.top = dst;

	bcache_journal(cl);
}

static void bio_insert_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);

	if (error) {
		/* TODO: We could try to recover from this. */
		if (op->insert_type == INSERT_WRITEBACK)
			s->error = error;

		if (op->insert_type == INSERT_WRITE)
			set_closure_fn(cl, bio_insert_error, bcache_wq);
		else
			set_closure_fn(cl, NULL, NULL);
	}

	bcache_endio(op->d->c, bio, error, "writing data to cache");
	closure_put(cl);
}

static void bio_insert(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = s->cache_bio, *n;
	unsigned sectors = bio_sectors(bio);

	bio->bi_end_io	= bio_insert_endio;
	bio->bi_private = cl;
	bio_get(bio);

	/* Make sure next fn is set for error path */
	set_closure_fn(cl, NULL, NULL);
	keylist_init(&op->keys);

	if (atomic_sub_return(bio_sectors(bio), &op->d->c->sectors_to_gc) < 0) {
		set_gc_sectors(op->d->c);
		queue_work(bcache_wq, &op->d->c->gc_work);
	}

	do {
		struct open_bucket *b;
		struct bkey *k;

		/* 1 for the device pointer and 1 for the chksum */
		if (keylist_realloc(&op->keys,
				    1 + (op->d->data_csum ? 1 : 0),
				    op->d->c))
			return_f(cl, bcache_journal, bcache_wq);

		k = op->keys.top;

		b = get_data_bucket(&KEY(op->d->id, bio->bi_sector, 0), s);
		if (!b)
			goto err;

		put_data_bucket(b, op->d->c, k, bio);

		n = bio_split_get(bio, KEY_SIZE(k), op->d);
		if (!n) {
			__bkey_put(op->d->c, k);
			return_f(cl, bio_insert, bcache_wq);
		}

		if (op->insert_type == INSERT_WRITEBACK)
			SET_KEY_DIRTY(k, true);

		SET_KEY_CSUM(k, op->d->data_csum);
		if (op->d->data_csum)
			bio_csum(n, k);

		pr_debug("%s", pkey(k));
		keylist_push(&op->keys);

		if (n == bio) {
			if (op->insert_type == INSERT_WRITEBACK)
				bcache_writeback_start(op->d);

			s->bio_done = true;
		}

		set_closure_fn(cl, bcache_journal, bcache_wq);
		n->bi_rw |= REQ_WRITE;

		trace_bcache_cache_insert(n, n->bi_sector, n->bi_bdev);
		submit_bbio(n, op->d->c, k, 0);
	} while (n != bio);

	return;
err:
	switch (op->insert_type) {
	case INSERT_WRITEBACK:
		/* This is dead code now, since we handle all memory allocation
		 * failures and block if we don't have free buckets
		 */
		BUG();
		/* Lookup in in_writeback rb tree, wait on appropriate
		 * closure, then invalidate in btree and do normal
		 * write
		 */
		s->bio_done	= true;
		s->error	= -ENOMEM;
		set_closure_fn(cl, NULL, NULL);
		break;
	case INSERT_WRITE:
		s->skip		= true;
		bio_invalidate(s);
		break;
	case INSERT_READ:
		s->bio_done	= true;
	}

	/* IO never happened, so bbio key isn't set up, so we can't call
	 * bio_endio()
	 */
	bio_put(bio);
	closure_put(cl);

	pr_debug("error for %s, %i/%i sectors done, bi_sector %llu",
		 insert_type(op), sectors - bio_sectors(bio), sectors,
		 (uint64_t) bio->bi_sector);
}

static void bio_invalidate(struct search *s)
{
	struct bio *bio = s->cache_bio;

	pr_debug("invalidating %i sectors from %llu",
		 bio_sectors(bio), (uint64_t) bio->bi_sector);

	set_closure_fn(&s->op.cl, bcache_journal, bcache_wq);
	keylist_init(&s->op.keys);

	while (bio_sectors(bio)) {
		unsigned len = min(bio_sectors(bio), 1U << 14);
		if (keylist_realloc(&s->op.keys, 0, s->op.d->c))
			return;

		bio->bi_sector	+= len;
		bio->bi_size	-= len << 9;

		keylist_add(&s->op.keys,
			    &KEY(s->op.d->id, bio->bi_sector, len));
	}

	s->bio_done = true;
}

void bcache_btree_insert_async(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
again:
	if (bcache_btree_insert(op, op->d->c)) {
		s->error	= -ENOMEM;
		s->bio_done	= true;
	}

	keylist_free(&s->op.keys);

	if (s->skip && !s->bio_done) {
		bio_invalidate(s);
		goto again;
	}

	return_f(cl, !s->bio_done
		 ? bio_insert : NULL, bcache_wq);
}

/* Process a bio */

static void __bio_complete(struct search *s)
{
	if (s->orig_bio) {
		if (s->error)
			clear_bit(BIO_UPTODATE, &s->orig_bio->bi_flags);

		trace_bcache_request_end(&s->op, s->orig_bio);
		bio_endio(s->orig_bio, s->error);
		s->orig_bio = NULL;
	}
}

static void bio_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *d = s->op.d;

	if (s->op.insert_type == INSERT_WRITE ||
	    s->op.insert_type == INSERT_WRITEBACK)
		up_read_non_owner(&d->writeback_lock);

	if (s->cache_bio) {
		int i;
		struct bio_vec *bv;

		if (s->op.insert_type == INSERT_READ)
			__bio_for_each_segment(bv, s->cache_bio, i, 0)
				__free_page(bv->bv_page);
		bio_put(s->cache_bio);
	}

	if (s->unaligned_bvec)
		mempool_free(s->bio.bio.bi_io_vec, d->unaligned_bvec);

	__bio_complete(s);

	closure_del(&s->cl);
	mempool_free(s, d->c->search);
	cached_dev_put(d);
}

static void request_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;

	if (error) {
		struct search *s = container_of(cl, struct search, cl);
		s->error = error;
		/* Only cache read errors are recoverable */
		s->recoverable = false;
	}

	bio_put(bio);
	closure_put(cl);
}

void cache_read_endio(struct bio *bio, int error)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct closure *cl = bio->bi_private;
	struct search *s = container_of(cl, struct search, cl);

	/*
	 * If the bucket was reused while our bio was in flight, we might have
	 * read the wrong data. Set s->error but not error so it doesn't get
	 * counted against the cache device, but we'll still reread the data
	 * from the backing device.
	 */

	if (error)
		s->error = error;
	else if (ptr_stale(s->op.d->c, &b->key, 0)) {
		atomic_long_inc(&s->op.d->c->cache_read_races);
		s->error = -EINTR;
	}

	bcache_endio(s->op.d->c, bio, error, "reading from cache");
	closure_put(cl);
}

int bcache_get_congested(struct cache_set *c)
{
	static const unsigned fract_bits = 6;
	unsigned fract;
	int ret, i;

	if (!c->congested_read_threshold_us &&
	    !c->congested_write_threshold_us)
		return 0;

	i = local_clock_us() - c->congested_last_us;
	if (i < 0)
		return 0;

	i /= 1024;
	i += atomic_read(&c->congested);
	if (i >= 0)
		return 0;

	i += CONGESTED_MAX;

	fract = i & ((1 << fract_bits) - 1);
	i >>= fract_bits;

	ret = 1 << i;
	ret += ((1 << i) * fract) >> fract_bits;

	return ret;
}

static void check_should_skip(struct search *s)
{
	void add_sequential(struct task_struct *t)
	{
		uint64_t avg = t->sequential_io_avg;

		avg *= 7;
		avg += t->sequential_io;
		avg /= 8;

		if (avg <= UINT_MAX)
			t->sequential_io_avg = avg;

		t->sequential_io = 0;
	}

	struct hlist_head *iohash(uint64_t k)
	{ return &s->op.d->io_hash[hash_64(k, RECENT_IO_BITS)]; }

	struct cached_dev *d = s->op.d;
	struct bio *bio = &s->bio.bio;
	int cutoff;

	if (atomic_read(&d->closing) ||
	    d->c->gc_stats.in_use > CUTOFF_CACHE_ADD ||
	    (bio->bi_rw & (1 << BIO_RW_DISCARD)))
		goto skip;

	if (cache_mode(s) == CACHE_MODE_NONE ||
	    (cache_mode(s) == CACHE_MODE_WRITEAROUND &&
	     (bio->bi_rw & REQ_WRITE)))
		goto skip;

	if (bio->bi_sector   & (d->c->sb.block_size - 1) ||
	    bio_sectors(bio) & (d->c->sb.block_size - 1)) {
		pr_debug("skipping unaligned io");
		goto skip;
	}

	cutoff = bcache_get_congested(d->c);

	if (!cutoff) {
		cutoff = d->sequential_cutoff >> 9;

		if (!cutoff)
			goto rescale;

		if (cache_mode(s) == CACHE_MODE_WRITEBACK &&
		    (bio->bi_rw & REQ_WRITE) &&
		    (bio->bi_rw & REQ_SYNC))
			goto rescale;
	}

	if (d->sequential_merge) {
		struct hlist_node *cursor;
		struct io *i;

		spin_lock(&d->lock);

		hlist_for_each_entry(i, cursor, iohash(bio->bi_sector), hash)
			if (i->last == bio->bi_sector &&
			    time_before(jiffies, i->jiffies))
				goto found;

		i = list_first_entry(&d->io_lru, struct io, lru);

		add_sequential(s->task);
		i->sequential = 0;
found:
		if (i->sequential + bio->bi_size > i->sequential)
			i->sequential	+= bio->bi_size;

		i->last			 = bio_end(bio);
		i->jiffies		 = jiffies + msecs_to_jiffies(5000);
		s->task->sequential_io	 = i->sequential;

		hlist_del(&i->hash);
		hlist_add_head(&i->hash, iohash(i->last));
		list_move_tail(&i->lru, &d->io_lru);

		spin_unlock(&d->lock);
	} else {
		s->task->sequential_io = bio->bi_size;

		add_sequential(s->task);
	}

	cutoff -= popcount_32(get_random_int());

	if (cutoff <= (int) (max(s->task->sequential_io,
				 s->task->sequential_io_avg) >> 9))
		goto skip;

rescale:
	rescale_priorities(d->c, bio_sectors(bio));
	return;
skip:
	atomic_add(bio_sectors(bio), &d->stats.sectors_bypassed);
	s->skip = true;
}

static void __do_bio_hook(struct search *s)
{
	struct bio *bio = &s->bio.bio;
	memcpy(bio, s->orig_bio, sizeof(struct bio));

#ifdef CONFIG_DISKMON
	bio->bi_flowid		= NULL;
#endif
	bio->bi_end_io		= request_endio;
	bio->bi_private		= &s->cl;
	bio->bi_destructor	= NULL;
	atomic_set(&bio->bi_cnt, 2);
}

static struct search *do_bio_hook(struct bio *bio, struct cached_dev *d)
{
	struct bio_vec *bv;
	struct search *s = mempool_alloc(d->c->search, GFP_NOIO);
	memset(s, 0, offsetof(struct search, op.keys));

	__closure_init(&s->cl, NULL);
	__closure_init(&s->op.cl, &s->cl);

	s->op.d			= d;
	s->op.lock		= -1;
	s->task			= get_current();
	s->orig_bio		= bio;
	s->recoverable		= 1;
	__do_bio_hook(s);

	if (bio->bi_size != bio_segments(bio) * PAGE_SIZE) {
		bv = mempool_alloc(d->unaligned_bvec, GFP_NOIO);
		memcpy(bv, bio_iovec(bio),
		       sizeof(struct bio_vec) * bio_segments(bio));

		s->bio.bio.bi_io_vec	= bv;
		s->unaligned_bvec	= 1;
	}

	return s;
}

/* Process reads */

static void setup_cache_miss(struct search *s, unsigned reada)
{
	struct bio *bio = s->cache_miss;

	if ((bio->bi_rw & REQ_RAHEAD) ||
	    (bio->bi_rw & REQ_META) ||
	    s->op.d->c->gc_stats.in_use >= CUTOFF_CACHE_READA)
		reada = 0;

	if (bio_end(bio) + reada >
	    (sector_t) (bio->bi_bdev->bd_inode->i_size >> 9))
		reada = (bio->bi_bdev->bd_inode->i_size >> 9) - bio_end(bio);

	if (reada)
		atomic_inc(&s->op.d->stats.cache_readaheads);

	s->cache_bio_sectors = bio_sectors(bio) + reada;

	s->cache_bio = bbio_kmalloc(GFP_NOIO,
			DIV_ROUND_UP(s->cache_bio_sectors, PAGE_SECTORS));
	if (!s->cache_bio)
		return;

	s->cache_bio->bi_sector	= bio->bi_sector;
	s->cache_bio->bi_bdev	= bio->bi_bdev;
	s->cache_bio->bi_size	= s->cache_bio_sectors << 9;

	s->cache_bio->bi_end_io	= request_endio;
	s->cache_bio->bi_private = &s->cl;

	bio_map(s->cache_bio, NULL);
	if (bio_alloc_pages(s->cache_bio, __GFP_NOWARN|GFP_NOIO)) {
		bio_put(s->cache_bio);
		s->cache_bio = NULL;
		return;
	}

	bio_get(s->cache_bio);
}

static void request_read_error(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio_vec *bv;
	int i;

	if (s->recoverable) {
		/* The cache read failed, but we can retry from the backing
		 * device.
		 */
		pr_debug("recovering at sector %llu",
			 (uint64_t) s->orig_bio->bi_sector);

		s->error = 0;
		bv = s->bio.bio.bi_io_vec;
		__do_bio_hook(s);
		s->bio.bio.bi_io_vec = bv;

		if (!s->unaligned_bvec)
			bio_for_each_segment(bv, s->orig_bio, i)
				bv->bv_offset = 0, bv->bv_len = PAGE_SIZE;
		else
			memcpy(s->bio.bio.bi_io_vec,
			       bio_iovec(s->orig_bio),
			       sizeof(struct bio_vec) *
			       bio_segments(s->orig_bio));

		/* XXX: invalidate cache */

		closure_get(&s->cl);
		trace_bcache_read_retry(&s->bio.bio);
		closure_bio_submit(&s->bio.bio, &s->cl, s->op.d->c->bio_split);
	}

	return_f(cl, bio_complete, NULL);
}

static void do_verify(struct search *s)
{
	char name[BDEVNAME_SIZE];
	struct bio *check;
	struct bio_vec *bv;
	struct closure *cl = &s->cl;
	int i;

	if (!s->unaligned_bvec)
		bio_for_each_segment(bv, s->orig_bio, i)
			bv->bv_offset = 0, bv->bv_len = PAGE_SIZE;

	check = bio_clone(s->orig_bio, GFP_NOIO);
	if (!check)
		return;

	if (bio_alloc_pages(check, GFP_NOIO))
		goto out_put;

	check->bi_rw		= READ_SYNC;
	check->bi_private	= cl;
	check->bi_end_io	= request_endio;

	bio_get(check);
	closure_get(cl);
	closure_bio_submit(check, cl, s->op.d->c->bio_split);
	closure_sync(cl);

	bio_for_each_segment(bv, s->orig_bio, i) {
		void *p1 = kmap(bv->bv_page);
		void *p2 = kmap(check->bi_io_vec[i].bv_page);

		if (memcmp(p1 + bv->bv_offset,
			   p2 + bv->bv_offset,
			   bv->bv_len))
			printk(KERN_ERR "bcache (%s): verify failed"
			       " at sector %llu\n",
			       bdevname(s->op.d->bdev, name),
			       (uint64_t) s->orig_bio->bi_sector);

		kunmap(bv->bv_page);
		kunmap(check->bi_io_vec[i].bv_page);
	}

	__bio_for_each_segment(bv, check, i, 0)
		__free_page(bv->bv_page);
out_put:
	bio_put(check);
}

static void request_read_done(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	/* s->cache_bio != NULL implies that we had a cache miss; cache_bio now
	 * contains data ready to be inserted into the cache.
	 *
	 * First, we copy the data we just read from cache_bio's bounce buffers
	 * to the buffers the original bio pointed to:
	 */

	if (s->cache_bio) {
		struct bio_vec *src, *dst;
		unsigned src_offset, dst_offset, bytes;
		void *dst_ptr;

		bio_reset(s->cache_bio);
		bio_put(s->cache_bio);
		s->cache_bio->bi_sector	= s->cache_miss->bi_sector;
		s->cache_bio->bi_bdev	= s->cache_miss->bi_bdev;
		s->cache_bio->bi_size	= s->cache_bio_sectors << 9;
		bio_map(s->cache_bio, NULL);

		src = bio_iovec(s->cache_bio);
		dst = bio_iovec(s->cache_miss);
		src_offset = src->bv_offset;
		dst_offset = dst->bv_offset;
		dst_ptr = kmap(dst->bv_page);

		while (1) {
			if (dst_offset == dst->bv_offset + dst->bv_len) {
				kunmap(dst->bv_page);
				dst++;
				if (dst == bio_iovec_idx(s->cache_miss,
							 s->cache_miss->bi_vcnt))
					break;

				dst_offset = dst->bv_offset;
				dst_ptr = kmap(dst->bv_page);
			}

			if (src_offset == src->bv_offset + src->bv_len) {
				src++;
				if (src == bio_iovec_idx(s->cache_bio,
							 s->cache_bio->bi_vcnt))
					BUG();

				src_offset = src->bv_offset;
			}

			bytes = min(dst->bv_offset + dst->bv_len - dst_offset,
				    src->bv_offset + src->bv_len - src_offset);

			memcpy(dst_ptr + dst_offset,
			       page_address(src->bv_page) + src_offset,
			       bytes);

			src_offset	+= bytes;
			dst_offset	+= bytes;
		}
	}

	if (verify(s) && s->recoverable)
		do_verify(s);

	__bio_complete(s);

	if (s->cache_bio && !atomic_read(&s->op.d->c->closing)) {
		closure_init(&s->op.cl, &s->cl);
		bio_insert(&s->op.cl);
	}

	return_f(cl, bio_complete, NULL);
}

static void request_read_done_bh(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	if (!s->lookup_done) {
		closure_init(&s->op.cl, &s->cl);
		return_f(&s->op.cl, __request_read, bcache_wq);
	}

	if (s->error)
		set_closure_fn(cl, request_read_error, bcache_wq);
	else if (s->cache_bio || verify(s))
		set_closure_fn(cl, request_read_done, bcache_wq);
	else
		set_closure_fn(cl, bio_complete, NULL);

	closure_queue(cl);
}

static void request_resubmit(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = s->cache_bio ?: s->cache_miss;

	closure_bio_submit(bio, &s->cl, op->d->c->bio_split);
	return_f(cl, NULL, NULL);
}

static void __request_read(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;
	unsigned reada = op->d->readahead;

	int ret = btree_root(search_recurse, op->d->c, op, bio, &reada);

	if (ret == -ENOMEM) {
		closure_put(&s->cl);
		return_f(cl, NULL, NULL);
	}

	if (ret == -EAGAIN)
		return_f(cl, __request_read, bcache_wq);

	s->lookup_done = true;

	if (!op->cache_hit) {
		if (s->cache_miss)
			generic_make_request(s->cache_miss);
		s->cache_miss = bio;
	} else
		reada = 0;

	atomic_inc(&op->d->stats.stats[s->skip][s->cache_miss != NULL]);
#ifdef CONFIG_CGROUP_BCACHE
	atomic_inc(&bio_to_cgroup(s->orig_bio)->
		   stats[s->skip][s->cache_miss != NULL]);
#endif

	if (s->cache_miss) {
		if (!s->skip)
			setup_cache_miss(s, reada);

		trace_bcache_cache_miss(s->orig_bio);

		bio = s->cache_bio ?: s->cache_miss;
		if (closure_bio_submit(bio, &s->cl, op->d->c->bio_split))
			return_f(cl, request_resubmit, bcache_wq);
	}

	return_f(cl, NULL, NULL);
}

static void request_read(struct search *s)
{
	set_closure_fn(&s->cl, request_read_done_bh, NULL);
	s->op.insert_type	= INSERT_READ;

	__request_read(&s->op.cl);
}

/* Process writes */

static bool should_writeback(struct search *s)
{
	return cache_mode(s) == CACHE_MODE_WRITEBACK &&
		s->op.d->c->gc_stats.in_use < (s->orig_bio->bi_rw & REQ_SYNC)
		? CUTOFF_WRITEBACK_SYNC
		: CUTOFF_WRITEBACK;
}

static void request_invalidate_resubmit(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;

	closure_bio_submit(bio, &s->cl, op->d->c->bio_split);
	return_f(cl, bcache_journal, bcache_wq);
}

static void request_write_resubmit(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;

	closure_bio_submit(bio, &s->cl, op->d->c->bio_split);
	bio_insert(&s->op.cl);
}

static void request_write(struct search *s)
{
	struct bio *bio = &s->bio.bio;

	set_closure_fn(&s->cl, bio_complete, NULL);
	s->op.insert_type = INSERT_WRITE;

	down_read_non_owner(&s->op.d->writeback_lock);

	if (bcache_in_writeback(s->op.d, bio->bi_sector, bio_sectors(bio))) {
		s->skip = false;
		s->op.insert_type = INSERT_WRITEBACK;
	}

	if (s->skip) {
skip:		s->cache_bio = s->orig_bio;
		bio_get(s->cache_bio);

		bio_invalidate(s);

		if ((bio->bi_rw & (1 << BIO_RW_DISCARD)) &&
		    !blk_queue_discard(bdev_get_queue(s->op.d->bdev)))
			bio_endio(bio, 0);
		else {
			trace_bcache_write_skip(s->orig_bio);
			if (closure_bio_submit(bio, &s->cl,
					       s->op.d->c->bio_split))
				return_f(&s->op.cl,
					 request_invalidate_resubmit,
					 bcache_wq);
		}

		closure_put(&s->op.cl);
		return;
	}

	if (should_writeback(s))
		s->op.insert_type = INSERT_WRITEBACK;

	if (s->op.insert_type == INSERT_WRITE) {
		s->cache_bio = bbio_kmalloc(GFP_NOIO, bio->bi_max_vecs);
		if (!s->cache_bio) {
			s->skip = true;
			goto skip;
		}

		__bio_clone(s->cache_bio, bio);
		trace_bcache_writethrough(s->orig_bio);
		if (closure_bio_submit(bio, &s->cl, s->op.d->c->bio_split))
			return_f(&s->op.cl, request_write_resubmit, bcache_wq);
	} else {
		trace_bcache_writeback(s->orig_bio);
		s->cache_bio = bio;
		closure_put(&s->cl);
	}

	bio_insert(&s->op.cl);
}

/* Split bios in passthrough mode */

static void bio_passthrough_done(struct closure *cl)
{
	struct bio_passthrough *s = container_of(cl, struct bio_passthrough,
						 cl);

	s->bio->bi_end_io	= s->bi_end_io;
	s->bio->bi_private	= s->bi_private;
	bio_endio(s->bio, 0);

	closure_del(&s->cl);
	mempool_free(s, s->d->bio_passthrough);
}

static void bio_passthrough_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct bio_passthrough *s = container_of(cl, struct bio_passthrough,
						 cl);

	if (error)
		clear_bit(BIO_UPTODATE, &s->bio->bi_flags);

	bio_put(bio);
	closure_put(cl);
}

static void bio_passthrough_submit(struct closure *cl)
{
	struct bio_passthrough *s = container_of(cl, struct bio_passthrough,
						 cl);
	struct bio *bio = s->bio, *n;

	set_closure_fn(&s->cl, bio_passthrough_done, NULL);

	do {
		n = bio_split_get(bio, bio_max_sectors(bio), s->d);
		if (!n)
			return_f(&s->cl, bio_passthrough_submit, bcache_wq);

		trace_bcache_passthrough(n);
		generic_make_request(n);
	} while (n != bio);
}

static void bio_passthrough(struct cached_dev *d, struct bio *bio)
{
	struct bio_passthrough *s;

	if (bio->bi_rw & (1 << BIO_RW_DISCARD)) {
		if (!blk_queue_discard(bdev_get_queue(d->bdev)))
			bio_endio(bio, 0);
		else
			generic_make_request(bio);

		return;
	}

	if (bio_max_sectors(bio) << 9 >= bio->bi_size) {
		generic_make_request(bio);
		return;
	}

	s = mempool_alloc(d->bio_passthrough, GFP_NOIO);

	closure_init(&s->cl, NULL);
	s->d		= d;
	s->bio		= bio;
	s->bi_end_io	= bio->bi_end_io;
	s->bi_private	= bio->bi_private;

	bio_get(bio);
	bio->bi_end_io	= bio_passthrough_endio;
	bio->bi_private	= &s->cl;

	bio_passthrough_submit(&s->cl);
}

/* The entry point */

int bcache_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct cached_dev *d = bio->bi_bdev->bd_disk->private_data;

	bio->bi_bdev = d->bdev;
	bio->bi_sector += 16;

	if (!bio_has_data(bio))
		generic_make_request(bio);
	else if (!cached_dev_get(d))
		bio_passthrough(d, bio);
	else {
		s = do_bio_hook(bio, d);
		trace_bcache_request_start(&s->op, bio);
		check_should_skip(s);

		(bio->bi_rw & REQ_WRITE ? request_write : request_read)(s);
	}
	return 0;
}

void bcache_request_exit(void)
{
#ifdef CONFIG_CGROUP_BCACHE
	cgroup_unload_subsys(&bcache_subsys);
#endif
	if (passthrough_cache)
		kmem_cache_destroy(passthrough_cache);
	if (search_cache)
		kmem_cache_destroy(search_cache);
}

int __init bcache_request_init(void)
{
	if (!(search_cache = KMEM_CACHE(search, 0)) ||
	    !(passthrough_cache = KMEM_CACHE(bio_passthrough, 0)))
		goto err;

#ifdef CONFIG_CGROUP_BCACHE
	cgroup_load_subsys(&bcache_subsys);
	init_bcache_cgroup(&bcache_default_cgroup);
#endif
	return 0;
err:
	bcache_request_exit();
	return -ENOMEM;
}
