
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

struct kmem_cache *bch_passthrough_cache;
struct kmem_cache *bch_search_cache;

static void check_should_skip(struct cached_dev *, struct search *);

static const char *search_type(struct search *s)
{
	return s->writeback ? "writeback"
		: s->write ? "write" : "read";
}

/* Cgroup interface */

#ifdef CONFIG_CGROUP_BCACHE
static struct bch_cgroup bcache_default_cgroup = { .cache_mode = -1 };

struct bch_cgroup *cgroup_to_bcache(struct cgroup *cgroup)
{
	struct cgroup_subsys_state *css;
	return cgroup &&
		(css = cgroup_subsys_state(cgroup, bcache_subsys_id))
		? container_of(css, struct bch_cgroup, css)
		: &bcache_default_cgroup;
}

struct bch_cgroup *bio_to_cgroup(struct bio *bio)
{
	return cgroup_to_bcache(get_bio_cgroup(bio));
}

static ssize_t cache_mode_read(struct cgroup *cgrp, struct cftype *cft,
			struct file *file,
			char __user *buf, size_t nbytes, loff_t *ppos)
{
	char tmp[1024];
	int len = snprint_string_list(tmp, PAGE_SIZE, bch_cache_modes,
				      cgroup_to_bcache(cgrp)->cache_mode + 1);

	if (len < 0)
		return len;

	return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
}

static int cache_mode_write(struct cgroup *cgrp, struct cftype *cft,
			    const char *buf)
{
	int v = read_string_list(buf, bch_cache_modes);
	if (v < 0)
		return v;

	cgroup_to_bcache(cgrp)->cache_mode = v - 1;
	return 0;
}

static u64 bch_verify_read(struct cgroup *cgrp, struct cftype *cft)
{
	return cgroup_to_bcache(cgrp)->verify;
}

static int bch_verify_write(struct cgroup *cgrp, struct cftype *cft, u64 val)
{
	cgroup_to_bcache(cgrp)->verify = val;
	return 0;
}

static u64 bch_cache_hits_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct bch_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->stats.cache_hits);
}

static u64 bch_cache_misses_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct bch_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->stats.cache_misses);
}

static u64 bch_cache_bypass_hits_read(struct cgroup *cgrp,
					 struct cftype *cft)
{
	struct bch_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->stats.cache_bypass_hits);
}

static u64 bch_cache_bypass_misses_read(struct cgroup *cgrp,
					   struct cftype *cft)
{
	struct bch_cgroup *bcachecg = cgroup_to_bcache(cgrp);
	return atomic_read(&bcachecg->stats.cache_bypass_misses);
}

struct cftype bch_files[] = {
	{
		.name		= "cache_mode",
		.read		= cache_mode_read,
		.write_string	= cache_mode_write,
	},
	{
		.name		= "verify",
		.read_u64	= bch_verify_read,
		.write_u64	= bch_verify_write,
	},
	{
		.name		= "cache_hits",
		.read_u64	= bch_cache_hits_read,
	},
	{
		.name		= "cache_misses",
		.read_u64	= bch_cache_misses_read,
	},
	{
		.name		= "cache_bypass_hits",
		.read_u64	= bch_cache_bypass_hits_read,
	},
	{
		.name		= "cache_bypass_misses",
		.read_u64	= bch_cache_bypass_misses_read,
	},
};

static void init_bch_cgroup(struct bch_cgroup *cg)
{
	cg->cache_mode = -1;
}

static struct cgroup_subsys_state *bcachecg_create(struct cgroup *cgroup)
{
	struct bch_cgroup *cg;

	cg = kzalloc(sizeof(*cg), GFP_KERNEL);
	if (!cg)
		return ERR_PTR(-ENOMEM);
	init_bch_cgroup(cg);
	return &cg->css;
}

static void bcachecg_destroy(struct cgroup *cgroup)
{
	struct bch_cgroup *cg = cgroup_to_bcache(cgroup);
	free_css_id(&bcache_subsys, &cg->css);
	kfree(cg);
}

static int bcachecg_populate(struct cgroup_subsys *subsys,
			     struct cgroup *cgroup)
{
	return cgroup_add_files(cgroup, subsys, bch_files,
				ARRAY_SIZE(bch_files));
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

static unsigned cache_mode(struct cached_dev *d, struct bio *bio)
{
#ifdef CONFIG_CGROUP_BCACHE
	int r = bio_to_cgroup(bio)->cache_mode;
	if (r >= 0)
		return r;
#endif
	return BDEV_CACHE_MODE(&d->sb);
}

static bool verify(struct cached_dev *d, struct bio *bio)
{
#ifdef CONFIG_CGROUP_BCACHE
	if (bio_to_cgroup(bio)->verify)
		return true;
#endif
	return d->verify;
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

static void bio_invalidate(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct bio *bio = op->cache_bio;

	pr_debug("invalidating %i sectors from %llu",
		 bio_sectors(bio), (uint64_t) bio->bi_sector);

	while (bio_sectors(bio)) {
		unsigned len = min(bio_sectors(bio), 1U << 14);

		if (bch_keylist_realloc(&op->keys, 0, op->c))
			goto out;

		bio->bi_sector	+= len;
		bio->bi_size	-= len << 9;

		bch_keylist_add(&op->keys, &KEY(op->inode, bio->bi_sector, len));
	}

	op->bio_insert_done = true;
out:
	continue_at(cl, bch_journal, bcache_wq);
}

struct open_bucket {
	struct list_head	list;
	struct task_struct	*last;
	unsigned		sectors_free;
	BKEY_PADDED(key);
};

void bch_open_buckets_free(struct cache_set *c)
{
	struct open_bucket *b;

	while (!list_empty(&c->data_buckets)) {
		b = list_first_entry(&c->data_buckets,
				     struct open_bucket, list);
		list_del(&b->list);
		kfree(b);
	}
}

int bch_open_buckets_alloc(struct cache_set *c)
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

/**
 * get_data_bucket - pick out a bucket to write some data to, possibly
 * allocating a new one.
 *
 * @search: Device/offset (backing device) the IO is for
 * @s: Big state struct
 *
 * We keep multiple buckets open for writes, and try to segregate different
 * write streams for better cache utilization: first we look for a bucket where
 * the last write to it was sequential with the current write, and failing that
 * we look for a bucket that was last used by the same task.
 *
 * The ideas is if you've got multiple tasks pulling data into the cache at the
 * same time, you'll get better cache utilization if you try to segregate their
 * data and preserve locality.
 *
 * For example, say you've starting Firefox at the same time you're copying a
 * bunch of files. Firefox will likely end up being fairly hot and stay in the
 * cache awhile, but the data you copied might not be; if you wrote all that
 * data to the same buckets it'd get invalidated at the same time.
 *
 * Both of those tasks will be doing fairly random IO so we can't rely on
 * detecting sequential IO to segregate their data, but going off of the task
 * should be a sane heuristic.
 */
static struct open_bucket *get_data_bucket(struct bkey *search,
					   struct search *s)
{
	struct closure cl, *w = NULL;
	struct cache_set *c = s->op.c;
	struct open_bucket *l, *ret, *ret_task;
	BKEY_PADDED(key) alloc;
	struct bkey *k = NULL;

	if (s->writeback) {
		closure_init_stack(&cl);
		w = &cl;
	}
	/*
	 * We might have to allocate a new bucket, which we can't do with a
	 * spinlock held. So if we have to allocate, we drop the lock, allocate
	 * and then retry.
	 */
again:
	ret = ret_task = NULL;

	spin_lock(&c->data_bucket_lock);
	list_for_each_entry_reverse(l, &c->data_buckets, list) {
		if (!bkey_cmp(&l->key, search)) {
			ret = l;
			goto found;
		} else if (l->last == s->task) {
			ret_task = l;
		}
	}

	ret = ret_task ?: list_first_entry(&c->data_buckets,
					   struct open_bucket, list);
found:
	if (!ret->sectors_free) {
		if (!k) {
			spin_unlock(&c->data_bucket_lock);
			k = &alloc.key;

			/*
			 * We don't segregate buckets for dirty and clean data -
			 * so when we allocate it always mark it reclaimable
			 * first, and then mark it dirty down below the first
			 * time we use it for dirty data
			 */

			if (bch_pop_bucket_set(c, GC_MARK_RECLAIMABLE,
					       s->op.write_prio,
					       k, 1, w))
				return NULL;

			goto again;
		}

		bkey_copy(&ret->key, k);
		k = NULL;

		ret->sectors_free = c->sb.bucket_size;
	} else {
		for (unsigned i = 0; i < KEY_PTRS(&ret->key); i++)
			EBUG_ON(ptr_stale(c, &ret->key, i));
	}

	/*
	 * If we had to allocate and then retry, we might discover that we raced
	 * and no longer need to allocate. Therefore, if we allocated a bucket
	 * but didn't use it, drop the refcount pop_bucket_set() took:
	 */
	if (k)
		__bkey_put(c, k);

	if (w)
		for (unsigned i = 0; i < KEY_PTRS(&ret->key); i++)
			SET_GC_MARK(PTR_BUCKET(c, &ret->key, i), GC_MARK_DIRTY);

	ret->last = s->task;
	bkey_copy_key(&ret->key, search);

	/* @ret is hot now, put it at the end of the queue */
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

	bch_journal(cl);
}

static void bio_insert_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);

	if (error) {
		/* TODO: We could try to recover from this. */
		if (s->writeback)
			s->error = error;
		else if (s->write)
			set_closure_fn(cl, bio_insert_error, bcache_wq);
		else
			set_closure_fn(cl, NULL, NULL);
	}

	bch_bbio_endio(op->c, bio, error, "writing data to cache");
}

static void bio_insert_loop(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = op->cache_bio, *n;
	unsigned sectors = bio_sectors(bio);

	if (op->skip)
		return bio_invalidate(cl);

	if (atomic_sub_return(bio_sectors(bio), &op->c->sectors_to_gc) < 0) {
		set_gc_sectors(op->c);
		bch_queue_gc(op->c);
	}

	do {
		struct open_bucket *b;
		struct bkey *k;
		struct bio_set *split = s->d
			? s->d->bio_split : op->c->bio_split;

		/* 1 for the device pointer and 1 for the chksum */
		if (bch_keylist_realloc(&op->keys,
					1 + (op->csum ? 1 : 0),
					op->c))
			continue_at(cl, bch_journal, bcache_wq);

		k = op->keys.top;

		b = get_data_bucket(&KEY(op->inode, bio->bi_sector, 0), s);
		if (!b)
			goto err;

		put_data_bucket(b, op->c, k, bio);

		n = __bch_bio_split_get(bio, KEY_SIZE(k), split);
		if (!n) {
			__bkey_put(op->c, k);
			continue_at(cl, bio_insert_loop, bcache_wq);
		}

		if (s->writeback)
			SET_KEY_DIRTY(k, true);

		SET_KEY_CSUM(k, op->csum);
		if (KEY_CSUM(k))
			bio_csum(n, k);

		pr_debug("%s", pkey(k));
		bch_keylist_push(&op->keys);

		n->bi_rw |= REQ_WRITE;

		if (n == bio)
			closure_get(cl);

		trace_bcache_cache_insert(n, n->bi_sector, n->bi_bdev);
		bch_submit_bbio(n, op->c, k, 0);
	} while (n != bio);

	op->bio_insert_done = true;
	continue_at(cl, bch_journal, bcache_wq);
err:
	/* IO never happened, so bbio key isn't set up, so we can't call
	 * bio_endio()
	 */
	bio_put(bio);

	pr_debug("error for %s, %i/%i sectors done, bi_sector %llu",
		 search_type(s), sectors - bio_sectors(bio), sectors,
		 (uint64_t) bio->bi_sector);

	if (s->writeback) {
		/* This is dead code now, since we handle all memory allocation
		 * failures and block if we don't have free buckets
		 */
		BUG();
		/* Lookup in in_writeback rb tree, wait on appropriate
		 * closure, then invalidate in btree and do normal
		 * write
		 */
		op->bio_insert_done	= true;
		s->error		= -ENOMEM;
	} else if (s->write) {
		op->skip		= true;
		return bio_invalidate(cl);
	} else
		op->bio_insert_done	= true;

	if (!bch_keylist_empty(&op->keys))
		continue_at(cl, bch_journal, bcache_wq);
	else
		closure_return(cl);
}

static void bio_insert(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);

	if (!op->skip) {
		struct bio *bio = op->cache_bio;

		bio->bi_end_io	= bio_insert_endio;
		bio->bi_private = cl;
		bio_get(bio);
	}

	bch_keylist_init(&op->keys);
	bio_insert_loop(cl);
}

void bch_btree_insert_async(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);
	struct search *s = container_of(op, struct search, op);

	if (bch_btree_insert(op, op->c)) {
		s->error		= -ENOMEM;
		op->bio_insert_done	= true;
	}

	if (op->bio_insert_done) {
		bch_keylist_free(&op->keys);
		closure_return(cl);
	} else
		continue_at(cl, bio_insert_loop, bcache_wq);
}

/* Common code for the make_request functions */

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

void bch_cache_read_endio(struct bio *bio, int error)
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
	else if (ptr_stale(s->op.c, &b->key, 0)) {
		atomic_long_inc(&s->op.c->cache_read_races);
		s->error = -EINTR;
	}

	bch_bbio_endio(s->op.c, bio, error, "reading from cache");
}

static void bio_complete(struct search *s)
{
	if (s->orig_bio) {
		if (s->error)
			clear_bit(BIO_UPTODATE, &s->orig_bio->bi_flags);

		trace_bcache_request_end(s, s->orig_bio);
		bio_endio(s->orig_bio, s->error);
		s->orig_bio = NULL;
	}
}

static void do_bio_hook(struct search *s)
{
	struct bio *bio = &s->bio.bio;
	memcpy(bio, s->orig_bio, sizeof(struct bio));

	bio->bi_end_io		= request_endio;
	bio->bi_private		= &s->cl;
	bio->bi_destructor	= NULL;
	atomic_set(&bio->bi_cnt, 3);
}

static void search_free(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	bio_complete(s);

	if (s->op.cache_bio)
		bio_put(s->op.cache_bio);

	if (s->unaligned_bvec)
		mempool_free(s->bio.bio.bi_io_vec, s->d->unaligned_bvec);

	closure_debug_destroy(cl);
	mempool_free(s, s->d->c->search);
}

static struct search *search_alloc(struct bio *bio, struct bcache_device *d)
{
	struct bio_vec *bv;
	struct search *s = mempool_alloc(d->c->search, GFP_NOIO);
	memset(s, 0, offsetof(struct search, op.keys));

	__closure_init(&s->cl, NULL);

	s->op.inode		= d->id;
	s->op.c			= d->c;
	s->d			= d;
	s->op.lock		= -1;
	s->task			= current;
	s->orig_bio		= bio;
	s->write		= (bio->bi_rw & REQ_WRITE) != 0;
	s->op.flush_journal	= (bio->bi_rw & REQ_FLUSH) != 0;
	s->recoverable		= 1;
	do_bio_hook(s);

	if (bio->bi_size != bio_segments(bio) * PAGE_SIZE) {
		bv = mempool_alloc(d->unaligned_bvec, GFP_NOIO);
		memcpy(bv, bio_iovec(bio),
		       sizeof(struct bio_vec) * bio_segments(bio));

		s->bio.bio.bi_io_vec	= bv;
		s->unaligned_bvec	= 1;
	}

	return s;
}

static void btree_read_async(struct closure *cl)
{
	struct btree_op *op = container_of(cl, struct btree_op, cl);

	int ret = btree_root(search_recurse, op->c, op);

	if (ret == -EAGAIN)
		continue_at(cl, btree_read_async, bcache_wq);

	closure_return(cl);
}

/* Cached devices */

static void cached_dev_bio_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	search_free(cl);
	cached_dev_put(dc);
}

/* Process reads */

static void cached_dev_read_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);

	if (s->cache_miss)
		bio_put(s->cache_miss);

	if (s->op.cache_bio) {
		int i;
		struct bio_vec *bv;

		__bio_for_each_segment(bv, s->op.cache_bio, i, 0)
			__free_page(bv->bv_page);
	}

	cached_dev_bio_complete(cl);
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
		do_bio_hook(s);
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

		trace_bcache_read_retry(&s->bio.bio);
		closure_bio_submit(&s->bio.bio, &s->cl, s->op.c->bio_split);
	}

	continue_at(cl, cached_dev_read_complete, NULL);
}

static void request_read_done(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *d = container_of(s->d, struct cached_dev, disk);

	/*
	 * s->cache_bio != NULL implies that we had a cache miss; cache_bio now
	 * contains data ready to be inserted into the cache.
	 *
	 * First, we copy the data we just read from cache_bio's bounce buffers
	 * to the buffers the original bio pointed to:
	 */

	if (s->op.cache_bio) {
		struct bio_vec *src, *dst;
		unsigned src_offset, dst_offset, bytes;
		void *dst_ptr;

		bio_reset(s->op.cache_bio);
		atomic_set(&s->op.cache_bio->bi_cnt, 1);
		s->op.cache_bio->bi_sector	= s->cache_miss->bi_sector;
		s->op.cache_bio->bi_bdev	= s->cache_miss->bi_bdev;
		s->op.cache_bio->bi_size	= s->cache_bio_sectors << 9;
		bio_map(s->op.cache_bio, NULL);

		src = bio_iovec(s->op.cache_bio);
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
				if (src == bio_iovec_idx(s->op.cache_bio,
							 s->op.cache_bio->bi_vcnt))
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

	if (verify(d, &s->bio.bio) && s->recoverable)
		bch_data_verify(s);

	bio_complete(s);

	if (s->op.cache_bio && !atomic_read(&s->op.c->closing)) {
		s->op.type = BTREE_REPLACE;
		closure_init(&s->op.cl, &s->cl);
		bio_insert(&s->op.cl);
	}

	continue_at(cl, cached_dev_read_complete, NULL);
}

static void request_read_done_bh(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *d = container_of(s->d, struct cached_dev, disk);

	if (s->cache_miss && s->op.insert_collision)
		bch_mark_cache_miss_collision(s);

	bch_mark_cache_accounting(s, !s->cache_miss, s->op.skip);

	if (s->error)
		set_closure_fn(cl, request_read_error, bcache_wq);
	else if (s->op.cache_bio || verify(d, &s->bio.bio))
		set_closure_fn(cl, request_read_done, bcache_wq);
	else
		set_closure_fn(cl, cached_dev_read_complete, NULL);

	closure_queue(cl);
}

static int cached_dev_cache_miss(struct btree *b, struct search *s,
				 struct bio *bio, unsigned sectors)
{
	int ret = 0;
	unsigned reada;
	struct cached_dev *d = container_of(s->d, struct cached_dev, disk);
	struct bio *n;

	sectors = min(sectors, bio_max_sectors(bio)),

	n = bch_bio_split_get(bio, sectors, s->d);
	if (!n)
		return -EAGAIN;

	if (n == bio)
		s->op.lookup_done = true;

	if (s->cache_miss || s->op.skip)
		goto out_submit;

	if (n != bio ||
	    (bio->bi_rw & REQ_RAHEAD) ||
	    (bio->bi_rw & REQ_META) ||
	    s->op.c->gc_stats.in_use >= CUTOFF_CACHE_READA)
		reada = 0;
	else
		reada = min(d->readahead >> 9, sectors - bio_sectors(n));

	s->cache_bio_sectors = bio_sectors(n) + reada;
	s->op.cache_bio = bch_bbio_kmalloc(GFP_NOIO,
			DIV_ROUND_UP(s->cache_bio_sectors, PAGE_SECTORS));

	if (!s->op.cache_bio)
		goto out_submit;

	s->op.cache_bio->bi_sector	= n->bi_sector;
	s->op.cache_bio->bi_bdev	= n->bi_bdev;
	s->op.cache_bio->bi_size	= s->cache_bio_sectors << 9;

	s->op.cache_bio->bi_end_io	= request_endio;
	s->op.cache_bio->bi_private	= &s->cl;

	/* btree_search_recurse()'s btree iterator is no good anymore */
	ret = -EINTR;
	if (!bch_btree_insert_check_key(b, &s->op, s->op.cache_bio))
		goto out_put;

	bio_map(s->op.cache_bio, NULL);
	if (bio_alloc_pages(s->op.cache_bio, __GFP_NOWARN|GFP_NOIO))
		goto out_put;

	s->cache_miss = n;
	bio_get(s->op.cache_bio);

	trace_bcache_cache_miss(s->orig_bio);
	generic_make_request(s->op.cache_bio);

	return ret;
out_put:
	bio_put(s->op.cache_bio);
	s->op.cache_bio = NULL;
out_submit:
	generic_make_request(n);
	return ret;
}

static void request_read(struct cached_dev *d, struct search *s)
{
	struct closure *cl = &s->cl;

	/*
	 * For the read we're going to issue - should figure out a better way to
	 * do this
	 */
	closure_get(cl);

	check_should_skip(d, s);

	__closure_init(&s->op.cl, cl);
	btree_read_async(&s->op.cl);

	continue_at(cl, request_read_done_bh, NULL);
}

/* Process writes */

static void cached_dev_write_complete(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct cached_dev *dc = container_of(s->d, struct cached_dev, disk);

	up_read_non_owner(&dc->writeback_lock);
	cached_dev_bio_complete(cl);
}

static bool should_writeback(struct cached_dev *d, struct bio *bio)
{
	unsigned threshold = (bio->bi_rw & REQ_SYNC)
		? CUTOFF_WRITEBACK_SYNC
		: CUTOFF_WRITEBACK;

	return !atomic_read(&d->disk.detaching) &&
		cache_mode(d, bio) == CACHE_MODE_WRITEBACK &&
		d->disk.c->gc_stats.in_use < threshold;
}

static void request_write_resubmit(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, cl);
	struct bio *bio = &s->bio.bio;

	closure_bio_submit(bio, cl, s->op.c->bio_split);

	__closure_init(&s->op.cl, cl);
	bio_insert(&s->op.cl);
	continue_at(cl, cached_dev_write_complete, NULL);
}

static void request_write(struct cached_dev *d, struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;
	struct bkey start, end;
	start = KEY(dc->disk.id, bio->bi_sector, 0);
	end = KEY(dc->disk.id, bio_end(bio), 0);

	check_should_skip(d, s);
	down_read_non_owner(&d->writeback_lock);

	if (bch_keybuf_check_overlapping(&dc->writeback_keys, &start, &end)) {
		s->op.skip	= false;
		s->writeback	= true;
	}

	if (bio->bi_rw & (1 << BIO_RW_DISCARD)) {
		s->op.skip	= true;
		s->op.cache_bio	= s->orig_bio;
		bio_get(s->op.cache_bio);

		if (blk_queue_discard(bdev_get_queue(d->bdev))) {
			closure_get(cl);
			generic_make_request(bio);
		}

		goto out;
	}

	if (s->op.skip) {
skip:		s->op.cache_bio = s->orig_bio;
		bio_get(s->op.cache_bio);
		trace_bcache_write_skip(s->orig_bio);

		goto submit;
	}

	if (should_writeback(d, s->orig_bio))
		s->writeback = true;

	if (!s->writeback) {
		s->op.cache_bio = bch_bbio_kmalloc(GFP_NOIO, bio->bi_max_vecs);
		if (!s->op.cache_bio) {
			s->op.skip = true;
			goto skip;
		}

		__bio_clone(s->op.cache_bio, bio);
		trace_bcache_writethrough(s->orig_bio);
submit:
		if (closure_bio_submit(bio, cl, s->op.c->bio_split))
			continue_at(cl, request_write_resubmit, bcache_wq);
	} else {
		s->op.cache_bio = bio;
		trace_bcache_writeback(s->orig_bio);
		bch_writeback_add(d, bio_sectors(bio));
	}
out:
	__closure_init(&s->op.cl, cl);
	bio_insert(&s->op.cl);
	continue_at(cl, cached_dev_write_complete, NULL);
}

static void request_nodata(struct cached_dev *d, struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;

	if (bio->bi_rw & (1 << BIO_RW_DISCARD)) {
		request_write(d, s);
		return;
	}

	if (s->op.flush_journal)
		bch_journal_meta(s->op.c, cl);

	closure_get(cl);
	generic_make_request(bio);

	continue_at(cl, cached_dev_bio_complete, NULL);
}

/* Split bios in passthrough mode */

static void bio_passthrough_done(struct closure *cl)
{
	struct bio_passthrough *s = container_of(cl, struct bio_passthrough,
						 cl);

	s->bio->bi_end_io	= s->bi_end_io;
	s->bio->bi_private	= s->bi_private;
	bio_endio(s->bio, 0);

	closure_debug_destroy(&s->cl);
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

	do {
		n = bch_bio_split_get(bio, bio_max_sectors(bio), &s->d->disk);
		if (!n)
			continue_at(cl, bio_passthrough_submit, bcache_wq);

		if (n == bio) {
			set_closure_fn(cl, bio_passthrough_done, NULL);
			closure_set_stopped(cl);
		}

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

	if (!bio_has_data(bio) ||
	    bio->bi_size <= bio_max_sectors(bio) << 9) {
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

/* Cached devices - read & write stuff */

int bch_get_congested(struct cache_set *c)
{
	int i;

	if (!c->congested_read_threshold_us &&
	    !c->congested_write_threshold_us)
		return 0;

	i = (local_clock_us() - c->congested_last_us) / 1024;
	if (i < 0)
		return 0;

	i += atomic_read(&c->congested);
	if (i >= 0)
		return 0;

	i += CONGESTED_MAX;

	return i <= 0 ? 1 : fract_exp_two(i, 6);
}

static void add_sequential(struct task_struct *t)
{
	ewma_add(t->sequential_io_avg,
		 t->sequential_io, 8, 0);

	t->sequential_io = 0;
}

static void check_should_skip(struct cached_dev *d, struct search *s)
{
	struct hlist_head *iohash(uint64_t k)
	{ return &d->io_hash[hash_64(k, RECENT_IO_BITS)]; }

	struct cache_set *c = s->op.c;
	struct bio *bio = &s->bio.bio;

	long rand;
	int cutoff = bch_get_congested(c);
	unsigned mode = cache_mode(d, bio);

	if (atomic_read(&d->disk.detaching) ||
	    c->gc_stats.in_use > CUTOFF_CACHE_ADD ||
	    (bio->bi_rw & (1 << BIO_RW_DISCARD)))
		goto skip;

	if (mode == CACHE_MODE_NONE ||
	    (mode == CACHE_MODE_WRITEAROUND &&
	     (bio->bi_rw & REQ_WRITE)))
		goto skip;

	if (bio->bi_sector   & (c->sb.block_size - 1) ||
	    bio_sectors(bio) & (c->sb.block_size - 1)) {
		pr_debug("skipping unaligned io");
		goto skip;
	}

	if (!cutoff) {
		cutoff = d->sequential_cutoff >> 9;

		if (!cutoff)
			goto rescale;

		if (mode == CACHE_MODE_WRITEBACK &&
		    (bio->bi_rw & REQ_WRITE) &&
		    (bio->bi_rw & REQ_SYNC))
			goto rescale;
	}

	if (d->sequential_merge) {
		struct hlist_node *cursor;
		struct io *i;

		spin_lock(&d->io_lock);

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

		spin_unlock(&d->io_lock);
	} else {
		s->task->sequential_io = bio->bi_size;

		add_sequential(s->task);
	}

	rand = get_random_int();
	cutoff -= bitmap_weight(&rand, BITS_PER_LONG);

	if (cutoff <= (int) (max(s->task->sequential_io,
				 s->task->sequential_io_avg) >> 9))
		goto skip;

rescale:
	bch_rescale_priorities(c, bio_sectors(bio));
	return;
skip:
	bch_mark_sectors_bypassed(s, bio_sectors(bio));
	s->op.skip = true;
}

static void cached_dev_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct bcache_device *d = bio->bi_bdev->bd_disk->private_data;
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);

	bio->bi_bdev = dc->bdev;
	bio->bi_sector += BDEV_DATA_START;

	if (cached_dev_get(dc)) {
		s = search_alloc(bio, d);
		trace_bcache_request_start(s, bio);

		if (!bio_has_data(bio))
			request_nodata(dc, s);
		else if (bio->bi_rw & REQ_WRITE)
			request_write(dc, s);
		else
			request_read(dc, s);
	} else
		bio_passthrough(dc, bio);
}

static int cached_dev_ioctl(struct bcache_device *d, fmode_t mode,
			    unsigned int cmd, unsigned long arg)
{
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	return __blkdev_driver_ioctl(dc->bdev, mode, cmd, arg);
}

static int cached_dev_congested(void *data, int bits)
{
	struct bcache_device *d = data;
	struct cached_dev *dc = container_of(d, struct cached_dev, disk);
	struct request_queue *q = bdev_get_queue(dc->bdev);
	int ret = 0;

	if (bdi_congested(&q->backing_dev_info, bits))
		return 1;

	if (cached_dev_get(dc)) {
		struct cache *ca;

		for_each_cache(ca, d->c) {
			q = bdev_get_queue(ca->bdev);
			ret |= bdi_congested(&q->backing_dev_info, bits);
		}

		cached_dev_put(dc);
	}

	return ret;
}

void bch_cached_dev_request_init(struct cached_dev *d)
{
	struct gendisk *g = d->disk.disk;

	g->queue->make_request_fn		= cached_dev_make_request;
	g->queue->backing_dev_info.congested_fn = cached_dev_congested;
	d->disk.cache_miss			= cached_dev_cache_miss;
	d->disk.ioctl				= cached_dev_ioctl;
}

/* Flash backed devices */

static int flash_dev_cache_miss(struct btree *b, struct search *s,
				struct bio *bio, unsigned sectors)
{
	sectors = min(sectors, bio_sectors(bio));

	/* Zero fill bio */

	while (sectors) {
		struct bio_vec *bv = bio_iovec(bio);
		unsigned j = min(bv->bv_len >> 9, sectors);

		void *p = kmap(bv->bv_page);
		memset(p + bv->bv_offset, 0, j << 9);
		kunmap(bv->bv_page);

		bv->bv_len	-= j << 9;
		bv->bv_offset	+= j << 9;

		bio->bi_sector	+= j;
		bio->bi_size	-= j << 9;

		bio->bi_idx++;
		sectors		-= j;
	}

	if (sectors >= bio_sectors(bio)) {
		s->op.lookup_done = true;
		bio_endio(bio, 0);
	}
	return 0;
}

static void flash_dev_read(struct search *s)
{
	struct closure *cl = &s->cl;

	/*
	 * For the read we're going to issue - should figure out a better way to
	 * do this
	 */
	closure_get(cl);

	__closure_init(&s->op.cl, cl);
	btree_read_async(&s->op.cl);
}

static void flash_dev_write(struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;

	s->op.skip	= (bio->bi_rw & (1 << BIO_RW_DISCARD)) != 0;
	s->writeback	= true;
	s->op.cache_bio	= bio;

	__closure_init(&s->op.cl, cl);
	bio_insert(&s->op.cl);
}

static void flash_dev_req_nodata(struct search *s)
{
	struct closure *cl = &s->cl;
	struct bio *bio = &s->bio.bio;

	if (bio->bi_rw & (1 << BIO_RW_DISCARD)) {
		flash_dev_write(s);
		return;
	}

	if (s->op.flush_journal)
		bch_journal_meta(s->op.c, cl);
}

static void flash_dev_make_request(struct request_queue *q, struct bio *bio)
{
	struct search *s;
	struct bcache_device *d = bio->bi_bdev->bd_disk->private_data;

	s = search_alloc(bio, d);
	trace_bcache_request_start(s, bio);

	(!bio_has_data(bio)	? flash_dev_req_nodata :
	 bio->bi_rw & REQ_WRITE ? flash_dev_write :
				  flash_dev_read)(s);

	continue_at(&s->cl, search_free, NULL);
}

static int flash_dev_ioctl(struct bcache_device *d, fmode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

static int flash_dev_congested(void *data, int bits)
{
	struct bcache_device *d = data;
	struct request_queue *q;
	struct cache *ca;
	int ret = 0;

	for_each_cache(ca, d->c) {
		q = bdev_get_queue(ca->bdev);
		ret |= bdi_congested(&q->backing_dev_info, bits);
	}

	return ret;
}

void bch_flash_dev_request_init(struct bcache_device *d)
{
	struct gendisk *g = d->disk;

	g->queue->make_request_fn		= flash_dev_make_request;
	g->queue->backing_dev_info.congested_fn = flash_dev_congested;
	d->cache_miss				= flash_dev_cache_miss;
	d->ioctl				= flash_dev_ioctl;
}

void bch_request_exit(void)
{
#ifdef CONFIG_CGROUP_BCACHE
	cgroup_unload_subsys(&bcache_subsys);
#endif
	if (bch_passthrough_cache)
		kmem_cache_destroy(bch_passthrough_cache);
	if (bch_search_cache)
		kmem_cache_destroy(bch_search_cache);
}

int __init bch_request_init(void)
{
	if (!(bch_search_cache = KMEM_CACHE(search, 0)) ||
	    !(bch_passthrough_cache = KMEM_CACHE(bio_passthrough, 0)))
		goto err;

#ifdef CONFIG_CGROUP_BCACHE
	cgroup_load_subsys(&bcache_subsys);
	init_bch_cgroup(&bcache_default_cgroup);
#endif
	return 0;
err:
	bch_request_exit();
	return -ENOMEM;
}
