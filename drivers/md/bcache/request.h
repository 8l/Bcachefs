#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_
#include <linux/cgroup.h>

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct bcache_device	*d;
	struct task_struct	*task;

	struct bbio		bio;
	struct bio		*orig_bio;
	struct bio		*cache_bio;
	struct bio		*cache_miss;
	unsigned		cache_bio_sectors;

	unsigned		recoverable:1;
	unsigned		unaligned_bvec:1;
	unsigned		skip:1;
	unsigned		write:1;
	unsigned		writeback:1;

	unsigned		bio_insert_done:1;

	/* IO error returned to s->bio */
	short			error;

	/* Anything past op->keys won't get zeroed in do_bio_hook */
	struct btree_op		op;
};

void cache_read_endio(struct bio *, int);
int bcache_get_congested(struct cache_set *);
void bcache_btree_insert_async(struct closure *);

void bcache_open_buckets_free(struct cache_set *);
int bcache_open_buckets_alloc(struct cache_set *);

void cached_dev_request_init(struct cached_dev *d);
void flash_dev_request_init(struct bcache_device *d);

extern struct kmem_cache *search_cache, *passthrough_cache;

struct bcache_cgroup {
#ifdef CONFIG_CGROUP_BCACHE
	struct cgroup_subsys_state	css;
#endif
	/*
	 * We subtract one from the index into bcache_cache_modes[], so that
	 * default == -1; this makes it so the rest match up with d->cache_mode,
	 * and we use d->cache_mode if cgrp->cache_mode < 0
	 */
	short				cache_mode;
	bool				verify;
	struct cache_stat_collector	stats;
};

#endif /* _BCACHE_REQUEST_H_ */
