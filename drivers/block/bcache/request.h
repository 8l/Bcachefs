#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct task_struct	*task;

	struct bbio		bio;
	struct bio		*orig_bio;
	struct bio		*cache_bio;
	struct bio		*cache_miss;
	unsigned		cache_bio_sectors;

	unsigned		skip:1;
	unsigned		bio_done:1;
	unsigned		lookup_done:1;
	unsigned		recoverable:1;
	unsigned		unaligned_bvec:1;

	/* IO error returned to s->bio */
	short			error;

	/* Anything past op->keys won't get zeroed in do_bio_hook */
	struct btree_op		op;
};

void cache_read_endio(struct bio *, int);
int bcache_get_congested(struct cache_set *);
void bcache_btree_insert_async(struct closure *);
int bcache_make_request(struct request_queue *, struct bio *);

void bcache_open_buckets_free(struct cache_set *);
int bcache_open_buckets_alloc(struct cache_set *);

extern struct kmem_cache *search_cache, *passthrough_cache;

#endif /* _BCACHE_REQUEST_H_ */
