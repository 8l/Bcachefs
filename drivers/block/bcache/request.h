#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct task_struct	*task;

	struct bio		*orig_bio;
	struct bio		*cache_bio;
	unsigned		cache_bio_sectors;
	struct bbio		bio;

	struct btree_op		op;

	unsigned		skip:1;
	unsigned		bio_done:1;
	unsigned		lookup_done:1;
	unsigned		recoverable:1;
	unsigned		allocated_vec:1;

	/* IO error returned to s->bio */
	short			error;
};

#endif /* _BCACHE_REQUEST_H_ */
