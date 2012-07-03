#ifndef BLK_MQ_H
#define BLK_MQ_H

#include <linux/blkdev.h>

struct blk_mq_ctx {
	spinlock_t		lock;

	struct list_head	rq_list;

	unsigned int		index;
	unsigned int		ipi_redirect;

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];
	unsigned long		rq_merged;

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];

	struct kobject		kobj;
};

struct blk_mq_hw_ctx {
	spinlock_t		__lock;
	spinlock_t		*lock;

	struct llist_head	dispatch;
	struct delayed_work	delayed_work;

	unsigned long		flags;

	struct request_queue	*queue;

	unsigned int		nr_ctx;
	struct blk_mq_ctx	**ctxs;
	unsigned int 		nr_ctx_map;
	unsigned long		*ctx_map;

	struct request		*rqs;
	unsigned long		*rq_map;
	wait_queue_head_t	rq_wait;

	unsigned long		queued;
	unsigned long		run;
#define BLK_MQ_MAX_DISPATCH_ORDER	10
	unsigned long		dispatched[BLK_MQ_MAX_DISPATCH_ORDER];

	unsigned int		queue_depth;
	unsigned int		numa_node;

	struct kobject		kobj;
};

typedef int (queue_rq_fn) (struct blk_mq_hw_ctx *, struct request *);
typedef struct blk_mq_hw_ctx *(map_queue_fn) (struct request_queue *, struct blk_mq_ctx *);

struct blk_mq_ops {
	queue_rq_fn		*queue_rq;
	map_queue_fn		*map_queue;
	rq_timed_out_fn		*timeout;
};

enum {
	BLK_MQ_RQ_QUEUE_OK	= 0,	/* queued fine */
	BLK_MQ_RQ_QUEUE_BUSY	= 1,	/* requeue IO for later */
	BLK_MQ_RQ_QUEUE_ERROR	= 2,	/* end IO with error */

	BLK_MQ_F_SHOULD_MERGE	= 1 << 0,
	BLK_MQ_F_SHOULD_SORT	= 1 << 1,
	BLK_MQ_F_SHOULD_IPI	= 1 << 2,
	BLK_MQ_F_SHOULD_LOCK	= 1 << 3, /* lock on queue_rq invocation */

	BLK_MQ_MAX_DEPTH	= 256,
};

struct blk_mq_reg {
	struct blk_mq_ops	*ops;
	unsigned int		nr_hw_queues;
	unsigned int		queue_depth;
	int			numa_node;
	unsigned int		timeout;
	unsigned int		flags;		/* BLK_MQ_F_* */
};

struct request_queue *blk_mq_init_queue(struct blk_mq_reg *, spinlock_t *);
void blk_mq_free_queue(struct request_queue *);
int blk_mq_register_disk(struct gendisk *);
void blk_mq_unregister_disk(struct gendisk *);

void blk_mq_flush_plug(struct request_queue *, bool);
void blk_mq_insert_request(struct request_queue *, struct request *);
void blk_mq_insert_requests(struct request_queue *, struct list_head *);
void blk_mq_run_queues(struct request_queue *q, bool async);
struct request *blk_mq_alloc_request(struct request_queue *q, int rw, gfp_t gfp);

struct blk_mq_hw_ctx *blk_mq_map_single_queue(struct request_queue *q, struct blk_mq_ctx *);

void blk_mq_end_io(struct blk_mq_hw_ctx *hctx, struct request *rq, int error);

#define queue_for_each_hw_ctx(q, hctx, i)				\
	for ((i) = 0, hctx = &(q)->queue_hw_ctx[0];			\
	     (i) < (q)->nr_hw_queues; (i)++, hctx++)

#define queue_for_each_ctx(q, ctx, i)					\
	for ((i) = 0, ctx = per_cpu_ptr((q)->queue_ctx, 0);		\
	     (i) < (q)->nr_queues; (i)++, ctx = per_cpu_ptr(q->queue_ctx, (i)))

#define hctx_for_each_ctx(hctx, ctx, i)					\
	for ((i) = 0, ctx = (hctx)->ctxs[0];				\
	     (i) < (hctx)->nr_ctx; (i)++, ctx = (hctx)->ctxs[(i)])

#define blk_ctx_sum(q, sum)						\
({									\
	struct blk_mq_ctx *__x;						\
	unsigned int __ret = 0, __i;					\
									\
	queue_for_each_ctx((q), __x, __i)				\
		__ret += sum;						\
	__ret;								\
})

static inline unsigned int __blk_mq_in_flight(struct request_queue *q, int sync)
{
	return blk_ctx_sum(q, __x->rq_dispatched[sync] - __x->rq_completed[sync]);
}

static inline int blk_mq_in_flight(struct request_queue *q)
{
	return blk_ctx_sum(q, (__x->rq_dispatched[0] - __x->rq_completed[0]) +
			      (__x->rq_dispatched[1] - __x->rq_completed[1]));
}

#endif
