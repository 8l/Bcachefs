#ifndef BLK_MQ_H
#define BLK_MQ_H

#include <linux/blkdev.h>

struct blk_mq_ctx {
	spinlock_t		lock;

	unsigned int		cpu;

	struct list_head	rq_list;

	struct list_head	timeout;

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];
};

struct blk_mq_hw_ctx {
	spinlock_t		lock;

	struct list_head	pending;
	struct delayed_work	delayed_work;

	unsigned long		flags;

	struct request_queue	*queue;

	unsigned int		nr_ctx;
	struct blk_mq_ctx	**ctxs;
};

typedef int (queue_rq_fn) (struct blk_mq_hw_ctx *, struct request *);
typedef struct blk_mq_hw_ctx *(map_queue_fn) (struct request_queue *, struct blk_mq_ctx *);

struct blk_mq_ops {
	queue_rq_fn		*queue_rq;
	map_queue_fn		*map_queue;
};

enum {
	BLK_MQ_RQ_QUEUE_OK	= 0,	/* queued fine */
	BLK_MQ_RQ_QUEUE_BUSY	= 1,	/* requeue IO for later */
	BLK_MQ_RQ_QUEUE_ERROR	= 2,	/* end IO with error */

	BLK_MQ_F_SHOULD_MERGE	= 1 << 0,
	BLK_MQ_F_SHOULD_SORT	= 1 << 1,
};

struct blk_mq_reg {
	struct blk_mq_ops	*ops;
	unsigned int		nr_hw_queues;
	unsigned int		queue_depth;
	int			numa_node;
	unsigned int		should_sort;
	unsigned int		flags;		/* BLK_MQ_F_* */
};

struct request_queue *blk_mq_init_queue(struct blk_mq_reg *);
void blk_mq_free_queue(struct request_queue *);

struct blk_mq_hw_ctx *blk_mq_map_single_queue(struct request_queue *q, struct blk_mq_ctx *);

void blk_mq_end_io(struct request *rq, int error);

#define queue_for_each_hw_ctx(q, hctx, i)				\
	for (i = 0, hctx = &(q)->queue_hw_ctx[0];			\
	     i < (q)->nr_hw_queues; i++, hctx++)

#define queue_for_each_ctx(q, ctx, i)					\
	for (i = 0, ctx = per_cpu_ptr((q)->queue_ctx, 0);		\
	     i < (q)->nr_queues; i++, ctx = per_cpu_ptr(q->queue_ctx, i))

#define hctx_for_each_ctx(hctx, ctx, i)					\
	for (i = 0, ctx = (hctx)->ctxs[0];				\
	     i < (hctx)->nr_ctx; i++, ctx = (hctx)->ctxs[i])

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
