#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/smp.h>

#include <linux/blk-mq.h>
#include "blk.h"

static struct request *blk_mq_alloc_request(struct request_queue *q,
					    struct blk_mq_ctx *ctx,
					    unsigned int rw_flags)
{
	struct request *rq;

	rq = kmem_cache_alloc(request_cachep, GFP_ATOMIC);
	blk_rq_init(q, rq);
	rq->mq_ctx = ctx;
	rq->cmd_flags = rw_flags;
	ctx->rq_dispatched[rw_is_sync(rw_flags)]++;

	return rq;
}

static void blk_mq_free_request(struct request *rq)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;

	ctx->rq_completed[rq_is_sync(rq)]++;
	kmem_cache_free(request_cachep, rq);
}

static void __blk_mq_end_io(struct request *rq, int error)
{
	struct bio *bio = rq->bio;

	while (bio) {
		struct bio *next = bio->bi_next;

		bio->bi_next = NULL;
		bio_endio(bio, error);
		bio = next;
	}

	if (!list_empty(&rq->timeout_list))
		list_del_init(&rq->timeout_list);

	blk_mq_free_request(rq);
}

#undef BLK_MQ_IPI_REDIRECT

#if defined(BLK_MQ_IPI_REDIRECT)
static void ipi_end_io(void *data)
{
	struct request *rq = data;

	__blk_mq_end_io(rq, rq->errors);
}

void blk_mq_end_io(struct request *rq, int error)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	int cpu = get_cpu();

	if (cpu == ctx->cpu)
		__blk_mq_end_io(rq, error);
	else {
		struct call_single_data *data = &rq->csd;

		rq->errors = error;
		data->func = ipi_end_io;
		data->info = rq;
		data->flags = 0;
		__smp_call_function_single(cpu, data, 0);
	}

	put_cpu();
}
#else
void blk_mq_end_io(struct request *rq, int error)
{
	__blk_mq_end_io(rq, error);
}
#endif
EXPORT_SYMBOL(blk_mq_end_io);

static void blk_mq_start_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	list_del_init(&rq->queuelist);
	rq->deadline = jiffies + q->rq_timeout;
	set_bit(REQ_ATOM_STARTED, &rq->atomic_flags);
}

static void blk_mq_rq_timer(unsigned long data)
{
	struct request_queue *q = (struct request_queue *) data;
	struct request *rq, *tmp;
	unsigned long next = 0;
	struct blk_mq_ctx *ctx;
	int i, next_set = 0;

	queue_for_each_ctx(q, ctx, i) {
		spin_lock(&ctx->lock);
		list_for_each_entry_safe(rq, tmp, &ctx->timeout, timeout_list)
			blk_rq_check_expired(rq, &next, &next_set);
		spin_unlock(&ctx->lock);
	}

	if (next_set)
		mod_timer(&q->timeout, round_jiffies_up(next));
}

static bool blk_mq_attempt_merge(struct request_queue *q,
				 struct blk_mq_ctx *ctx, struct bio *bio)
{
	struct request *rq;
	int checked = 8;

	list_for_each_entry_reverse(rq, &ctx->rq_list, queuelist) {
		int el_ret;

		if (!checked--)
			break;

		if (!blk_rq_merge_ok(rq, bio))
			continue;

		el_ret = blk_try_merge(rq, bio);
		if (el_ret == ELEVATOR_BACK_MERGE) {
			if (bio_attempt_back_merge(q, rq, bio))
				return true;
		} else if (el_ret == ELEVATOR_FRONT_MERGE) {
			if (bio_attempt_front_merge(q, rq, bio))
				return true;
		}
	}

	return false;
}

static void blk_mq_add_timer(struct request *rq)
{
	__blk_add_timer(rq, &rq->mq_ctx->timeout);
}

void blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct blk_mq_ctx *ctx;
	LIST_HEAD(rq_list);
	int bit;

	/*
	 * Someone else is already in here, let him do the work
	 */
	if (atomic_add_return(1, &hctx->run_count) != 1)
		return;

re_run:
	if (!list_empty(&hctx->pending)) {
		spin_lock(&hctx->lock);
		list_splice_init(&hctx->pending, &rq_list);
		spin_unlock(&hctx->lock);
	}

	for_each_set_bit(bit, &hctx->ctx_map, hctx->nr_ctx) {
		clear_bit(bit, &hctx->ctx_map);
		ctx = hctx->ctxs[bit];
		BUG_ON(bit != ctx->cpu);

		spin_lock(&ctx->lock);
		list_splice_tail_init(&ctx->rq_list, &rq_list);
		spin_unlock(&ctx->lock);
	}

	while (!list_empty(&rq_list)) {
		struct request *rq;
		int ret;

		rq = list_entry(rq_list.next, struct request, queuelist);
		blk_mq_start_request(rq);

		ret = q->mq_ops->queue_rq(hctx, rq);
		switch (ret) {
		case BLK_MQ_RQ_QUEUE_OK:
			continue;
		case BLK_MQ_RQ_QUEUE_BUSY:
			break;
		default:
			pr_err("blk-mq: bad return on queue: %d\n", ret);
			rq->errors = -EIO;
		case BLK_MQ_RQ_QUEUE_ERROR:
			blk_mq_end_io(rq, rq->errors);
			break;
		}
	}

	if (!list_empty(&rq_list)) {
		spin_lock(&hctx->lock);
		list_splice(&rq_list, &hctx->pending);
		spin_unlock(&hctx->lock);
	} else if (!hctx->ctx_map)
		atomic_set(&hctx->run_count, 0);
	else if (atomic_add_return(-1, &hctx->run_count))
		goto re_run;
}

void blk_mq_run_queue(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_run_hw_queue(hctx);
}

static void blk_mq_work_fn(struct work_struct *work)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(work, struct blk_mq_hw_ctx, delayed_work.work);
	blk_mq_run_hw_queue(hctx);
}

static void blk_mq_make_request(struct request_queue *q, struct bio *bio)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	unsigned int rw_flags;
	int is_sync = rw_is_sync(bio->bi_rw);
	struct request *rq;

	blk_queue_bounce(q, &bio);

	rw_flags = bio_data_dir(bio);
	if (is_sync)
		rw_flags |= REQ_SYNC;

	preempt_disable();
	ctx = per_cpu_ptr(q->queue_ctx, smp_processor_id());
	hctx = q->mq_ops->map_queue(q, ctx);

	spin_lock(&ctx->lock);

	if (!(hctx->flags & BLK_MQ_F_SHOULD_MERGE) ||
	    !blk_mq_attempt_merge(q, ctx, bio)) {
		rq = blk_mq_alloc_request(q, ctx, rw_flags);

		init_request_from_bio(rq, bio);
		list_add_tail(&rq->queuelist, &ctx->rq_list);

		if (!test_bit(ctx->cpu, &hctx->ctx_map))
			set_bit(ctx->cpu, &hctx->ctx_map);

		/*
		 * We do this early, to ensure we are on the right CPU.
		 */
		blk_mq_add_timer(rq);
	}

	spin_unlock(&ctx->lock);
	preempt_enable();

	if (is_sync)
		blk_mq_run_hw_queue(hctx);
	else
		kblockd_schedule_delayed_work(q, &hctx->delayed_work, 2);
}

struct blk_mq_hw_ctx *blk_mq_map_single_queue(struct request_queue *q,
						 struct blk_mq_ctx *ctx)
{
	return &q->queue_hw_ctx[0];
}
EXPORT_SYMBOL(blk_mq_map_single_queue);

struct request_queue *blk_mq_init_queue(struct blk_mq_reg *reg)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	struct request_queue *q;
	int i, last_index = 0;

	if (!reg->nr_hw_queues || !reg->ops->queue_rq || !reg->ops->map_queue)
		return ERR_PTR(-EINVAL);

	if (!reg->queue_depth)
		reg->queue_depth = BLKDEV_MAX_RQ;

	ctx = alloc_percpu(struct blk_mq_ctx);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	hctx = kmalloc_node(reg->nr_hw_queues * sizeof(*hctx), GFP_KERNEL,
				reg->numa_node);
	if (!hctx) {
		free_percpu(ctx);
		return ERR_PTR(-ENOMEM);
	}
	memset(hctx, 0, reg->nr_hw_queues * sizeof(*hctx));

	q = blk_alloc_queue_node(GFP_KERNEL, reg->numa_node);
	if (!q) {
		free_percpu(ctx);
		return ERR_PTR(-ENOMEM);
	}

	setup_timer(&q->timeout, blk_mq_rq_timer, (unsigned long) q);
	blk_queue_rq_timeout(q, 30000);

	q->queue_ctx = ctx;
	q->queue_hw_ctx = hctx;

	blk_queue_make_request(q, blk_mq_make_request);
	q->mq_ops = reg->ops;

	for_each_possible_cpu(i) {
		struct blk_mq_ctx *__ctx = per_cpu_ptr(ctx, i);

		hctx = q->mq_ops->map_queue(q, ctx);
		hctx->nr_ctx++;

		memset(__ctx, 0, sizeof(*__ctx));
		spin_lock_init(&__ctx->lock);
		__ctx->cpu = i;
		INIT_LIST_HEAD(&__ctx->rq_list);
		INIT_LIST_HEAD(&__ctx->timeout);
		last_index = i;
	}

	q->nr_queues = last_index;
	q->nr_hw_queues = reg->nr_hw_queues;

	/*
	 * Initialize hardware queues
	 */
	queue_for_each_hw_ctx(q, hctx, i) {
		INIT_DELAYED_WORK(&hctx->delayed_work, blk_mq_work_fn);
		spin_lock_init(&hctx->lock);
		INIT_LIST_HEAD(&hctx->pending);
		atomic_set(&hctx->run_count, 0);
		hctx->queue = q;
		hctx->flags = reg->flags;

		/* FIXME: alloc failure handling */
		hctx->ctxs = kmalloc_node(hctx->nr_ctx * sizeof(void *),
						GFP_KERNEL, reg->numa_node);
		hctx->nr_ctx = 0;
	}

	/*
	 * Map software to hardware queues
	 */
	queue_for_each_ctx(q, ctx, i) {
		hctx = q->mq_ops->map_queue(q, ctx);
		hctx->ctxs[hctx->nr_ctx++] = ctx;
	}

	return q;
}
EXPORT_SYMBOL(blk_mq_init_queue);

void blk_mq_free_queue(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		cancel_delayed_work_sync(&hctx->delayed_work);
		kfree(hctx->ctxs);
	}

	free_percpu(q->queue_ctx);
	kfree(q->queue_hw_ctx);

	q->queue_ctx = NULL;
	q->queue_hw_ctx = NULL;
}
EXPORT_SYMBOL(blk_mq_free_queue);
