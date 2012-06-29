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
#include <linux/llist.h>
#include <linux/cpu.h>

#include <linux/blk-mq.h>
#include "blk.h"

static DEFINE_PER_CPU(struct llist_head, ipi_lists);

/*
 * Check if any of the ctx's have pending work in this hardware queue
 */
static bool blk_mq_hctx_has_pending(struct blk_mq_hw_ctx *hctx)
{
	unsigned int i;

	for (i = 0; i < hctx->nr_ctx_map; i++)
		if (hctx->ctx_map[i])
			return true;

	return false;
}

/*
 * Mark this ctx as having pending work in this hardware queue
 */
static void blk_mq_hctx_mark_pending(struct blk_mq_hw_ctx *hctx,
				     struct blk_mq_ctx *ctx)
{
	if (!test_bit(ctx->index, hctx->ctx_map))
		set_bit(ctx->index, hctx->ctx_map);
}

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

/*
 * Called with interrupts disabled.
 */
static void ipi_end_io(void *data)
{
	struct llist_head *list = &per_cpu(ipi_lists, smp_processor_id());
	struct llist_node *entry;
	struct request *rq;

	while ((entry = llist_del_first(list)) != NULL) {
		rq = llist_entry(entry, struct request, ll_list);

		__blk_mq_end_io(rq, rq->errors);
	}
}

/*
 * End IO on this request on a multiqueue enabled driver. We'll either do
 * it directly inline, or punt to a local IPI handler on the matching
 * remote CPU.
 */
void blk_mq_end_io(struct request *rq, int error)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	int cpu;

	if (!ctx->ipi_redirect)
		return __blk_mq_end_io(rq, error);

	cpu = get_cpu();
	if (cpu == ctx->index)
		__blk_mq_end_io(rq, error);
	else {
		struct call_single_data *data = &rq->csd;

		rq->errors = error;
		rq->ll_list.next = NULL;

		if (llist_add(&rq->ll_list, &per_cpu(ipi_lists, cpu))) {
			data->func = ipi_end_io;
			data->flags = 0;
			__smp_call_function_single(cpu, data, 0);
		}
	}

	put_cpu();
}
EXPORT_SYMBOL(blk_mq_end_io);

/*
 * FIXME: we currently don't add requests to the ctx timeout list
 */
static void blk_mq_start_request(struct request *rq)
{
	struct request_queue *q = rq->q;

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
		list_for_each_entry_safe(rq, tmp, &ctx->timeout, timeout_list) {
			if (!test_bit(REQ_ATOM_STARTED, &rq->atomic_flags))
				continue;
			blk_rq_check_expired(rq, &next, &next_set);
		}
		spin_unlock(&ctx->lock);
	}

	if (next_set)
		mod_timer(&q->timeout, round_jiffies_up(next));
}

/*
 * Reverse check our software queue for entries that we could potentially
 * merge with. Currently includes a hand-wavy stop count of 8, to not spend
 * too much time checking for merges.
 */
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
			if (bio_attempt_back_merge(q, rq, bio)) {
				ctx->rq_merged++;
				return true;
			}
		} else if (el_ret == ELEVATOR_FRONT_MERGE) {
			if (bio_attempt_front_merge(q, rq, bio)) {
				ctx->rq_merged++;
				return true;
			}
		}
	}

	return false;
}

static void blk_mq_add_timer(struct request *rq)
{
	__blk_add_timer(rq, &rq->mq_ctx->timeout);
}

/*
 * Run this hardware queue, pulling any software queues mapped to it in.
 * Note that this function currently has various problems around ordering
 * of IO. In particular, we'd like FIFO behaviour on handling existing
 * items on the hctx->dispatch list. Ignore that for now.
 */
void blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct blk_mq_ctx *ctx;
	struct request *rq;
	struct llist_node *first, *last = NULL;
	LLIST_HEAD(rq_list);
	LIST_HEAD(tmp);
	int bit, queued;

	hctx->run++;

	/*
	 * Touch any software queue that has pending entries.
	 */
	for_each_set_bit(bit, hctx->ctx_map, hctx->nr_ctx) {
		clear_bit(bit, hctx->ctx_map);
		ctx = hctx->ctxs[bit];
		BUG_ON(bit != ctx->index);

		spin_lock(&ctx->lock);
		list_splice_tail_init(&ctx->rq_list, &tmp);
		spin_unlock(&ctx->lock);

		/*
		 * Reverse-add the entries to a lockless list, using the
		 * non-cmpxchg variant for adding the entries. It's a local
		 * list on the stack, so we need not care about others
		 * fiddling with it.
		 */
		while (!list_empty(&tmp)) {
			rq = list_entry(tmp.prev, struct request, queuelist);
			list_del(&rq->queuelist);
			rq->ll_list.next = NULL;
			__llist_add(&rq->ll_list, &rq_list);

			if (!last)
				last = &rq->ll_list;
		}
	}

	/*
	 * If we found entries above, batch add them to the dispatch list.
	 */
	if (!llist_empty(&rq_list))
		llist_add_batch(rq_list.first, last, &hctx->dispatch);

	/*
	 * Delete and return all entries from our dispatch list
	 */
	queued = 0;
	first = llist_del_all(&hctx->dispatch);

	/*
	 * Now process all the entries, sending them to the driver.
	 */
	while (first) {
		struct llist_node *entry;
		int ret;

		entry = first;
		first = first->next;

		rq = llist_entry(entry, struct request, ll_list);
		blk_mq_start_request(rq);

		ret = q->mq_ops->queue_rq(hctx, rq);
		switch (ret) {
		case BLK_MQ_RQ_QUEUE_OK:
			queued++;
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

	if (!queued)
		hctx->dispatched[0]++;
	else if (queued < (1 << (BLK_MQ_MAX_DISPATCH_ORDER - 1)))
		hctx->dispatched[ilog2(queued) + 1]++;

	/*
	 * Any items that need requeuing? Find last entry, batch re-add.
	 */
	if (first) {
		last = NULL;
		while (first->next)
			last = first->next;

		if (last)
			llist_add_batch(first, last, &hctx->dispatch);
		else
			llist_add(first, &hctx->dispatch);
	}
}

void blk_mq_run_queues(struct request_queue *q, bool async)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (!blk_mq_hctx_has_pending(hctx) &&
		    llist_empty(&hctx->dispatch))
			continue;

		if (!async)
			blk_mq_run_hw_queue(hctx);
		else
			kblockd_schedule_delayed_work(q, &hctx->delayed_work, 0);
	}
}

static void blk_mq_work_fn(struct work_struct *work)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(work, struct blk_mq_hw_ctx, delayed_work.work);
	blk_mq_run_hw_queue(hctx);
}

void blk_mq_flush_plug(struct request_queue *q, bool from_schedule)
{
	blk_mq_run_queues(q, from_schedule);
}

static void __blk_mq_insert_request(struct blk_mq_hw_ctx *hctx,
				    struct blk_mq_ctx *ctx,
				    struct request *rq)
{
	list_add_tail(&rq->queuelist, &ctx->rq_list);
	blk_mq_hctx_mark_pending(hctx, ctx);

	/*
	 * We do this early, to ensure we are on the right CPU.
	 */
	blk_mq_add_timer(rq);
}

void blk_mq_insert_requests(struct request_queue *q, struct list_head *list)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;

	ctx = per_cpu_ptr(q->queue_ctx, smp_processor_id());
	hctx = q->mq_ops->map_queue(q, ctx);
	
	spin_lock(&ctx->lock);
	while (!list_empty(list)) {
		struct request *rq;

		rq = list_entry(list->next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		__blk_mq_insert_request(hctx, ctx, rq);
	}
	spin_unlock(&ctx->lock);
}

static void blk_mq_make_request(struct request_queue *q, struct bio *bio)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	int is_sync = rw_is_sync(bio->bi_rw);
	struct request *rq;

	blk_queue_bounce(q, &bio);

	preempt_disable();
	ctx = per_cpu_ptr(q->queue_ctx, smp_processor_id());
	hctx = q->mq_ops->map_queue(q, ctx);

	hctx->queued++;

	spin_lock(&ctx->lock);

	if (!(hctx->flags & BLK_MQ_F_SHOULD_MERGE) ||
	    !blk_mq_attempt_merge(q, ctx, bio)) {
		unsigned int rw_flags;

		rw_flags = bio_data_dir(bio);
		if (is_sync)
			rw_flags |= REQ_SYNC;

		rq = blk_mq_alloc_request(q, ctx, rw_flags);

		init_request_from_bio(rq, bio);
		__blk_mq_insert_request(hctx, ctx, rq);
	}

	spin_unlock(&ctx->lock);
	preempt_enable();

	if (is_sync)
		blk_mq_run_hw_queue(hctx);
	else
		kblockd_schedule_delayed_work(q, &hctx->delayed_work, 2);
}

/*
 * Default mapping to a software queue, since we use one per CPU
 */
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
	int i;

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
		__ctx->index = i;
		INIT_LIST_HEAD(&__ctx->rq_list);
		INIT_LIST_HEAD(&__ctx->timeout);
	}

	q->nr_queues = nr_cpu_ids;
	q->nr_hw_queues = reg->nr_hw_queues;

	/*
	 * Initialize hardware queues
	 */
	queue_for_each_hw_ctx(q, hctx, i) {
		unsigned int num_maps;

		INIT_DELAYED_WORK(&hctx->delayed_work, blk_mq_work_fn);
		spin_lock_init(&hctx->lock);
		init_llist_head(&hctx->dispatch);
		atomic_set(&hctx->run_count, 0);
		hctx->queue = q;
		hctx->flags = reg->flags;

		/* FIXME: alloc failure handling */
		hctx->ctxs = kmalloc_node(hctx->nr_ctx *
				sizeof(void *), GFP_KERNEL, reg->numa_node);

		num_maps = (nr_cpu_ids + BITS_PER_LONG - 1) / BITS_PER_LONG;
		hctx->ctx_map = kmalloc_node(num_maps * sizeof(unsigned long),
						GFP_KERNEL, reg->numa_node);
		hctx->nr_ctx_map = num_maps;

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
		kfree(hctx->ctx_map);
		kfree(hctx->ctxs);
	}

	free_percpu(q->queue_ctx);
	kfree(q->queue_hw_ctx);

	q->queue_ctx = NULL;
	q->queue_hw_ctx = NULL;
}
EXPORT_SYMBOL(blk_mq_free_queue);

static int __cpuinit blk_mq_cpu_notify(struct notifier_block *self,
				       unsigned long action, void *hcpu)
{
	/*
	 * If the CPU goes away, ensure that we run any pending completions.
	 */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		int cpu = (unsigned long) hcpu;
		struct llist_node *node;
		struct request *rq;

		local_irq_disable();

		node = llist_del_first(&per_cpu(ipi_lists, cpu));
		llist_for_each_entry(rq, node, ll_list)
			__blk_mq_end_io(rq, rq->errors);

		local_irq_enable();
	}

	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata blk_mq_cpu_notifier = {
	.notifier_call	= blk_mq_cpu_notify,
};

int blk_mq_init(void)
{
	unsigned int i;

	for_each_possible_cpu(i)
		init_llist_head(&per_cpu(ipi_lists, i));

	register_hotcpu_notifier(&blk_mq_cpu_notifier);
	return 0;
}
