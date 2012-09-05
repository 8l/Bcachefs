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

#include <trace/events/block.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"

static DEFINE_PER_CPU(struct llist_head, ipi_lists);

/*
 * This assumes per-cpu software queueing queues. They could be per-node
 * as well, for instance. For now this is hardcoded as-is. Note that we don't
 * care about preemption, since we know the ctx's are persistent. This does
 * mean that we can't rely on ctx always matching the currently running CPU.
 */
static struct blk_mq_ctx *blk_mq_get_ctx(struct request_queue *q)
{
	return per_cpu_ptr(q->queue_ctx, raw_smp_processor_id());
}

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
	if (!test_bit(ctx->index_hw, hctx->ctx_map))
		set_bit(ctx->index_hw, hctx->ctx_map);
}

static struct request *__blk_mq_alloc_rq_nowait(struct blk_mq_hw_ctx *hctx)
{
	struct request *rq;
	unsigned int tag;

	do {
		tag = find_first_zero_bit(hctx->rq_map, hctx->queue_depth);
		if (tag >= hctx->queue_depth)
			return NULL;
	} while (test_and_set_bit_lock(tag, hctx->rq_map));

	rq = &hctx->rqs[tag];
	rq->tag = tag;

	return rq;
}

static struct request *__blk_mq_alloc_request(struct request_queue *q,
					      struct blk_mq_ctx *ctx,
					      unsigned int rw_flags, gfp_t gfp,
					      bool has_lock)
{
	struct blk_mq_hw_ctx *hctx;
	struct request *rq = NULL;
	DEFINE_WAIT(wait);

	hctx = q->mq_ops->map_queue(q, ctx->index);

	rq = __blk_mq_alloc_rq_nowait(hctx);
	if (rq) {
got_rq:
		rq->mq_ctx = ctx;
		rq->cmd_flags = rw_flags;
		ctx->rq_dispatched[rw_is_sync(rw_flags)]++;

		return rq;
	}

	if (!(gfp & __GFP_WAIT))
		return NULL;

	if (has_lock)
		spin_unlock(&ctx->q.lock);

	do {
		prepare_to_wait(&hctx->rq_wait, &wait, TASK_UNINTERRUPTIBLE);
		rq = __blk_mq_alloc_rq_nowait(hctx);
		if (rq)
			break;

		trace_block_sleeprq(q, NULL, rw_flags & 1);
		io_schedule();
	} while (!rq);

	finish_wait(&hctx->rq_wait, &wait);

	if (has_lock)
		spin_lock(&ctx->q.lock);

	goto got_rq;
}

struct request *blk_mq_alloc_request(struct request_queue *q, int rw, gfp_t gfp)
{
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);

	return __blk_mq_alloc_request(q, ctx, rw, gfp, false);
}

static void blk_mq_free_request(struct request *rq)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx;
	struct request_queue *q = rq->q;
	const int tag = rq->tag;

	ctx->rq_completed[rq_is_sync(rq)]++;

	hctx = q->mq_ops->map_queue(q, ctx->index);
	blk_rq_init(hctx->queue, rq);
	clear_bit_unlock(tag, hctx->rq_map);

	if (waitqueue_active(&hctx->rq_wait))
		wake_up(&hctx->rq_wait);
}

static void __blk_mq_end_io(struct request *rq, int error)
{
	struct bio *bio = rq->bio;
	unsigned int bytes = 0;

	if (blk_mark_rq_complete(rq))
		return;

	trace_block_rq_complete(rq->q, rq);

	while (bio) {
		struct bio *next = bio->bi_next;

		bio->bi_next = NULL;
		bytes += bio->bi_size;
		bio_endio(bio, error);
		bio = next;
	}

	blk_account_io_completion(rq, bytes);
	blk_account_io_done(rq);
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

	while ((entry = llist_del_all(list)) != NULL)
		llist_for_each_entry(rq, entry, ll_list)
			__blk_mq_end_io(rq, rq->errors);
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

		/*
		 * If the list is non-empty, an existing IPI must already
		 * be "in flight". If that is the case, we need not schedule
		 * a new one.
		 */
		if (llist_add(&rq->ll_list, &per_cpu(ipi_lists, cpu))) {
			data->func = ipi_end_io;
			data->flags = 0;
			__smp_call_function_single(cpu, data, 0);
		}
	}

	put_cpu();
}
EXPORT_SYMBOL(blk_mq_end_io);

static void blk_mq_start_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	trace_block_rq_issue(q, rq);

	/*
	 * Just mark start time and set the started bit. Due to memory
	 * ordering, we know we'll see the correct deadline as long as
	 * REQ_ATOMIC_STARTED is seen.
	 */
	rq->deadline = jiffies + q->rq_timeout;
	set_bit(REQ_ATOM_STARTED, &rq->atomic_flags);
}

static void blk_mq_hw_ctx_check_timeout(struct blk_mq_hw_ctx *hctx,
					unsigned long *next,
					unsigned int *next_set)
{
	unsigned int i;

	/*
	 * Timeout checks the busy map. If a bit is set, that request is
	 * currently allocated. It may not be in flight yet (this is where
	 * the REQ_ATOMIC_STARTED flag comes in). The requests are
	 * statically allocated, so we know it's always safe to access the
	 * memory associated with a bit offset into ->rqs[].
	 */
	for_each_set_bit(i, hctx->rq_map, hctx->queue_depth) {
		struct request *rq = &hctx->rqs[i];

		if (!test_bit(REQ_ATOM_STARTED, &rq->atomic_flags))
			continue;

		blk_rq_check_expired(rq, next, next_set);
	}
}

static void blk_mq_rq_timer(unsigned long data)
{
	struct request_queue *q = (struct request_queue *) data;
	struct blk_mq_hw_ctx *hctx;
	unsigned long next = 0;
	int i, next_set = 0;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_hw_ctx_check_timeout(hctx, &next, &next_set);

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

	list_for_each_entry_reverse(rq, &ctx->q.rq_list, queuelist) {
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
			break;
		} else if (el_ret == ELEVATOR_FRONT_MERGE) {
			if (bio_attempt_front_merge(q, rq, bio)) {
				ctx->rq_merged++;
				return true;
			}
			break;
		}
	}

	return false;
}

static void blk_mq_add_timer(struct request *rq)
{
	__blk_add_timer(rq, NULL);
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
		BUG_ON(bit != ctx->index_hw);

		spin_lock(&ctx->q.lock);
		list_splice_tail_init(&ctx->q.rq_list, &tmp);
		spin_unlock(&ctx->q.lock);

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

		if (!first)
			rq->cmd_flags |= REQ_END;

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
		last = first;
		while (last->next)
			last = last->next;

		if (last != first)
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
	list_add_tail(&rq->queuelist, &ctx->q.rq_list);
	blk_mq_hctx_mark_pending(hctx, ctx);

	/*
	 * We do this early, to ensure we are on the right CPU.
	 */
	blk_mq_add_timer(rq);
}

void blk_mq_insert_request(struct request_queue *q, struct request *rq)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;

	ctx = rq->mq_ctx;
	hctx = q->mq_ops->map_queue(q, ctx->index);

	spin_lock(&ctx->q.lock);
	__blk_mq_insert_request(hctx, ctx, rq);
	spin_unlock(&ctx->q.lock);
}

void blk_mq_insert_requests(struct request_queue *q, struct list_head *list)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;

	if (list_empty(list))
		return;

	ctx = blk_mq_get_ctx(q);
	hctx = q->mq_ops->map_queue(q, ctx->index);

	spin_lock(&ctx->q.lock);
	while (!list_empty(list)) {
		struct request *rq;

		rq = list_entry(list->next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		__blk_mq_insert_request(hctx, ctx, rq);
	}
	spin_unlock(&ctx->q.lock);

	blk_mq_run_hw_queue(hctx);
}

static struct request *blk_mq_bio_to_request(struct request_queue *q,
					     struct blk_mq_ctx *ctx,
					     struct bio *bio, bool has_lock)
{
	unsigned int rw_flags;
	struct request *rq;

	rw_flags = bio_data_dir(bio);
	if (rw_is_sync(bio->bi_rw))
		rw_flags |= REQ_SYNC;

	trace_block_getrq(q, bio, rw_flags & 1);

	rq = __blk_mq_alloc_request(q, ctx, rw_flags, GFP_ATOMIC | __GFP_WAIT,
					has_lock);
	if (rq) {
		init_request_from_bio(rq, bio);
		blk_account_io_start(rq, 1);
	}

	return rq;
}

static void blk_mq_make_request(struct request_queue *q, struct bio *bio)
{
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	int is_sync = rw_is_sync(bio->bi_rw);
	struct request *rq;
	unsigned int request_count = 0;
	struct blk_plug *plug;

	blk_queue_bounce(q, &bio);

	if (blk_attempt_plug_merge(q, bio, &request_count))
		return;

	ctx = blk_mq_get_ctx(q);
	hctx = q->mq_ops->map_queue(q, ctx->index);

	hctx->queued++;

	/*
	 * A task plug currently exists. Since this is completely lockless,
	 * utilize that to temporarily store requests until the task is
	 * either done or scheduled away.
	 */
	plug = current->plug;
	if (plug) {
		rq = blk_mq_bio_to_request(q, ctx, bio, false);
		if (list_empty(&plug->list))
			trace_block_plug(q);
		else if (request_count >= BLK_MAX_REQUEST_COUNT) {
			blk_flush_plug_list(plug, false);
			trace_block_plug(q);
		}
		list_add_tail(&rq->queuelist, &plug->list);
		return;
	}

	spin_lock(&ctx->q.lock);

	if (!(hctx->flags & BLK_MQ_F_SHOULD_MERGE) ||
	    !blk_mq_attempt_merge(q, ctx, bio)) {
		rq = blk_mq_bio_to_request(q, ctx, bio, true);
		__blk_mq_insert_request(hctx, ctx, rq);
	}

	spin_unlock(&ctx->q.lock);

	/*
	 * For a SYNC request, send it to the hardware immediately. For an
	 * ASYNC request, just ensure that we run it later on. The latter
	 * allows for merging opportunities and more efficient dispatching.
	 */
	if (is_sync)
		blk_mq_run_hw_queue(hctx);
	else
		kblockd_schedule_delayed_work(q, &hctx->delayed_work, 2);
}

/*
 * Default mapping to a software queue, since we use one per CPU
 */
struct blk_mq_hw_ctx *blk_mq_map_single_queue(struct request_queue *q,
					      const int ctx_index)
{
	return q->queue_hw_ctx[0];
}
EXPORT_SYMBOL(blk_mq_map_single_queue);

struct blk_mq_hw_ctx *blk_mq_alloc_single_hw_queue(struct blk_mq_reg *reg,
						   unsigned int hctx_index)
{
	return kmalloc_node(sizeof(struct blk_mq_hw_ctx),
				GFP_KERNEL | __GFP_ZERO, reg->numa_node);
}
EXPORT_SYMBOL(blk_mq_alloc_single_hw_queue);

void blk_mq_free_single_hw_queue(struct blk_mq_hw_ctx *hctx,
				 unsigned int hctx_index)
{
	kfree(hctx);
}
EXPORT_SYMBOL(blk_mq_free_single_hw_queue);

static void blk_mq_free_rq_map(struct blk_mq_hw_ctx *hctx)
{
	kfree(hctx->rqs);
	kfree(hctx->rq_map);
}

static int blk_mq_init_rq_map(struct blk_mq_hw_ctx *hctx)
{
	unsigned int num_maps, cur_qd;
	int i;

	/*
	 * We try to allocate all request structures up front. For highly
	 * fragmented memory this might not be possible and as a result, we
	 * lower the queue depth size and try again.
	 */
	cur_qd = hctx->queue_depth;
	while (cur_qd > 0) {
		size_t size = hctx->queue_depth * sizeof(struct request);

		hctx->rqs = kmalloc_node(size, GFP_KERNEL, hctx->numa_node);
		if (hctx->rqs)
			break;

		cur_qd >>= 1;
	}

	if (!hctx->rqs)
		return -ENOMEM;

	if (hctx->queue_depth != cur_qd) {
		hctx->queue_depth = cur_qd;
		pr_warn("%s: queue depth set to %u because of low memory\n",
					__func__, cur_qd);
	}

	num_maps = ALIGN(hctx->queue_depth, BITS_PER_LONG) / BITS_PER_LONG;
	hctx->rq_map = kzalloc_node(num_maps * sizeof(unsigned long),
					GFP_KERNEL, hctx->numa_node);
	if (!hctx->rq_map) {
		kfree(hctx->rqs);
		return -ENOMEM;
	}

	for (i = 0; i < hctx->queue_depth; i++)
		blk_rq_init(hctx->queue, &hctx->rqs[i]);

	init_waitqueue_head(&hctx->rq_wait);
	return 0;
}

struct request_queue *blk_mq_init_queue(struct blk_mq_reg *reg)
{
	struct blk_mq_hw_ctx **hctxs;
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	struct request_queue *q;
	int i;

	if (!reg->nr_hw_queues || !reg->ops->queue_rq ||
	    !reg->ops->map_queue || !reg->ops->alloc_hctx ||
	    !reg->ops->free_hctx)
		return ERR_PTR(-EINVAL);

	if (!reg->queue_depth)
		reg->queue_depth = BLK_MQ_MAX_DEPTH;
	else if (reg->queue_depth > BLK_MQ_MAX_DEPTH) {
		pr_err("blk-mq: queuedepth too large (%u)\n", reg->queue_depth);
		reg->queue_depth = BLK_MQ_MAX_DEPTH;
	}

	ctx = alloc_percpu(struct blk_mq_ctx);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	hctxs = kmalloc_node(reg->nr_hw_queues * sizeof(*hctxs), GFP_KERNEL,
			reg->numa_node);

	if (!hctxs)
		goto err_percpu;

	for (i = 0; i < reg->nr_hw_queues; i++) {
		hctxs[i] = reg->ops->alloc_hctx(reg, i);
		if (!hctxs[i])
			goto err_hctxs;
	}

	q = blk_alloc_queue_node(GFP_KERNEL, reg->numa_node);
	if (!q)
		goto err_hctxs;

	setup_timer(&q->timeout, blk_mq_rq_timer, (unsigned long) q);
	blk_queue_rq_timeout(q, 30000);

	q->nr_queues = nr_cpu_ids;
	q->nr_hw_queues = reg->nr_hw_queues;

	q->queue_ctx = ctx;
	q->queue_hw_ctx = hctxs;

	q->mq_ops = reg->ops;

	blk_queue_make_request(q, blk_mq_make_request);
	blk_queue_rq_timed_out(q, reg->ops->timeout);
	blk_queue_rq_timeout(q, reg->timeout);

	for_each_possible_cpu(i) {
		struct blk_mq_ctx *__ctx = per_cpu_ptr(ctx, i);

		memset(__ctx, 0, sizeof(*__ctx));
		__ctx->index = i;
		spin_lock_init(&__ctx->q.lock);
		INIT_LIST_HEAD(&__ctx->q.rq_list);

		hctx = q->mq_ops->map_queue(q, i);
		hctx->nr_ctx++;
	}

	/*
	 * Initialize hardware queues
	 */
	queue_for_each_hw_ctx(q, hctx, i) {
		unsigned int num_maps;

		INIT_DELAYED_WORK(&hctx->delayed_work, blk_mq_work_fn);
		spin_lock_init(&hctx->lock);
		init_llist_head(&hctx->dispatch);
		hctx->queue = q;
		hctx->flags = reg->flags;
		hctx->queue_depth = reg->queue_depth;
		hctx->numa_node = reg->numa_node;

		if (blk_mq_init_rq_map(hctx))
			break;

		hctx->ctxs = kmalloc_node(hctx->nr_ctx *
				sizeof(void *), GFP_KERNEL, reg->numa_node);
		if (!hctx->ctxs)
			break;

		num_maps = ALIGN(nr_cpu_ids, BITS_PER_LONG) / BITS_PER_LONG;
		hctx->ctx_map = kmalloc_node(num_maps * sizeof(unsigned long),
						GFP_KERNEL, reg->numa_node);
		hctx->nr_ctx_map = num_maps;

		hctx->nr_ctx = 0;
	}

	/*
	 * Init failed
	 */
	if (i != q->nr_hw_queues) {
		int j;

		queue_for_each_hw_ctx(q, hctx, j) {
			if (i == j)
				break;

			blk_mq_free_rq_map(hctx);
			kfree(hctx->ctxs);
		}

		goto err_hctxs;
	}

	/*
	 * Map software to hardware queues
	 */
	queue_for_each_ctx(q, ctx, i) {
		hctx = q->mq_ops->map_queue(q, i);
		ctx->index_hw = hctx->nr_ctx;
		hctx->ctxs[hctx->nr_ctx++] = ctx;
	}

	return q;
err_hctxs:
	for (i = 0; i < reg->nr_hw_queues; i++) {
		if (!hctxs[i])
			break;
		reg->ops->free_hctx(hctxs[i], i);
	}
	kfree(hctxs);
err_percpu:
	free_percpu(ctx);
	return ERR_PTR(-ENOMEM);
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
		blk_mq_free_rq_map(hctx);
		q->mq_ops->free_hctx(hctx, i);
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

		node = llist_del_all(&per_cpu(ipi_lists, cpu));
		llist_for_each_entry(rq, node, ll_list)
			__blk_mq_end_io(rq, rq->errors);

		local_irq_enable();
	}

	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata blk_mq_cpu_notifier = {
	.notifier_call	= blk_mq_cpu_notify,
};

int __init blk_mq_init(void)
{
	unsigned int i;

	for_each_possible_cpu(i)
		init_llist_head(&per_cpu(ipi_lists, i));

	register_hotcpu_notifier(&blk_mq_cpu_notifier);
	return 0;
}
