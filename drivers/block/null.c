#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/blk-mq.h>
#include <linux/hrtimer.h>

struct nullb {
	struct list_head list;
	struct request_queue *q;
	struct gendisk *disk;
	struct hrtimer timer;
	spinlock_t lock;
};

static LIST_HEAD(nullb_list);
static struct mutex lock;
static int null_major;

struct completion_queue {
	struct llist_head list;
	struct hrtimer timer;
};

/*
 * These are per-cpu for now, they will need to be configured by the
 * complete_queues parameter and appropriately mapped.
 */
static DEFINE_PER_CPU(struct completion_queue, completion_queues);

enum {
	NULL_IRQ_NONE		= 0,
	NULL_IRQ_SOFTIRQ,
	NULL_IRQ_TIMER,
};

static int submit_queues = 1;
module_param(submit_queues, int, S_IRUGO);
MODULE_PARM_DESC(submit_queues, "Number of submission queues");

static int complete_queues = 1;
module_param(complete_queues, int, S_IRUGO);
MODULE_PARM_DESC(complete_queues, "Number of completion queues");

static int home_node = NUMA_NO_NODE;
module_param(home_node, int, S_IRUGO);
MODULE_PARM_DESC(home_node, "Home node for the device");

static int use_mq = 1;
module_param(use_mq, int, S_IRUGO);
MODULE_PARM_DESC(use_mq, "Use blk-mq interface");

static int gb = 250;
module_param(gb, int, S_IRUGO);
MODULE_PARM_DESC(gb, "Size in GB");

static int bs = 512;
module_param(bs, int, S_IRUGO);
MODULE_PARM_DESC(bs, "Block size (in bytes)");

static int irqmode = NULL_IRQ_SOFTIRQ;
module_param(irqmode, int, S_IRUGO);
MODULE_PARM_DESC(irqmode, "IRQ completion handler. 0-none, 1-softirq, 2-timer");

static int completion_nsec = 10000;
module_param(completion_nsec, int, S_IRUGO);
MODULE_PARM_DESC(completion_nsec, "Time in ns to complete a request in hardware. Default: 10,000ns");

static int hw_queue_depth = 64;
module_param(hw_queue_depth, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: 64");

static bool use_per_node_hctx = true;
module_param(use_per_node_hctx, bool, S_IRUGO);
MODULE_PARM_DESC(use_per_node_hctx, "Use per-node allocation for hardware context queues. Default: true");

static void null_complete_request(struct blk_mq_hw_ctx *hctx,
				  struct request *rq)
{
	if (use_mq)
		blk_mq_end_io(hctx, rq, 0);
	else {
		INIT_LIST_HEAD(&rq->queuelist);
		blk_end_request_all(rq, 0);
	}
}

static enum hrtimer_restart null_request_timer_expired(struct hrtimer *timer)
{
	struct completion_queue *cq;
	struct llist_node *entry;
	struct request *rq;

	cq = &per_cpu(completion_queues, smp_processor_id());

	while ((entry = llist_del_first(&cq->list)) != NULL) {
		rq = llist_entry(entry, struct request, ll_list);
		null_complete_request(NULL, rq);
	}

	return HRTIMER_NORESTART;
}

static void null_request_end_timer(struct request *rq)
{
	struct completion_queue *cq = &per_cpu(completion_queues, get_cpu());

	rq->ll_list.next = NULL;
	if (llist_add(&rq->ll_list, &cq->list)) {
		ktime_t kt = ktime_set(0, completion_nsec);

		hrtimer_start(&cq->timer, kt, HRTIMER_MODE_REL);
	}

	put_cpu();
}

static void null_ipi_end_io(void *data)
{
	struct completion_queue *cq;
	struct llist_node *entry;
	struct request *rq;

	cq = &per_cpu(completion_queues, smp_processor_id());

	while ((entry = llist_del_first(&cq->list)) != NULL) {
		rq = llist_entry(entry, struct request, ll_list);
		null_complete_request(NULL, rq);
	}
}

static void null_softirq_done_fn(struct request *rq)
{
	blk_end_request_all(rq, 0);
}

static void null_request_end_ipi(struct request *rq)
{
	struct call_single_data *data = &rq->csd;
	int cpu = get_cpu();
	struct completion_queue *cq = &per_cpu(completion_queues, cpu);

	rq->ll_list.next = NULL;

	if (llist_add(&rq->ll_list, &cq->list)) {
		data->func = null_ipi_end_io;
		data->flags = 0;
		__smp_call_function_single(cpu, data, 0);
	}

	put_cpu();
}

static inline void null_handle_rq(struct blk_mq_hw_ctx *hctx,
				  struct request *rq)
{
	/* Complete IO by inline, softirq or timer */
	switch (irqmode) {
	case NULL_IRQ_NONE:
		null_complete_request(hctx, rq);
		break;
	case NULL_IRQ_SOFTIRQ:
		null_request_end_ipi(rq);
		break;
	case NULL_IRQ_TIMER:
		null_request_end_timer(rq);
		break;
	}
}

static void null_request_fn(struct request_queue *q)
{
	struct request *rq;

	while ((rq = blk_fetch_request(q)) != NULL) {
		spin_unlock_irq(q->queue_lock);
		null_handle_rq(NULL, rq);
		spin_lock_irq(q->queue_lock);
	}
}

static int null_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	null_handle_rq(hctx, rq);
	return BLK_MQ_RQ_QUEUE_OK;
}

static struct blk_mq_hw_ctx *null_alloc_hctx(struct blk_mq_reg *reg, unsigned int hctx_index)
{
	return kmalloc_node(sizeof(struct blk_mq_hw_ctx),
				GFP_KERNEL | __GFP_ZERO, hctx_index);
}

static void null_free_hctx(struct blk_mq_hw_ctx* hctx, unsigned int hctx_index)
{
	kfree(hctx);
}

/*
 * Map each per-cpu software queue to a per-node hardware queue
 */
struct blk_mq_hw_ctx *null_queue_map_per_node(struct request_queue *q,
					      struct blk_mq_ctx *ctx)
{
	return q->queue_hw_ctx[cpu_to_node(ctx->index)];
}

static struct blk_mq_ops null_mq_ops = {
	.queue_rq       = null_queue_rq,
	.map_queue      = blk_mq_map_single_queue,
};

static struct blk_mq_reg null_mq_reg = {
	.ops		= &null_mq_ops,
	.queue_depth	= 64,
	.flags		= BLK_MQ_F_SHOULD_MERGE,
};

static void null_del_dev(struct nullb *nullb)
{
	list_del_init(&nullb->list);

	del_gendisk(nullb->disk);
	if (use_mq)
		blk_mq_free_queue(nullb->q);
	else
		blk_cleanup_queue(nullb->q);
	put_disk(nullb->disk);
	kfree(nullb);
}

static int null_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static int null_release(struct gendisk *disk, fmode_t mode)
{
	return 0;
}

static const struct block_device_operations null_fops = {
	.owner =	THIS_MODULE,
	.open =		null_open,
	.release =	null_release,
};

static int null_add_dev(void)
{
	struct gendisk *disk;
	struct nullb *nullb;
	sector_t size;

	nullb = kmalloc_node(sizeof(*nullb), GFP_KERNEL, home_node);
	if (!nullb)
		return -ENOMEM;

	memset(nullb, 0, sizeof(*nullb));

	spin_lock_init(&nullb->lock);

	if (use_mq) {
		null_mq_reg.numa_node = home_node;
		null_mq_reg.queue_depth = hw_queue_depth;

		if (use_per_node_hctx) {
			null_mq_reg.ops->alloc_hctx = null_alloc_hctx;
			null_mq_reg.ops->free_hctx = null_free_hctx;

			null_mq_reg.nr_hw_queues = nr_online_nodes;
		} else {
			null_mq_reg.ops->alloc_hctx = blk_mq_alloc_single_hw_queue;
			null_mq_reg.ops->free_hctx = blk_mq_free_single_hw_queue;

			null_mq_reg.nr_hw_queues = submit_queues;
		}

		nullb->q = blk_mq_init_queue(&null_mq_reg);
	} else {
		nullb->q = blk_init_queue_node(null_request_fn, &nullb->lock, home_node);
		if (nullb->q)
			blk_queue_softirq_done(nullb->q, null_softirq_done_fn);
	}

	if (!nullb->q) {
		kfree(nullb);
		return -ENOMEM;
	}

	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, nullb->q);

	disk = nullb->disk = alloc_disk_node(1, home_node);
	if (!disk) {
		if (use_mq)
			blk_mq_free_queue(nullb->q);
		else
			blk_cleanup_queue(nullb->q);
		kfree(nullb);
		return -ENOMEM;
	}

	mutex_lock(&lock);
	list_add_tail(&nullb->list, &nullb_list);
	mutex_unlock(&lock);

	blk_queue_logical_block_size(nullb->q, bs);
	blk_queue_physical_block_size(nullb->q, bs);

	size = gb * 1024 * 1024 * 1024ULL;
	size /= (sector_t) bs;
	set_capacity(disk, size);

	disk->flags |= GENHD_FL_EXT_DEVT;
	spin_lock_init(&nullb->lock);
	disk->major		= null_major;
	disk->first_minor	= 0;
	disk->fops		= &null_fops;
	disk->private_data	= nullb;
	disk->queue		= nullb->q;
	sprintf(disk->disk_name, "nullb%d", 0);
	add_disk(disk);
	return 0;
}

static int __init null_init(void)
{
	unsigned int i;

	mutex_init(&lock);

	/* Initialize a separate list for each CPU for issuing softirqs */
	for_each_possible_cpu(i) {
		struct completion_queue *cq = &per_cpu(completion_queues, i);

		init_llist_head(&cq->list);

		if (irqmode != NULL_IRQ_TIMER)
			continue;

		hrtimer_init(&cq->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cq->timer.function = null_request_timer_expired;
	}

	null_major = register_blkdev(0, "nullb");
	if (null_major < 0)
		return null_major;

	if (null_add_dev()) {
		unregister_blkdev(null_major, "nullb");
		return -EINVAL;
	}

	pr_info("null: module loaded\n");
	return 0;
}

static void __exit null_exit(void)
{
	struct nullb *nullb;

	unregister_blkdev(null_major, "nullb");

	mutex_lock(&lock);
	while (!list_empty(&nullb_list)) {
		nullb = list_entry(nullb_list.next, struct nullb, list);
		null_del_dev(nullb);
	}
	mutex_unlock(&lock);
}

module_init(null_init);
module_exit(null_exit);

MODULE_AUTHOR("Jens Axboe <jaxboe@fusionio.com>");
MODULE_LICENSE("GPL");
