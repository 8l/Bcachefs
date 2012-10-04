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

static void blk_mq_sysfs_release(struct kobject *kobj)
{
}

struct blk_mq_ctx_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct blk_mq_ctx *, char *);
	ssize_t (*store)(struct blk_mq_ctx *, const char *, size_t);
};

struct blk_mq_hw_ctx_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct blk_mq_hw_ctx *, char *);
	ssize_t (*store)(struct blk_mq_hw_ctx *, const char *, size_t);
};

static ssize_t blk_mq_sysfs_show(struct kobject *kobj, struct attribute *attr,
				 char *page)
{
	struct blk_mq_ctx_sysfs_entry *entry;
	struct blk_mq_ctx *ctx;
	ssize_t res;

	entry = container_of(attr, struct blk_mq_ctx_sysfs_entry, attr);
	ctx = container_of(kobj, struct blk_mq_ctx, kobj);

	if (!entry->show)
		return -EIO;

	//mutex_lock(&q->sysfs_lock);
	res = entry->show(ctx, page);
	//mutex_unlock(&q->sysfs_lock);
	return res;
}

static ssize_t blk_mq_sysfs_store(struct kobject *kobj, struct attribute *attr,
				  const char *page, size_t length)
{
	struct blk_mq_ctx_sysfs_entry *entry;
	struct blk_mq_ctx *ctx;
	ssize_t res;

	entry = container_of(attr, struct blk_mq_ctx_sysfs_entry, attr);
	ctx = container_of(kobj, struct blk_mq_ctx, kobj);

	if (!entry->store)
		return -EIO;

	//mutex_unlock(&q->sysfs_lock);
	res = entry->store(ctx, page, length);
	//mutex_unlock(&q->sysfs_lock);
	return res;
}

static ssize_t blk_mq_hw_sysfs_show(struct kobject *kobj,
				    struct attribute *attr, char *page)
{
	struct blk_mq_hw_ctx_sysfs_entry *entry;
	struct blk_mq_hw_ctx *hctx;
	ssize_t res;

	entry = container_of(attr, struct blk_mq_hw_ctx_sysfs_entry, attr);
	hctx = container_of(kobj, struct blk_mq_hw_ctx, kobj);

	if (!entry->show)
		return -EIO;

	//mutex_lock(&q->sysfs_lock);
	res = entry->show(hctx, page);
	//mutex_unlock(&q->sysfs_lock);
	return res;
}

static ssize_t blk_mq_hw_sysfs_store(struct kobject *kobj,
				     struct attribute *attr, const char *page,
				     size_t length)
{
	struct blk_mq_hw_ctx_sysfs_entry *entry;
	struct blk_mq_hw_ctx *hctx;
	ssize_t res;

	entry = container_of(attr, struct blk_mq_hw_ctx_sysfs_entry, attr);
	hctx = container_of(kobj, struct blk_mq_hw_ctx, kobj);

	if (!entry->store)
		return -EIO;

	//mutex_unlock(&q->sysfs_lock);
	res = entry->store(hctx, page, length);
	//mutex_unlock(&q->sysfs_lock);
	return res;
}

static ssize_t blk_mq_sysfs_dispatched_show(struct blk_mq_ctx *ctx, char *page)
{
	return sprintf(page, "%lu %lu\n", ctx->rq_dispatched[1], ctx->rq_dispatched[0]);
}

static ssize_t blk_mq_sysfs_completed_show(struct blk_mq_ctx *ctx, char *page)
{
	return sprintf(page, "%lu %lu\n", ctx->rq_completed[1], ctx->rq_completed[0]);
}

static ssize_t sysfs_list_show(char *page, struct list_head *list, char *msg)
{
	char *start_page = page;
	struct request *rq;

	page += sprintf(page, "%s:\n", msg);

	list_for_each_entry(rq, list, queuelist)
		page += sprintf(page, "\t%p\n", rq);

	return page - start_page;
}

static ssize_t blk_mq_sysfs_rq_list_show(struct blk_mq_ctx *ctx, char *page)
{
	return sysfs_list_show(page, &ctx->rq_list, "CTX pending");
}

static ssize_t blk_mq_hw_sysfs_queued_show(struct blk_mq_hw_ctx *hctx,
					   char *page)
{
	return sprintf(page, "%lu\n", hctx->queued);
}

static ssize_t blk_mq_hw_sysfs_run_show(struct blk_mq_hw_ctx *hctx, char *page)
{
	return sprintf(page, "%lu\n", hctx->run);
}

static ssize_t blk_mq_hw_sysfs_dispatched_show(struct blk_mq_hw_ctx *hctx,
					       char *page)
{
	char *start_page = page;
	int i;

	page += sprintf(page, "%8u\t%lu\n", 0U, hctx->dispatched[0]);

	for (i = 1; i < BLK_MQ_MAX_DISPATCH_ORDER; i++) {
		unsigned long d = 1U << (i - 1);

		page += sprintf(page, "%8lu\t%lu\n", d, hctx->dispatched[i]);
	}

	return page - start_page;
}

static ssize_t blk_mq_hw_sysfs_rq_list_show(struct blk_mq_hw_ctx *hctx, char *page)
{
	return sysfs_list_show(page, &hctx->pending, "HCTX pending");
}

static struct blk_mq_ctx_sysfs_entry blk_mq_sysfs_dispatched = {
	.attr = {.name = "dispatched", .mode = S_IRUGO },
	.show = blk_mq_sysfs_dispatched_show,
};
static struct blk_mq_ctx_sysfs_entry blk_mq_sysfs_completed = {
	.attr = {.name = "completed", .mode = S_IRUGO },
	.show = blk_mq_sysfs_completed_show,
};
static struct blk_mq_ctx_sysfs_entry blk_mq_sysfs_rq_list = {
	.attr = {.name = "rq_list", .mode = S_IRUGO },
	.show = blk_mq_sysfs_rq_list_show,
};

static struct attribute *default_ctx_attrs[] = {
	&blk_mq_sysfs_dispatched.attr,
	&blk_mq_sysfs_completed.attr,
	&blk_mq_sysfs_rq_list.attr,
	NULL,
};

static struct blk_mq_hw_ctx_sysfs_entry blk_mq_hw_sysfs_queued = {
	.attr = {.name = "queued", .mode = S_IRUGO },
	.show = blk_mq_hw_sysfs_queued_show,
};
static struct blk_mq_hw_ctx_sysfs_entry blk_mq_hw_sysfs_run = {
	.attr = {.name = "run", .mode = S_IRUGO },
	.show = blk_mq_hw_sysfs_run_show,
};
static struct blk_mq_hw_ctx_sysfs_entry blk_mq_hw_sysfs_dispatched = {
	.attr = {.name = "dispatched", .mode = S_IRUGO },
	.show = blk_mq_hw_sysfs_dispatched_show,
};
static struct blk_mq_hw_ctx_sysfs_entry blk_mq_hw_sysfs_pending = {
	.attr = {.name = "pending", .mode = S_IRUGO },
	.show = blk_mq_hw_sysfs_rq_list_show,
};

static struct attribute *default_hw_ctx_attrs[] = {
	&blk_mq_hw_sysfs_queued.attr,
	&blk_mq_hw_sysfs_run.attr,
	&blk_mq_hw_sysfs_dispatched.attr,
	&blk_mq_hw_sysfs_pending.attr,
	NULL,
};

static const struct sysfs_ops blk_mq_sysfs_ops = {
	.show	= blk_mq_sysfs_show,
	.store	= blk_mq_sysfs_store,
};

static const struct sysfs_ops blk_mq_hw_sysfs_ops = {
	.show	= blk_mq_hw_sysfs_show,
	.store	= blk_mq_hw_sysfs_store,
};

static struct kobj_type blk_mq_ktype = {
	.sysfs_ops	= &blk_mq_sysfs_ops,
	.release	= blk_mq_sysfs_release,
};

static struct kobj_type blk_mq_ctx_ktype = {
	.sysfs_ops	= &blk_mq_sysfs_ops,
	.default_attrs	= default_ctx_attrs,
	.release	= blk_mq_sysfs_release,
};

static struct kobj_type blk_mq_hw_ktype = {
	.sysfs_ops	= &blk_mq_hw_sysfs_ops,
	.default_attrs	= default_hw_ctx_attrs,
	.release	= blk_mq_sysfs_release,
};

void blk_mq_unregister_disk(struct gendisk *disk)
{
	struct request_queue *q = disk->queue;

	kobject_uevent(&q->mq_kobj, KOBJ_REMOVE);
	kobject_del(&q->mq_kobj);

	kobject_put(&disk_to_dev(disk)->kobj);
}

int blk_mq_register_disk(struct gendisk *disk)
{
	struct device *dev = disk_to_dev(disk);
	struct request_queue *q = disk->queue;
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	int ret, i, j;

	kobject_init(&q->mq_kobj, &blk_mq_ktype);

	ret = kobject_add(&q->mq_kobj, kobject_get(&dev->kobj), "%s", "mq");
	if (ret < 0)
		return ret;

	kobject_uevent(&q->mq_kobj, KOBJ_ADD);

	queue_for_each_hw_ctx(q, hctx, i) {
		kobject_init(&hctx->kobj, &blk_mq_hw_ktype);
		ret = kobject_add(&hctx->kobj, &q->mq_kobj, "%u", i);
		if (ret)
			break;

		hctx_for_each_ctx(hctx, ctx, j) {
			kobject_init(&ctx->kobj, &blk_mq_ctx_ktype);
			ret = kobject_add(&ctx->kobj, &hctx->kobj, "%u", j);
			if (ret)
				break;
		}
	}

	if (ret) {
		blk_mq_unregister_disk(disk);
		return ret;
	}

	return 0;
}
