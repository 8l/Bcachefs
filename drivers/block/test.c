
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>

#include "../md/bcache/util.h"

#define kobj_attribute_write(n, fn)					\
	static struct kobj_attribute ksysfs_##n = __ATTR(n, S_IWUSR, NULL, fn)

static int blk_test_major, blk_test_minor;

struct blk_test_dev {
	struct gendisk		*disk;
	struct block_device	*bdev;

	struct bio_set		*pool;
	struct mutex		lock;
	struct rb_root		buffer;
	unsigned		nr_pages;
};

struct cached_page {
	struct rb_node		node;
	sector_t		sector;
	struct page		*page;
};

struct blk_test_bio {
	struct bio		*orig_bio;
	struct blk_test_dev	*dev;
	struct work_struct	work;
	struct bio		bio;
};

static int cached_page_cmp(struct cached_page *l, struct cached_page *r)
{
	if (l->sector < r->sector)
		return -1;
	if (l->sector > r->sector)
		return 1;
	return 0;
}

static struct cached_page *first_cached_page(struct blk_test_dev *dev,
					     struct bio *bio)
{
	return bio->bi_iter.bi_sector
		? RB_GREATER(&dev->buffer,
			     ((struct cached_page) { .sector = bio->bi_iter.bi_sector - 1 }),
			     node, cached_page_cmp)
		: RB_FIRST(&dev->buffer, struct cached_page, node);
}

static void cache_flush(struct blk_test_dev *dev)
{
	struct cached_page *p;
	struct bio *bio = bio_alloc(GFP_NOIO, 1);

	while ((p = RB_FIRST(&dev->buffer, struct cached_page, node))) {
		bio->bi_iter.bi_sector	= p->sector;
		bio->bi_bdev	= dev->bdev;
		bio_add_page(bio, p->page, PAGE_SIZE, 0);

		submit_bio_wait(WRITE, bio);
		bio_reset(bio);

		rb_erase(&p->node, &dev->buffer);
		__free_page(p->page);
		kfree(p);
	}

	bio_put(bio);
	dev->nr_pages = 0;
}

static void cache_bio_read(struct blk_test_dev *dev, struct bio *bio)
{
	struct cached_page *p = first_cached_page(dev, bio);
	struct bio_vec bv;
	struct bvec_iter iter;
	sector_t sector = bio->bi_iter.bi_sector;

	bio_for_each_segment(bv, bio, iter) {
		if (!p)
			break;

		if (p->sector == sector) {
			copy_page(page_address(bv.bv_page),
				  page_address(p->page));
			p = RB_NEXT(p, node);
		}

		sector += bv.bv_len >> 9;
	}
}

static void cache_bio_cache(struct blk_test_dev *dev, struct bio *bio)
{
	struct cached_page *p;
	struct bio_vec bv;
	struct bvec_iter iter;
	sector_t sector = bio->bi_iter.bi_sector;

	mutex_lock(&dev->lock);
	p = first_cached_page(dev, bio);

	bio_for_each_segment(bv, bio, iter) {
		if (!p || p->sector != sector) {
			p = kzalloc(sizeof(struct cached_page), GFP_NOIO);
			BUG_ON(!p);

			p->sector = sector;
			p->page = alloc_page(GFP_NOIO);
			BUG_ON(!p->page);
			RB_INSERT(&dev->buffer, p, node, cached_page_cmp);
			dev->nr_pages++;
		}

		copy_page(page_address(p->page),
			  page_address(bv.bv_page));
		p = RB_NEXT(p, node);

		sector += bv.bv_len >> 9;
	}

	mutex_unlock(&dev->lock);
}

static void cache_bio_drop(struct blk_test_dev *dev, struct bio *bio)
{
	struct cached_page *p = first_cached_page(dev, bio);

	while (p && p->sector < bio_end_sector(bio)) {
		struct cached_page *next = RB_NEXT(p, node);

		rb_erase(&p->node, &dev->buffer);
		__free_page(p->page);
		kfree(p);
		dev->nr_pages--;

		p = next;
	}
}

static void blk_test_make_request_work(struct work_struct *work)
{
	struct blk_test_bio *t = container_of(work, struct blk_test_bio, work);
	struct bio *orig_bio = t->orig_bio;
	int error;

	mutex_lock(&t->dev->lock);

	if (orig_bio->bi_rw & REQ_FLUSH)
		cache_flush(t->dev);

	error = submit_bio_wait(0, &t->bio);
	if (!error) {
		if (bio_data_dir(orig_bio) == READ)
			cache_bio_read(t->dev, orig_bio);
		else
			cache_bio_drop(t->dev, orig_bio);
	}

	mutex_unlock(&t->dev->lock);

	bio_put(&t->bio);
	bio_endio(orig_bio, error);
}

static void blk_test_make_request(struct request_queue *q, struct bio *bio)
{
	struct blk_test_dev *dev = q->queuedata;
	struct blk_test_bio *t;

	if (bio->bi_iter.bi_sector % (PAGE_SIZE >> 9) ||
	    bio->bi_iter.bi_size != bio->bi_vcnt * PAGE_SIZE) {
		printk(KERN_INFO "unaligned bio\n");
		bio->bi_rw |= REQ_FLUSH;
	}

	if (bio_data_dir(bio) == WRITE &&
	    !(bio->bi_rw & (REQ_FLUSH|REQ_FUA)) &&
	    dev->nr_pages < 2048 &&
	    !(get_random_int() % 5)) {
		cache_bio_cache(dev, bio);
		bio_endio(bio, 0);
		return;
	}

	t = container_of(bio_clone_bioset(bio, GFP_NOIO, dev->pool),
			 struct blk_test_bio, bio);

	t->orig_bio	= bio;
	t->dev		= dev;
	t->bio.bi_bdev	= dev->bdev;

	INIT_WORK(&t->work, blk_test_make_request_work);
	schedule_work(&t->work);
}

static int open_dev(struct block_device *b, fmode_t mode)
{
	return 0;
}

static void release_dev(struct gendisk *b, fmode_t mode)
{
}

static const struct block_device_operations blk_test_ops = {
	.open		= open_dev,
	.release	= release_dev,
	.owner		= THIS_MODULE,
};

static ssize_t register_blk_test(struct kobject *k, struct kobj_attribute *attr,
				 const char *buffer, size_t size)
{
	ssize_t ret = size;
	struct blk_test_dev *dev = NULL;
	char *path = NULL;

	if (!(path = kstrndup(buffer, size, GFP_KERNEL)) ||
	    !(dev = kzalloc(sizeof(struct blk_test_dev), GFP_KERNEL)))
		ret = ENOMEM;

	mutex_init(&dev->lock);

	dev->bdev = blkdev_get_by_path(strim(path),
				       FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				       dev);
	if (IS_ERR(dev->bdev)) {
		ret = PTR_ERR(dev->bdev);
		goto err;
	}

	dev->pool = bioset_create(4, offsetof(struct blk_test_bio, bio));
	if (!dev->pool)
		goto err;

	dev->disk = alloc_disk(1);
	if (!dev->disk)
		goto err;

	set_capacity(dev->disk, dev->bdev->bd_part->nr_sects);
	snprintf(dev->disk->disk_name, DISK_NAME_LEN, "blk_test%i", blk_test_minor);

	dev->disk->major	= blk_test_major;
	dev->disk->first_minor	= blk_test_minor++;
	dev->disk->fops		= &blk_test_ops;
	dev->disk->private_data	= dev;

	dev->disk->queue = blk_alloc_queue(GFP_KERNEL);
	if (!dev->disk->queue)
		goto err;

	blk_queue_make_request(dev->disk->queue, blk_test_make_request);
	blk_queue_flush(dev->disk->queue, REQ_FLUSH|REQ_FUA);

	set_bit(QUEUE_FLAG_NONROT,	&dev->disk->queue->queue_flags);
	//set_bit(QUEUE_FLAG_DISCARD,	&dev->disk->queue->queue_flags);

	dev->disk->queue->queuedata = dev;
	dev->disk->queue->limits = dev->bdev->bd_queue->limits;

	add_disk(dev->disk);

out:
	kfree(path);
	return ret;
err:
	if (dev && dev->bdev)
		blkdev_put(dev->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	kfree(dev);
	goto out;
}

kobj_attribute_write(register_blk_test,		register_blk_test);

static void blk_test_exit(void)
{
	unregister_blkdev(blk_test_major, "blk_test");

}

static int __init blk_test_init(void)
{
	int ret;
	static const struct attribute *files[] = {
		&ksysfs_register_blk_test.attr,
		NULL
	};

	blk_test_major = register_blkdev(0, "blk_test");
	if (blk_test_major < 0)
		return blk_test_major;

	ret = sysfs_create_files(fs_kobj, files);
	if (ret)
		return ret;

	return 0;
}

module_exit(blk_test_exit);
module_init(blk_test_init);
