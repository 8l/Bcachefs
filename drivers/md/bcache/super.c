/*
 * bcache setup/teardown code, and some metadata io - read a superblock and
 * figure out what to do with it.
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "blockdev.h"
#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "gc.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"
#include "notify.h"
#include "stats.h"
#include "super.h"
#include "tier.h"
#include "writeback.h"

#include <linux/blkdev.h>
#include <linux/crc32c.h>
#include <linux/debugfs.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/reboot.h>
#include <linux/sysfs.h>

#include <trace/events/bcache.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

static const uuid_le invalid_uuid = {
	.b = {
		0xa0, 0x3e, 0xf8, 0xed, 0x3e, 0xe1, 0xb8, 0x78,
		0xc8, 0x50, 0xfc, 0x5e, 0xcb, 0x16, 0xcd, 0x99
	}
};

static struct kset *bcache_kset;
struct mutex bch_register_lock;
LIST_HEAD(bch_cache_sets);

struct workqueue_struct *bcache_io_wq;

static void bch_cache_stop(struct cache *);

u64 bch_checksum_update(unsigned type, u64 crc, const void *data, size_t len)
{
	switch (type) {
	case BCH_CSUM_NONE:
		return 0;
	case BCH_CSUM_CRC32C:
		return crc32c(crc, data, len);
	case BCH_CSUM_CRC64:
		return bch_crc64_update(crc, data, len);
	default:
		BUG();
	}
}

u64 bch_checksum(unsigned type, const void *data, size_t len)
{
	u64 crc = 0xffffffffffffffffULL;

	crc = bch_checksum_update(type, crc, data, len);

	return crc ^ 0xffffffffffffffffULL;
}

static bool bch_is_open_cache(struct block_device *bdev)
{
	struct cache_set *c, *tc;
	struct cache *ca;
	unsigned i;

	rcu_read_lock();
	list_for_each_entry_safe(c, tc, &bch_cache_sets, list)
		for_each_cache_rcu(ca, c, i)
			if (ca->disk_sb.bdev == bdev) {
				rcu_read_unlock();
				return true;
			}
	rcu_read_unlock();
	return false;
}

static bool bch_is_open(struct block_device *bdev)
{
	bool ret;

	mutex_lock(&bch_register_lock);
	ret = bch_is_open_cache(bdev) || bch_is_open_backing(bdev);
	mutex_unlock(&bch_register_lock);

	return ret;
}

static const char *bch_blkdev_open(const char *path, void *holder,
				   struct block_device **ret)
{
	struct block_device *bdev;
	const char *err;

	*ret = NULL;
	bdev = blkdev_get_by_path(path, FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				  holder);

	if (bdev == ERR_PTR(-EBUSY)) {
		bdev = lookup_bdev(path);
		if (IS_ERR(bdev))
			return "device busy";

		err = bch_is_open(bdev)
			? "device already registered"
			: "device busy";

		bdput(bdev);
		return err;
	}

	if (IS_ERR(bdev))
		return "failed to open device";

	*ret = bdev;
	return NULL;
}

void bch_cache_group_remove_cache(struct cache_group *grp, struct cache *ca)
{
	unsigned i;

	write_seqcount_begin(&grp->lock);

	for (i = 0; i < grp->nr_devices; i++)
		if (grp->devices[i] == ca) {
			grp->nr_devices--;
			memmove(&grp->devices[i],
				&grp->devices[i + 1],
				(grp->nr_devices - i) * sizeof(ca));
			break;
		}

	write_seqcount_end(&grp->lock);
}

void bch_cache_group_add_cache(struct cache_group *grp, struct cache *ca)
{
	write_seqcount_begin(&grp->lock);
	BUG_ON(grp->nr_devices >= MAX_CACHES_PER_SET);

	rcu_assign_pointer(grp->devices[grp->nr_devices++], ca);
	write_seqcount_end(&grp->lock);
}

/* Superblock */

const char *validate_cache_member(struct cache_sb *sb,
				  struct cache_member *mi)
{
	if (mi->nbuckets > LONG_MAX)
		return "Too many buckets";

	if (mi->nbuckets < 1 << 8)
		return "Not enough buckets";

	if (!is_power_of_2(mi->bucket_size) ||
	    mi->bucket_size < PAGE_SECTORS ||
	    mi->bucket_size < sb->block_size)
		return "Bad bucket size";

	return NULL;
}

const char *validate_super(struct bcache_superblock *disk_sb,
			   struct cache_sb *sb)
{
	const char *err;
	struct cache_sb *s = disk_sb->sb;

	sb->offset		= le64_to_cpu(s->offset);
	sb->version		= le64_to_cpu(s->version);
	sb->seq			= le64_to_cpu(s->seq);

	sb->magic		= s->magic;
	sb->disk_uuid		= s->disk_uuid;
	sb->user_uuid		= s->user_uuid;
	sb->set_uuid		= s->set_uuid;
	memcpy(sb->label,	s->label, SB_LABEL_SIZE);

	sb->flags		= le64_to_cpu(s->flags);
	sb->block_size		= le16_to_cpu(s->block_size);
	sb->u64s		= le16_to_cpu(s->u64s);

	switch (sb->version) {
	case BCACHE_SB_VERSION_BDEV:
		sb->bdev_data_offset	= BDEV_DATA_START_DEFAULT;
		sb->bdev_last_mount	= le32_to_cpu(s->bdev_last_mount);
		sb->bdev_last_mount	= get_seconds();
		break;
	case BCACHE_SB_VERSION_BDEV_WITH_OFFSET:
		sb->bdev_data_offset	= le64_to_cpu(s->bdev_data_offset);
		sb->bdev_last_mount	= le32_to_cpu(s->bdev_last_mount);
		/* hrm. */
		sb->bdev_last_mount	= get_seconds();

		if (sb->bdev_data_offset < BDEV_DATA_START_DEFAULT)
			return "Bad data offset";

		break;
	case BCACHE_SB_VERSION_CDEV_V0:
	case BCACHE_SB_VERSION_CDEV_WITH_UUID:
	case BCACHE_SB_VERSION_CDEV_V2:
	case BCACHE_SB_VERSION_CDEV_V3:
		sb->nr_in_set	= le16_to_cpu(s->nr_in_set);
		sb->nr_this_dev	= le16_to_cpu(s->nr_this_dev);

		if (CACHE_SYNC(sb) &&
		    sb->version != BCACHE_SB_VERSION_CDEV_V3)
			return "Unsupported superblock version";

		if (!is_power_of_2(sb->block_size) ||
		    sb->block_size > PAGE_SECTORS)
			return "Bad block size";

		if (bch_is_zero(sb->disk_uuid.b, sizeof(uuid_le)))
			return "Bad disk UUID";

		if (bch_is_zero(sb->user_uuid.b, sizeof(uuid_le)))
			return "Bad user UUID";

		if (bch_is_zero(sb->set_uuid.b, sizeof(uuid_le)))
			return "Bad set UUID";

		if (!sb->nr_in_set ||
		    sb->nr_in_set <= sb->nr_this_dev ||
		    sb->nr_in_set > MAX_CACHES_PER_SET)
			return "Bad cache device number in set";

		if (!CACHE_SET_META_REPLICAS_WANT(sb) ||
		    CACHE_SET_META_REPLICAS_WANT(sb) >= BKEY_EXTENT_PTRS_MAX)
			return "Invalid number of metadata replicas";

		if (!CACHE_SET_DATA_REPLICAS_WANT(sb) ||
		    CACHE_SET_DATA_REPLICAS_WANT(sb) >= BKEY_EXTENT_PTRS_MAX)
			return "Invalid number of data replicas";

		if (CACHE_SB_CSUM_TYPE(sb) >= BCH_CSUM_NR)
			return "Invalid checksum type";

		if (!CACHE_BTREE_NODE_SIZE(sb))
			return "Btree node size not set";

		if (sb->u64s < bch_journal_buckets_offset(sb))
			return "Invalid superblock: member info area missing";

		if ((err = validate_cache_member(sb, s->members +
						 sb->nr_this_dev)))
			return err;

		break;
	default:
		return"Unsupported superblock version";
	}

	return NULL;
}

void free_super(struct bcache_superblock *sb)
{
	if (sb->bio)
		bio_put(sb->bio);
	if (!IS_ERR_OR_NULL(sb->bdev))
		blkdev_put(sb->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	free_pages((unsigned long) sb->sb, sb->page_order);
	memset(sb, 0, sizeof(*sb));
}

static int __bch_super_realloc(struct bcache_superblock *sb, unsigned order)
{
	struct cache_sb *new_sb;
	struct bio *bio;

	if (sb->page_order >= order && sb->sb)
		return 0;

	new_sb = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!new_sb)
		return -ENOMEM;

	bio = bio_kmalloc(GFP_KERNEL, 1 << order);
	if (!bio) {
		free_pages((unsigned long) new_sb, order);
		return -ENOMEM;
	}

	if (sb->sb)
		memcpy(new_sb, sb->sb, PAGE_SIZE << sb->page_order);

	free_pages((unsigned long) sb->sb, sb->page_order);
	sb->sb = new_sb;

	if (sb->bio)
		bio_put(sb->bio);
	sb->bio = bio;

	sb->page_order = order;

	return 0;
}

int bch_super_realloc(struct bcache_superblock *sb, unsigned u64s)
{
	struct cache_member *mi = sb->sb->members + sb->sb->nr_this_dev;
	char buf[BDEVNAME_SIZE];
	size_t bytes = __set_bytes((struct cache_sb *) NULL, u64s);
	size_t want = bytes + (SB_SECTOR << 9);

	if (want > mi->first_bucket * (mi->bucket_size << 9)) {
		pr_err("%s: superblock too big: want %zu but have %u",
		       bdevname(sb->bdev, buf), want,
		       mi->first_bucket * mi->bucket_size << 9);
		return -ENOSPC;
	}

	return __bch_super_realloc(sb, get_order(bytes));
}

static const char *read_super(struct bcache_superblock *sb,
			      const char *path)
{
	const char *err;
	unsigned order = 0;

	memset(sb, 0, sizeof(*sb));

	err = bch_blkdev_open(path, &sb, &sb->bdev);
	if (err)
		return err;
retry:
	err = "cannot allocate memory";
	if (__bch_super_realloc(sb, order))
		goto err;

	err = "dynamic fault";
	if (cache_set_init_fault("read_super"))
		goto err;

	bio_reset(sb->bio);
	sb->bio->bi_bdev = sb->bdev;
	sb->bio->bi_iter.bi_sector = SB_SECTOR;
	sb->bio->bi_iter.bi_size = PAGE_SIZE << sb->page_order;
	bch_bio_map(sb->bio, sb->sb);

	err = "IO error";
	if (submit_bio_wait(READ, sb->bio))
		goto err;

	err = "Not a bcache superblock";
	if (uuid_le_cmp(sb->sb->magic, BCACHE_MAGIC))
		goto err;

	err = "Superblock has incorrect offset";
	if (le64_to_cpu(sb->sb->offset) != SB_SECTOR)
		goto err;

	pr_debug("read sb version %llu, flags %llu, seq %llu, journal size %u",
		 le64_to_cpu(sb->sb->version),
		 le64_to_cpu(sb->sb->flags),
		 le64_to_cpu(sb->sb->seq),
		 le16_to_cpu(sb->sb->u64s));

	err = "Superblock block size smaller than device block size";
	if (le16_to_cpu(sb->sb->block_size) << 9 <
	    bdev_logical_block_size(sb->bdev))
		goto err;

	order = get_order(__set_bytes(sb->sb, le16_to_cpu(sb->sb->u64s)));
	if (order > sb->page_order)
		goto retry;

	err = "Bad checksum";
	if (sb->sb->csum != csum_set(sb->sb,
				     le64_to_cpu(sb->sb->version) <
				     BCACHE_SB_VERSION_CDEV_V3
				     ? BCH_CSUM_CRC64
				     : CACHE_SB_CSUM_TYPE(sb->sb)))
		goto err;

	return NULL;
err:
	free_super(sb);
	return err;
}

void __write_super(struct cache_set *c, struct bcache_superblock *disk_sb,
		   struct cache_sb *sb)
{
	struct cache_sb *out = disk_sb->sb;
	struct bio *bio = disk_sb->bio;

	bio->bi_bdev		= disk_sb->bdev;
	bio->bi_iter.bi_sector	= SB_SECTOR;
	bio->bi_iter.bi_size	= roundup(set_bytes(sb),
					  bdev_logical_block_size(disk_sb->bdev));
	bch_bio_map(bio, out);

	out->offset		= cpu_to_le64(sb->offset);
	out->version		= cpu_to_le64(sb->version);
	out->seq		= cpu_to_le64(sb->seq);

	out->disk_uuid		= sb->disk_uuid;
	out->user_uuid		= sb->user_uuid;
	out->set_uuid		= sb->set_uuid;
	memcpy(out->label,	sb->label, SB_LABEL_SIZE);

	if (__SB_IS_BDEV(sb->version)) {
		out->bdev_data_offset	= cpu_to_le64(sb->bdev_data_offset);
		out->bdev_last_mount	= cpu_to_le32(sb->bdev_last_mount);
	} else {
		out->nr_in_set		= cpu_to_le16(sb->nr_in_set);
		out->nr_this_dev	= cpu_to_le16(sb->nr_this_dev);
	}

	out->flags		= cpu_to_le64(sb->flags);
	out->u64s		= cpu_to_le16(sb->u64s);
	out->csum		= csum_set(out,
					   sb->version < BCACHE_SB_VERSION_CDEV_V3
					   ? BCH_CSUM_CRC64
					   : CACHE_SB_CSUM_TYPE(sb));

	pr_debug("ver %llu, flags %llu, seq %llu",
		 sb->version, sb->flags, sb->seq);

	bio->bi_rw		|= (REQ_WRITE|REQ_SYNC|REQ_META);
	bch_generic_make_request(bio, c);
}

static void write_super_endio(struct bio *bio, int error)
{
	struct cache *ca = bio->bi_private;

	bch_count_io_errors(ca, error, "writing superblock");
	closure_put(&ca->set->sb_write);
	percpu_ref_put(&ca->ref);
}

static void bcache_write_super_unlock(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, sb_write);

	up(&c->sb_write_mutex);
}

static int cache_sb_to_cache_set(struct cache_set *c, struct cache_sb *sb)
{
	struct cache_member_rcu *new, *old = c->members;
	unsigned nr_in_set = le16_to_cpu(sb->nr_in_set);

	new = kzalloc(sizeof(struct cache_member_rcu) +
		      sizeof(struct cache_member) * nr_in_set,
		      GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->nr_in_set = nr_in_set;
	memcpy(&new->m, sb->members,
	       nr_in_set * sizeof(new->m[0]));

	rcu_assign_pointer(c->members, new);
	if (old)
		kfree_rcu(old, rcu);

	c->sb.version		= le64_to_cpu(sb->version);
	c->sb.seq		= le64_to_cpu(sb->seq);
	c->sb.user_uuid		= sb->user_uuid;
	c->sb.set_uuid		= sb->set_uuid;
	memcpy(c->sb.label, sb->label, SB_LABEL_SIZE);
	c->sb.nr_in_set		= le16_to_cpu(sb->nr_in_set);
	c->sb.flags		= le64_to_cpu(sb->flags);
	c->sb.block_size	= le16_to_cpu(sb->block_size);

	pr_debug("set version = %llu", c->sb.version);
	return 0;
}

static int cache_sb_from_cache_set(struct cache_set *c, struct cache *ca)
{
	struct cache_member_rcu *mi;

	if (ca->sb.nr_in_set != c->sb.nr_in_set) {
		unsigned old_offset = bch_journal_buckets_offset(&ca->sb);
		unsigned u64s = bch_journal_buckets_offset(&c->sb)
			+ bch_nr_journal_buckets(&ca->sb);
		int ret = bch_super_realloc(&ca->disk_sb, u64s);

		if (ret)
			return ret;

		ca->sb.nr_in_set = c->sb.nr_in_set;
		ca->sb.u64s = u64s;

		memmove(__journal_buckets(ca),
			ca->disk_sb.sb->_data + old_offset,
			bch_nr_journal_buckets(&ca->sb) * sizeof(u64));
	}

	mi = cache_member_info_get(c);
	ca->mi = mi->m[ca->sb.nr_this_dev];

	memcpy(ca->disk_sb.sb->_data, mi->m,
	       mi->nr_in_set * sizeof(mi->m[0]));
	cache_member_info_put();

	ca->sb.version		= BCACHE_SB_VERSION_CDEV;
	ca->sb.seq		= c->sb.seq;
	ca->sb.user_uuid	= c->sb.user_uuid;
	ca->sb.set_uuid		= c->sb.set_uuid;
	memcpy(ca->sb.label, c->sb.label, SB_LABEL_SIZE);
	ca->sb.nr_in_set	= c->sb.nr_in_set;
	ca->sb.flags		= c->sb.flags;

	return 0;
}

static void __bcache_write_super(struct cache_set *c)
{
	struct closure *cl = &c->sb_write;
	struct cache *ca;
	unsigned i;

	closure_init(cl, &c->cl);

	c->sb.seq++;

	for_each_cache(ca, c, i) {
		struct bio *bio = ca->disk_sb.bio;

		cache_sb_from_cache_set(c, ca);

		SET_CACHE_SB_CSUM_TYPE(&ca->sb,
				       CACHE_PREFERRED_CSUM_TYPE(&c->sb));

		bio_reset(bio);
		bio->bi_bdev	= ca->disk_sb.bdev;
		bio->bi_end_io	= write_super_endio;
		bio->bi_private = ca;

		closure_get(cl);
		percpu_ref_get(&ca->ref);
		__write_super(c, &ca->disk_sb, &ca->sb);
	}

	closure_return_with_destructor(cl, bcache_write_super_unlock);
}

void bcache_write_super(struct cache_set *c)
{
	down(&c->sb_write_mutex);
	__bcache_write_super(c);
}

void bch_check_mark_super_slowpath(struct cache_set *c,
				   const struct bkey *k, bool meta)
{
	struct cache_member *mi;
	const struct bkey_i_extent *e = bkey_i_to_extent_c(k);
	const struct bch_extent_ptr *ptr;

	down(&c->sb_write_mutex);

	/* recheck, might have raced */
	if (bch_check_super_marked(c, k, meta)) {
		up(&c->sb_write_mutex);
		return;
	}

	mi = cache_member_info_get(c)->m;

	extent_for_each_ptr(e, ptr)
		(meta
		 ? SET_CACHE_HAS_METADATA
		 : SET_CACHE_HAS_DATA)(mi + PTR_DEV(ptr), true);

	cache_member_info_put();

	__bcache_write_super(c);
}

/* Cache set */

static void bch_recalc_capacity(struct cache_set *c)
{
	struct cache_group *tier = c->cache_tiers + ARRAY_SIZE(c->cache_tiers);
	u64 capacity = 0;
	unsigned i;

	while (--tier >= c->cache_tiers)
		if (tier->nr_devices) {
			for (i = 0; i < tier->nr_devices; i++) {
				struct cache *ca = tier->devices[i];

				capacity += (ca->mi.nbuckets -
					     ca->mi.first_bucket) <<
					ca->bucket_bits;

				ca->reserve_buckets_count =
				div_u64((ca->mi.nbuckets - ca->mi.first_bucket) *
						c->bucket_reserve_percent, 100);

			}

			capacity *= (100 - c->sector_reserve_percent);
			capacity = div64_u64(capacity, 100);
			break;
		}

	c->capacity = capacity;

	/* Wake up case someone was waiting for buckets */
	closure_wake_up(&c->freelist_wait);
	closure_wake_up(&c->buckets_available_wait);
}

static void __bch_cache_read_only(struct cache *ca);

static void bch_cache_set_read_only(struct cache_set *c)
{
	struct cached_dev *dc;
	struct bcache_device *d;
	struct radix_tree_iter iter;
	void **slot;

	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	if (test_and_set_bit(CACHE_SET_RO, &c->flags))
		return;

	trace_bcache_cache_set_read_only(c);

	/*
	 * Block new foreground-end write operations from starting - any new
	 * writes will return -EROFS:
	 */
	percpu_ref_kill(&c->writes);

	bch_wake_delayed_writes((unsigned long) c);
	del_timer_sync(&c->foreground_write_wakeup);
	cancel_delayed_work_sync(&c->pd_controllers_update);

	/* Wait for outstanding writes to complete: */
	wait_for_completion(&c->write_disable_complete);

	radix_tree_for_each_slot(slot, &c->devices, &iter, 0) {
		d = rcu_dereference_protected(*slot,
				lockdep_is_held(&bch_register_lock));

		if (!INODE_FLASH_ONLY(&d->inode.v)) {
			dc = container_of(d, struct cached_dev, disk);
			bch_cached_dev_writeback_stop(dc);
		}
	}

	c->tiering_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&c->tiering_pd.rate);
	bch_tiering_read_stop(c);

	set_bit(CACHE_SET_GC_STOPPING, &c->flags);

	if (!IS_ERR_OR_NULL(c->gc_thread))
		kthread_stop(c->gc_thread);

	/* Should skip this if we're unregistering because of an error */
	bch_btree_flush(c);

	for_each_cache(ca, c, i)
		__bch_cache_read_only(ca);

	if (c->journal.cur) {
		cancel_delayed_work_sync(&c->journal.work);
		/* flush last journal entry if needed */
		c->journal.work.work.func(&c->journal.work.work);
	}

	bch_notify_cache_set_read_only(c);

	trace_bcache_cache_set_read_only_done(c);
}

static void bch_cache_set_read_only_work(struct work_struct *work)
{
	struct cache_set *c = container_of(work, struct cache_set, read_only_work);

	mutex_lock(&bch_register_lock);
	bch_cache_set_read_only(c);
	mutex_unlock(&bch_register_lock);
}

void bch_cache_set_fail(struct cache_set *c)
{
	switch (CACHE_ERROR_ACTION(&c->sb)) {
	case BCH_ON_ERROR_CONTINUE:
		break;
	case BCH_ON_ERROR_RO:
		pr_err("%pU going read only", c->sb.set_uuid.b);
		schedule_work(&c->read_only_work);
		break;
	case BCH_ON_ERROR_PANIC:
		panic("bcache: %pU panic after error\n",
		      c->sb.set_uuid.b);
		break;
	}
}

void bch_cache_set_release(struct kobject *kobj)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
	kfree(c);
	module_put(THIS_MODULE);
}

static void cache_set_free(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, cl);
	struct cache *ca;
	unsigned i;

	if (!IS_ERR_OR_NULL(c->debug))
		debugfs_remove(c->debug);

	bch_btree_cache_free(c);
	bch_journal_free(c);

	mutex_lock(&bch_register_lock);
	for_each_cache(ca, c, i)
		bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);

	bch_bset_sort_state_free(&c->sort);

	percpu_ref_free(&c->writes);
	free_percpu(c->prio_clock[WRITE].rescale_percpu);
	free_percpu(c->prio_clock[READ].rescale_percpu);
	if (c->wq)
		destroy_workqueue(c->wq);
	if (c->bio_split)
		bioset_free(c->bio_split);
	if (c->fill_iter)
		mempool_destroy(c->fill_iter);
	if (c->bio_meta)
		mempool_destroy(c->bio_meta);
	if (c->search)
		mempool_destroy(c->search);

	mutex_lock(&bch_register_lock);
	list_del(&c->list);
	mutex_unlock(&bch_register_lock);

	bch_notify_cache_set_stopped(c);

	kfree(c->uevent_env);

	pr_info("Cache set %pU unregistered", c->sb.set_uuid.b);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

static void cache_set_flush(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	mutex_lock(&bch_register_lock);

	bch_extent_store_exit_cache_set(c);
	bch_cache_set_read_only(c);

	mutex_unlock(&bch_register_lock);

	bch_cache_accounting_destroy(&c->accounting);

	kobject_put(&c->internal);
	kobject_del(&c->kobj);

	closure_return(cl);
}

static void __cache_set_unregister(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);
	struct cached_dev *dc;
	struct bcache_device *d;
	struct radix_tree_iter iter;
	void **slot;

	mutex_lock(&bch_register_lock);

	rcu_read_lock();

	radix_tree_for_each_slot(slot, &c->devices, &iter, 0) {
		d = radix_tree_deref_slot(slot);

		if (!INODE_FLASH_ONLY(&d->inode.v) &&
		    test_bit(CACHE_SET_UNREGISTERING, &c->flags)) {
			dc = container_of(d, struct cached_dev, disk);
			bch_cached_dev_detach(dc);
		} else {
			bcache_device_stop(d);
		}
	}

	rcu_read_unlock();

	mutex_unlock(&bch_register_lock);

	continue_at(cl, cache_set_flush, system_wq);
}

void bch_cache_set_stop(struct cache_set *c)
{
	if (!test_and_set_bit(CACHE_SET_STOPPING, &c->flags))
		closure_queue(&c->caching);
}

void bch_cache_set_unregister(struct cache_set *c)
{
	if (!test_and_set_bit(CACHE_SET_UNREGISTERING, &c->flags))
		bch_cache_set_stop(c);
}

static unsigned cache_set_nr_devices(struct cache_set *c)
{
	unsigned i, nr = 0;
	struct cache_member_rcu *mi = cache_member_info_get(c);

	for (i = 0; i < mi->nr_in_set; i++)
		if (!bch_is_zero(mi->m[i].uuid.b, sizeof(uuid_le)))
			nr++;

	cache_member_info_put();

	return nr;
}

static unsigned cache_set_nr_online_devices(struct cache_set *c)
{
	unsigned i, nr = 0;

	for (i = 0; i < c->sb.nr_in_set; i++)
		if (c->cache[i])
			nr++;

	return nr;
}

static void bch_writes_disabled(struct percpu_ref *writes)
{
	struct cache_set *c = container_of(writes, struct cache_set, writes);
	complete(&c->write_disable_complete);
}

#define alloc_bucket_pages(gfp, ca)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(ca))))

static const char *bch_cache_set_alloc(struct cache_sb *sb,
				       struct cache_set **ret)
{
	const char *err = "cannot allocate memory";
	struct cache_set *c;
	unsigned i, iter_size;

	lockdep_assert_held(&bch_register_lock);

	c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
	if (!c)
		return err;

	__module_get(THIS_MODULE);
	closure_init(&c->cl, NULL);
	set_closure_fn(&c->cl, cache_set_free, system_wq);

	closure_init(&c->caching, &c->cl);
	set_closure_fn(&c->caching, __cache_set_unregister, system_wq);

	/* Maybe create continue_at_noreturn() and use it here? */
	closure_set_stopped(&c->cl);
	closure_put(&c->cl);

	c->kobj.kset = bcache_kset;
	kobject_init(&c->kobj, &bch_cache_set_ktype);
	kobject_init(&c->internal, &bch_cache_set_internal_ktype);

	bch_cache_accounting_init(&c->accounting, &c->cl);

	if (cache_sb_to_cache_set(c, sb))
		goto err;

	c->minor		= -1;
	c->block_bits		= ilog2(c->sb.block_size);
	c->btree_pages		= CACHE_BTREE_NODE_SIZE(&c->sb) / PAGE_SECTORS;

	sema_init(&c->sb_write_mutex, 1);
	INIT_RADIX_TREE(&c->devices, GFP_KERNEL);
	mutex_init(&c->btree_cache_lock);
	mutex_init(&c->bucket_lock);
	spin_lock_init(&c->btree_root_lock);
	init_completion(&c->write_disable_complete);
	INIT_WORK(&c->read_only_work, bch_cache_set_read_only_work);

	init_rwsem(&c->gc_lock);
	mutex_init(&c->gc_scan_keylist_lock);
	INIT_LIST_HEAD(&c->gc_scan_keylists);

	spin_lock_init(&c->mca_alloc_time.lock);
	spin_lock_init(&c->mca_scan_time.lock);
	spin_lock_init(&c->btree_gc_time.lock);
	spin_lock_init(&c->btree_coalesce_time.lock);
	spin_lock_init(&c->btree_split_time.lock);
	spin_lock_init(&c->btree_read_time.lock);
	spin_lock_init(&c->journal_full_time.lock);

	bch_open_buckets_init(c);
	bch_tiering_init_cache_set(c);

	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->cached_devs);
	INIT_LIST_HEAD(&c->btree_cache);
	INIT_LIST_HEAD(&c->btree_cache_freeable);
	INIT_LIST_HEAD(&c->btree_cache_freed);

	INIT_WORK(&c->bio_submit_work, bch_bio_submit_work);
	spin_lock_init(&c->bio_submit_lock);

	mutex_init(&c->uevent_lock);

	c->btree_flush_delay = 30;

	c->congested_read_threshold_us	= 2000;
	c->congested_write_threshold_us	= 20000;
	c->error_limit	= 16 << IO_ERROR_SHIFT;

	c->tiering_percent = 10;
	c->btree_scan_ratelimit = 30;

	c->copy_gc_enabled = 1;
	c->tiering_enabled = 1;

	c->gc_timeouts_enabled = 1;

	c->foreground_target_percent = 20;
	c->bucket_reserve_percent = 10;
	c->sector_reserve_percent = 20;

	c->prio_clock[READ].hand = 1;
	c->prio_clock[READ].min_prio = 0;
	c->prio_clock[WRITE].hand = 1;
	c->prio_clock[WRITE].min_prio = 0;

	bio_list_init(&c->read_race_list);
	spin_lock_init(&c->read_race_lock);
	INIT_WORK(&c->read_race_work, bch_read_race_work);

	seqlock_init(&c->gc_cur_lock);
	c->gc_cur_btree = BTREE_ID_NR;

	seqcount_init(&c->cache_all.lock);

	for (i = 0; i < ARRAY_SIZE(c->cache_tiers); i++)
		seqcount_init(&c->cache_tiers[i].lock);

	c->promote_write_point.group = &c->cache_tiers[0];
	c->promote_write_point.n_replicas = 1;
	c->promote_write_point.reserve = RESERVE_TIERING;

	c->migration_write_point.group = &c->cache_all;
	c->migration_write_point.n_replicas = 1;
	c->migration_write_point.reserve = RESERVE_NONE;

	c->gc_sector_percent = DFLT_CACHE_SET_GC_SECTOR_PERCENT;
	c->cache_reserve_percent = DFLT_CACHE_SET_CACHE_RESERVE_PERCENT;

	set_bit(CACHE_SET_CACHE_FULL_EXTENTS, &c->flags);

	c->search = mempool_create_slab_pool(32, bch_search_cache);
	if (!c->search)
		goto err;

	iter_size = (btree_blocks(c) + 1) *
		sizeof(struct btree_node_iter_set);

	if (!(c->bio_meta = mempool_create_kmalloc_pool(2,
				sizeof(struct bbio) + sizeof(struct bio_vec) *
				c->btree_pages)) ||
	    !(c->fill_iter = mempool_create_kmalloc_pool(1, iter_size)) ||
	    !(c->bio_split = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(c->wq = create_workqueue("bcache")) ||
	    !(c->prio_clock[READ].rescale_percpu = alloc_percpu(unsigned)) ||
	    !(c->prio_clock[WRITE].rescale_percpu = alloc_percpu(unsigned)) ||
	    percpu_ref_init(&c->writes, bch_writes_disabled) ||
	    bch_journal_alloc(c) ||
	    bch_btree_cache_alloc(c) ||
	    bch_bset_sort_state_init(&c->sort, ilog2(c->btree_pages)))
		goto err;

	c->uevent_env = kzalloc(sizeof(struct kobj_uevent_env), GFP_KERNEL);
	if (c->uevent_env == NULL)
		goto err;

	err = "error creating kobject";
	if (kobject_add(&c->kobj, NULL, "%pU", c->sb.user_uuid.b) ||
	    kobject_add(&c->internal, &c->kobj, "internal") ||
	    bch_cache_accounting_add_kobjs(&c->accounting, &c->kobj))
		goto err;

	list_add(&c->list, &bch_cache_sets);

	*ret = c;
	return NULL;
err:
	bch_cache_set_stop(c);
	return err;
}

static const char *__bch_cache_read_write(struct cache *ca);

const char *bch_run_cache_set(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct cache_member_rcu *mi;
	struct cached_dev *dc, *t;
	struct cache *ca;
	struct closure cl;
	unsigned i, id;
	long now;

	BUG_ON(test_bit(CACHE_SET_RUNNING, &c->flags));
	lockdep_assert_held(&bch_register_lock);

	closure_init_stack(&cl);

	/* We don't want bch_cache_set_error() to free underneath us */
	closure_get(&c->caching);

	/*
	 * Make sure that each cache object's mi is up to date before
	 * we start testing it.
	 */

	mi = cache_member_info_get(c);
	for_each_cache(ca, c, i)
		ca->mi = mi->m[ca->sb.nr_this_dev];
	cache_member_info_put();

	/*
	 * CACHE_SYNC is true if the cache set has already been run
	 * and potentially has data.
	 * It is false if it is the first time it is run.
	 */

	if (CACHE_SYNC(&c->sb)) {
		LIST_HEAD(journal);
		struct jset *j;

		err = bch_journal_read(c, &journal);
		if (err)
			goto err;

		pr_debug("btree_journal_read() done");

		j = &list_entry(journal.prev, struct journal_replay, list)->j;

		err = "error reading priorities";
		for_each_cache(ca, c, i)
			if (bch_prio_read(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		c->prio_clock[READ].hand = j->read_clock;
		c->prio_clock[WRITE].hand = j->write_clock;

		for_each_cache(ca, c, i) {
			bch_recalc_min_prio(ca, READ);
			bch_recalc_min_prio(ca, WRITE);
		}

		/*
		 * If bch_prio_read() fails it'll call cache_set_error and we'll
		 * tear everything down right away, but if we perhaps checked
		 * sooner we could avoid journal replay.
		 */

		for (id = 0; id < BTREE_ID_NR; id++) {
			unsigned level;
			struct bkey *k;

			err = "bad btree root";
			k = bch_journal_find_btree_root(c, j, id, &level);
			if (!k && id == BTREE_ID_EXTENTS)
				goto err;
			if (!k) {
				pr_debug("missing btree root: %d", id);
				continue;
			}

			err = "error reading btree root";
			if (bch_btree_root_read(c, id, k, level))
				goto err;
		}

		err = "error in recovery";
		if (bch_initial_gc(c, &journal))
			goto err;
		pr_debug("bch_initial_gc() done");

		/*
		 * bcache_journal_next() can't happen sooner, or
		 * btree_gc_finish() will give spurious errors about oldest_gen >
		 * bucket_gen - this is a hack but oh well.
		 */
		bch_journal_next(&c->journal);

		for_each_cache(ca, c, i)
			if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
			    (err = __bch_cache_read_write(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_journal_replay(c, &journal);
		set_bit(JOURNAL_REPLAY_DONE, &c->journal.flags);
	} else {
		struct bkey_i_inode inode;

		pr_notice("invalidating existing data");

		err = "unable to allocate journal buckets";
		for_each_cache(ca, c, i)
			if (bch_cache_journal_alloc(ca)) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_initial_gc(c, NULL);

		for_each_cache(ca, c, i)
			if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
			    (err = __bch_cache_read_write(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		err = "cannot allocate new btree root";
		for (id = 0; id < BTREE_ID_NR; id++)
			if (bch_btree_root_alloc(c, id, &cl))
				goto err;

		/*
		 * We don't want to write the first journal entry until
		 * everything is set up - fortunately journal entries won't be
		 * written until the SET_CACHE_SYNC() here:
		 */
		SET_CACHE_SYNC(&c->sb, true);
		set_bit(JOURNAL_REPLAY_DONE, &c->journal.flags);

		bch_journal_next(&c->journal);
		bch_journal_meta(c, &cl);

		bkey_inode_init(&inode.k);
		inode.k.p.inode = BCACHE_ROOT_INO;
		inode.v.i_mode = S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO;
		inode.v.i_nlink = 2;

		err = "error creating root directory";
		if (bch_inode_update(c, &inode.k))
			goto err;
	}

	err = "error starting btree GC thread";
	if (bch_gc_thread_start(c))
		goto err;

	for_each_cache(ca, c, i) {
		if (CACHE_STATE(&ca->mi) != CACHE_ACTIVE)
			continue;

		err = "error starting moving GC thread";
		if (bch_moving_gc_thread_start(ca)) {
			percpu_ref_put(&ca->ref);
			goto err;
		}
	}

	err = "error starting tiering thread";
	if (bch_tiering_read_start(c))
		goto err;

	schedule_delayed_work(&c->pd_controllers_update, 5 * HZ);

	closure_sync(&cl);

	now = get_seconds();
	mi = cache_member_info_get(c);
	for_each_cache_rcu(ca, c, i)
		mi->m[ca->sb.nr_this_dev].last_mount = now;
	cache_member_info_put();

	bcache_write_super(c);

	flash_devs_run(c);

	err = "error creating character device";
	if (bch_extent_store_init_cache_set(c))
		goto err;

	bch_debug_init_cache_set(c);

	err = "dynamic fault";
	if (cache_set_init_fault("run_cache_set"))
		goto err;

	set_bit(CACHE_SET_RUNNING, &c->flags);
	list_for_each_entry_safe(dc, t, &uncached_devices, list)
		bch_cached_dev_attach(dc, c);

	closure_put(&c->caching);

	bch_notify_cache_set_read_write(c);

	return NULL;
err:
	closure_sync(&cl);
	bch_cache_set_unregister(c);
	closure_put(&c->caching);
	return err;
}

static const char *can_add_cache(struct cache_sb *sb,
				 struct cache_set *c)
{
	if (sb->block_size != c->sb.block_size)
		return "mismatched block size";

	if (sb->members[le16_to_cpu(sb->nr_this_dev)].bucket_size <
	    c->btree_pages * PAGE_SECTORS)
		return "new cache bucket_size is too small";

	return NULL;
}

static const char *can_attach_cache(struct cache_sb *sb, struct cache_set *c)
{
	const char *err;
	struct cache_member_rcu *mi;
	bool match;

	err = can_add_cache(sb, c);
	if (err)
		return err;

	/*
	 * When attaching an existing device, the cache set superblock must
	 * already contain member_info with a matching UUID
	 */
	mi = cache_member_info_get(c);

	match = !(sb->seq <= c->sb.seq &&
		  (sb->nr_this_dev >= mi->nr_in_set ||
		   memcmp(&mi->m[sb->nr_this_dev].uuid,
			  &sb->disk_uuid,
			  sizeof(uuid_le))));

	cache_member_info_put();

	if (!match)
		return "cache sb does not match set";

	return NULL;
}

void bch_cache_set_close(struct cache_set *c)
{
	closure_put(&c->cl);
}
EXPORT_SYMBOL(bch_cache_set_close);

static struct cache_set *bch_cache_set_get(struct cache_set *c)
{
	lockdep_assert_held(&bch_register_lock);

	if (!c ||
	    !test_bit(CACHE_SET_RUNNING, &c->flags) ||
	    test_bit(CACHE_SET_STOPPING, &c->flags))
		return NULL;

	closure_get(&c->cl);
	return c;
}

struct cache_set *bch_cache_set_open(unsigned minor)
{
	struct cache_set *c;

	mutex_lock(&bch_register_lock);
	c = bch_cache_set_get(idr_find(&bch_cache_set_minor, minor));
	mutex_unlock(&bch_register_lock);

	return c;
}
EXPORT_SYMBOL(bch_cache_set_open);

struct cache_set *bch_cache_set_open_by_uuid(uuid_le *uuid)
{
	struct cache_set *c;

	mutex_lock(&bch_register_lock);

	list_for_each_entry(c, &bch_cache_sets, list)
		if (!memcmp(uuid, &c->sb.user_uuid, sizeof(*uuid))) {
			c = bch_cache_set_get(c);
			goto out;
		}

	c = NULL;
out:
	mutex_unlock(&bch_register_lock);

	return c;
}
EXPORT_SYMBOL(bch_cache_set_open_by_uuid);

/* Cache device */

static void __bch_cache_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member_rcu *mi = cache_member_info_get(c);
	struct cache_group *tier = &c->cache_tiers[
		CACHE_TIER(&mi->m[ca->sb.nr_this_dev])];
	struct task_struct *p;
	char buf[BDEVNAME_SIZE];

	cache_member_info_put();

	trace_bcache_cache_read_only(ca);

	bch_moving_gc_stop(ca);
	bch_tiering_write_stop(ca);

	/*
	 * These remove this cache device from the list from which new
	 * buckets can be allocated.
	 */
	bch_cache_group_remove_cache(tier, ca);
	bch_cache_group_remove_cache(&c->cache_all, ca);

	/*
	 * Stopping the allocator thread stops the writing of any
	 * prio/gen information to the device.
	 */
	p = ca->alloc_thread;
	ca->alloc_thread = NULL;
	smp_wmb();
	if (p)
		kthread_stop(p);

	bch_recalc_capacity(c);

	/*
	 * This stops new data writes (e.g. to existing open data
	 * buckets) and then waits for all existing writes to
	 * complete.
	 *
	 * The access (read) barrier is in bch_cache_percpu_ref_release.
	 */
	bch_stop_new_data_writes(ca);

	/*
	 * This will suspend the running task until outstanding writes complete.
	 */
	bch_await_scheduled_data_writes(ca);

	bch_notify_cache_read_only(ca);

	/*
	 * Device data write barrier -- no non-meta-data writes should
	 * occur after this point.  However, writes to btree buckets,
	 * journal buckets, and the superblock can still occur.
	 */
	trace_bcache_cache_read_only_done(ca);

	pr_notice("%s read only (data)", bdevname(ca->disk_sb.bdev, buf));
}

static bool bch_last_rw_tier0_device(struct cache *ca)
{
	unsigned i;
	bool ret = true;
	struct cache *ca2;

	rcu_read_lock();

	for_each_cache_rcu(ca2, ca->set, i) {
		if ((CACHE_TIER(&ca2->mi) == 0)
		    && (CACHE_STATE(&ca2->mi) == CACHE_ACTIVE)
		    && (ca2 != ca)) {
			ret = false;
		}
	}

	rcu_read_unlock();
	return ret;
}

/* This does not write the super-block, should it? */

void bch_cache_read_only(struct cache *ca)
{
	unsigned tier;
	bool has_meta, meta_off;
	char buf[BDEVNAME_SIZE];
	struct cache_member *mi;
	struct cache_member_rcu *allmi;

	/*
	 * Stop data writes.
	 */
	__bch_cache_read_only(ca);

	/*
	 * Mark as RO.
	 */
	allmi = cache_member_info_get(ca->set);
	mi = &allmi->m[ca->sb.nr_this_dev];
	tier = CACHE_TIER(mi);
	has_meta = CACHE_HAS_METADATA(mi);
	SET_CACHE_STATE(mi, CACHE_RO);
	ca->mi = *mi;		/* Update cache_member cache in struct cache */
	cache_member_info_put();

	meta_off = false;

	/*
	 * The only way to stop meta-data writes is to actually move
	 * the meta-data off!
	 */
	if (has_meta) {
		if ((tier == 0) && (bch_last_rw_tier0_device(ca)))
			pr_err("Tier 0 needs to allow meta-data writes in %pU.",
			       ca->set->sb.set_uuid.b);
		else if (bch_move_meta_data_off_device(ca) != 0)
			pr_err("Unable to stop writing meta-data in %pU.",
			       ca->set->sb.set_uuid.b);
		else
			meta_off = true;
	}

	if (has_meta && meta_off)
		pr_notice("%s read only (meta-data)",
			  bdevname(ca->disk_sb.bdev, buf));
	return;
}

static const char *__bch_cache_read_write(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member_rcu *mi = cache_member_info_get(c);
	struct cache_group *tier = &c->cache_tiers[
		CACHE_TIER(&mi->m[ca->sb.nr_this_dev])];
	const char *err;

	cache_member_info_put();

	trace_bcache_cache_read_write(ca);

	err = bch_cache_allocator_start(ca);
	if (err)
		return err;

	err = "error starting tiering write workqueue";
	if (bch_tiering_write_start(ca))
		return err;

	bch_cache_group_add_cache(tier, ca);
	bch_cache_group_add_cache(&c->cache_all, ca);

	bch_recalc_capacity(c);

	trace_bcache_cache_read_write_done(ca);

	return NULL;
}

/* This does not write the super-block, should it? */

const char *bch_cache_read_write(struct cache *ca)
{
	const char *err = __bch_cache_read_write(ca);

	if (err != NULL)
		return err;

	err = "error starting moving GC thread";
	if (!bch_moving_gc_thread_start(ca))
		err = NULL;

	wake_up_process(ca->set->tiering_read);

	bch_notify_cache_read_write(ca);

	return err;
}

/*
 * bch_cache_stop has already returned, so we no longer hold the register
 * lock at the point this is called.
 */

void bch_cache_release(struct kobject *kobj)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);

	kfree(ca);
}

static void bch_cache_free_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, free_work);
	struct cache_set *c = ca->set;
	char buf[BDEVNAME_SIZE];
	unsigned i;

	/*
	 * These test internally and skip if never initialized,
	 * hence we don't need to test here. However, we do need
	 * to unregister them before we drop our reference to
	 * @c.
	 */
	bch_moving_gc_destroy(ca);
	bch_tiering_write_destroy(ca);

	if (c && c->kobj.state_in_sysfs) {
		char buf[12];

		sprintf(buf, "cache%u", ca->sb.nr_this_dev);
		sysfs_remove_link(&c->kobj, buf);
		kobject_put(&c->kobj);
	}

	/*
	 * bch_cache_stop can be called in the middle of initialization
	 * of the struct cache object.
	 * As such, not all the sub-structures may be initialized.
	 * However, they were zeroed when the object was allocated.
	 */
	if (ca->replica_set != NULL)
		bioset_free(ca->replica_set);

	free_percpu(ca->bucket_stats_percpu);
	kfree(ca->journal.seq);
	free_pages((unsigned long) ca->disk_buckets, ilog2(bucket_pages(ca)));
	kfree(ca->prio_buckets);
	kfree(ca->bio_prio);
	vfree(ca->buckets);
	vfree(ca->bucket_gens);
	free_heap(&ca->heap);
	free_fifo(&ca->free_inc);

	for (i = 0; i < RESERVE_NR; i++)
		free_fifo(&ca->free[i]);

	if (ca->disk_sb.bdev)
		pr_notice("%s removed", bdevname(ca->disk_sb.bdev, buf));

	free_super(&ca->disk_sb);
	kobject_put(&ca->kobj);
}

static void bch_cache_percpu_ref_release(struct percpu_ref *ref)
{
	struct cache *ca = container_of(ref, struct cache, ref);

	/*
	 * Device access barrier -- no non-superblock accesses should occur
	 * after this point.
	 * The write barrier is in bch_cache_read_only.
	 *
	 * This results in bch_cache_release being called which
	 * frees up the storage.
	 */
	schedule_work(&ca->free_work);
}

static void bch_cache_free_rcu(struct rcu_head *rcu)
{
	struct cache *ca = container_of(rcu, struct cache, free_rcu);

	/*
	 * This decrements the ref count to ca, and once the ref count
	 * is 0 (outstanding bios to the ca also incremented it and
	 * decrement it on completion/error), bch_cache_percpu_ref_release
	 * is called, and that eventually results in bch_cache_free_work
	 * being called, which in turn results in bch_cache_release being
	 * called.
	 *
	 * In particular, these functions won't be called until there are no
	 * bios outstanding (the per-cpu ref counts are all 0), so it
	 * is safe to remove the actual sysfs device at that point,
	 * and that can indicate success to the user.
	 */

	percpu_ref_kill(&ca->ref);
}

static void bch_cache_stop(struct cache *ca)
{
	struct cache_set *c = ca->set;

	lockdep_assert_held(&bch_register_lock);

	if (c) {
		BUG_ON(rcu_access_pointer(c->cache[ca->sb.nr_this_dev]) != ca);
		rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], NULL);
	}

	call_rcu(&ca->free_rcu, bch_cache_free_rcu);
}

static void bch_cache_remove_work(struct work_struct *work)
{
	unsigned tier;
	bool has_data, has_meta, data_off, meta_off;
	struct cache *ca = container_of(work, struct cache, remove_work);
	struct cache_set *c = ca->set;
	struct cache_member_rcu *allmi;
	struct cache_member *mi;
	bool force = (test_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags));

	mutex_lock(&bch_register_lock);
	allmi = cache_member_info_get(c);
	mi = &allmi->m[ca->sb.nr_this_dev];

	/*
	 * Right now, we can't remove the last device from a tier,
	 * - For tier 0, because all metadata lives in tier 0 and because
	 *   there is no way to have foreground writes go directly to tier 1.
	 * - For tier 1, because the code doesn't completely support an
	 *   empty tier 1.
	 */

	tier = CACHE_TIER(mi);

	/*
	 * Turning a device read-only removes it from the cache group,
	 * so there may only be one read-write device in a tier, and yet
	 * the device we are removing is in the same tier, so we have
	 * to check for identity.
	 * Removing the last RW device from a tier requires turning the
	 * whole cache set RO.
	 */

	if ((c->cache_tiers[tier].nr_devices == 1)
	    && (c->cache_tiers[tier].devices[0] == ca)) {
		cache_member_info_put();
		mutex_unlock(&bch_register_lock);
		clear_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		pr_err("Can't remove last device in tier %u of %pU.",
		       tier, c->sb.set_uuid.b);
		return;
	}

	/* CACHE_ACTIVE means Read/Write. */

	if (CACHE_STATE(mi) != CACHE_ACTIVE) {
		has_data = CACHE_HAS_DATA(mi);
		cache_member_info_put();
	} else {
		cache_member_info_put();
		/*
		 * The following quiesces data writes but not meta-data writes.
		 */
		__bch_cache_read_only(ca);

		/* Update the state to read-only */

		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		SET_CACHE_STATE(mi, CACHE_RO);
		ca->mi = *mi;	/* Update cache_member cache in struct cache */
		has_data = CACHE_HAS_DATA(mi);
		cache_member_info_put();
		bcache_write_super(c);
	}

	mutex_unlock(&bch_register_lock);

	/*
	 * The call to __bch_cache_read_only above has quiesced all data writes.
	 * Move the data off the device, if there is any.
	 */

	data_off = (!has_data || (bch_move_data_off_device(ca) == 0));

	if (has_data && !data_off && force)
		/* Ignore the return value and proceed anyway */
		(void) bch_flag_data_bad(ca);

	allmi = cache_member_info_get(c);
	mi = &allmi->m[ca->sb.nr_this_dev];
	if (has_data && (data_off || force)) {
		/* We've just moved all the data off! */
		SET_CACHE_HAS_DATA(mi, false);
		/* Update cache_member cache in struct cache */
		ca->mi = *mi;
	}
	has_meta = CACHE_HAS_METADATA(mi);
	cache_member_info_put();

	/*
	 * If there is no meta data, claim it has been moved off.
	 * Else, try to move it off -- this also quiesces meta-data writes.
	 */

	meta_off = (!has_meta || (bch_move_meta_data_off_device(ca) == 0));

	/*
	 * If we successfully moved meta-data off, mark as having none.
	 */

	if (has_meta && meta_off) {
		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		/* We've just moved all the meta-data off! */
		SET_CACHE_HAS_METADATA(mi, false);
		/* Update cache_member cache in struct cache */
		ca->mi = *mi;
		cache_member_info_put();
	}

	/* Now, complain as necessary */

	/*
	 * Note: These error messages are messy because pr_err is a macro
	 * that concatenates its first must-be-string argument.
	 */

	if (has_data && !data_off)
		pr_err("%s in %pU%s",
		       (force
			? "Forcing device removal with live data"
			: "Unable to move data off device"),
		       c->sb.set_uuid.b,
		       (force ? "!" : "."));

	if (has_meta && !meta_off)
		pr_err("%s in %pU%s",
		       (force
			? "Forcing device removal with live meta-data"
			: "Unable to move meta-data off device"),
		       c->sb.set_uuid.b,
		       (force ? "!" : "."));

	/* If there is (meta-) data left, and not forcing, abort */

	if ((!data_off || !meta_off) && (!force)) {
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		return;
	}

	if (has_meta && meta_off) {
		char buf[BDEVNAME_SIZE];
		pr_notice("%s read only (meta-data)",
			  bdevname(ca->disk_sb.bdev, buf));
	}

	/* Update the super block */

	down(&c->sb_write_mutex);

	/* Mark it as failed in the super block */

	if (meta_off) {
		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		SET_CACHE_STATE(mi, CACHE_FAILED);
		/* Update cache_member cache in struct cache */
		ca->mi = *mi;
		cache_member_info_put();
	}

	__bcache_write_super(c); /* ups sb_write_mutex */

	/*
	 * Now mark the slot as 0 in memory so that the slot can be reused.
	 * It won't actually be reused until btree_gc makes sure that there
	 * are no pointers to the device at all.
	 */

	if (meta_off) {
		allmi = cache_member_info_get(c);
		mi = &allmi->m[ca->sb.nr_this_dev];
		memset(&mi->uuid, 0, sizeof(mi->uuid));
		/* No need to copy to struct cache as we are removing */
		cache_member_info_put();
	}

	/*
	 * This completes asynchronously, with bch_cache_stop scheduling
	 * the final teardown when there are no (read) bios outstanding.
	 */

	mutex_lock(&bch_register_lock);
	bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);

	bch_notify_cache_removed(ca);

	return;
}

bool bch_cache_remove(struct cache *ca, bool force)
{
	if (test_and_set_bit(CACHE_DEV_REMOVING, &ca->flags))
		return false;

	bch_notify_cache_removing(ca);

	if (force)
		set_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);

	queue_work(system_long_wq, &ca->remove_work);
	return true;
}

static const char *cache_alloc(struct bcache_superblock *sb,
			       struct cache_set *c,
			       struct cache **ret)
{
	struct cache_member_rcu *mi;
	size_t reserve_none, movinggc_reserve, free_inc_reserve, total_reserve;
	size_t heap_size;
	char buf[12];
	unsigned i;
	const char *err;
	struct cache *ca;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return "cannot allocate memory";

	if (percpu_ref_init(&ca->ref, bch_cache_percpu_ref_release)) {
		kfree(ca);
		return "cannot allocate memory";
	}

	kobject_init(&ca->kobj, &bch_cache_ktype);

	seqcount_init(&ca->self.lock);
	ca->self.nr_devices = 1;
	ca->self.devices[0] = ca;

	INIT_WORK(&ca->free_work, bch_cache_free_work);
	INIT_WORK(&ca->remove_work, bch_cache_remove_work);
	bio_init(&ca->journal.bio);
	ca->journal.bio.bi_max_vecs = 8;
	ca->journal.bio.bi_io_vec = ca->journal.bio.bi_inline_vecs;
	spin_lock_init(&ca->freelist_lock);
	spin_lock_init(&ca->prio_buckets_lock);
	mutex_init(&ca->heap_lock);

	ca->disk_sb = *sb;
	ca->disk_sb.bdev->bd_holder = ca;
	memset(sb, 0, sizeof(*sb));

	err = "dynamic fault";
	if (cache_set_init_fault("cache_alloc"))
		goto err;

	err = validate_super(&ca->disk_sb, &ca->sb);
	if (err)
		goto err;

	mi = cache_member_info_get(c);
	ca->mi = mi->m[ca->sb.nr_this_dev];
	cache_member_info_put();

	ca->bucket_bits = ilog2(ca->mi.bucket_size);

	err = "Invalid superblock: device too small";
	if (get_capacity(ca->disk_sb.bdev->bd_disk) <
	    ca->mi.bucket_size * ca->mi.nbuckets)
		goto err;

	err = "Invalid superblock: first bucket comes before end of super";
	if (ca->sb.offset +
	    (set_blocks(&ca->sb, block_bytes(c)) << c->block_bits) >
	    ca->mi.first_bucket << ca->bucket_bits)
		goto err;

	err = "bad journal bucket";
	for (i = 0; i < bch_nr_journal_buckets(&ca->sb); i++)
		if (journal_bucket(ca, i) <  ca->mi.first_bucket ||
		    journal_bucket(ca, i) >= ca->mi.nbuckets)
			goto err;

	/* XXX: tune these */
	movinggc_reserve = max_t(size_t, NUM_GC_GENS * 2,
				 ca->mi.nbuckets >> 7);
	reserve_none = max_t(size_t, 4, ca->mi.nbuckets >> 9);
	free_inc_reserve = reserve_none << 1;
	heap_size = max_t(size_t, free_inc_reserve, movinggc_reserve);

	err = "cannot allocate memory";
	for (i = 0; i < BTREE_ID_NR; i++)
		if (!init_fifo(&ca->free[i], BTREE_NODE_RESERVE, GFP_KERNEL))
			goto err;

	if (!init_fifo(&ca->free[RESERVE_PRIO], prio_buckets(ca), GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC_BTREE],
		       BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_TIERING_BTREE],
		       BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC],
		       movinggc_reserve, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_TIERING], 0, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_NONE], reserve_none, GFP_KERNEL) ||
	    !init_fifo(&ca->free_inc,	free_inc_reserve, GFP_KERNEL) ||
	    !init_heap(&ca->heap,	heap_size, GFP_KERNEL) ||
	    !(ca->bucket_gens	= vzalloc(sizeof(u8) *
					  ca->mi.nbuckets)) ||
	    !(ca->buckets	= vzalloc(sizeof(struct bucket) *
					  ca->mi.nbuckets)) ||
	    !(ca->prio_buckets	= kzalloc(sizeof(uint64_t) * prio_buckets(ca) *
					  2, GFP_KERNEL)) ||
	    !(ca->disk_buckets	= alloc_bucket_pages(GFP_KERNEL, ca)) ||
	    !(ca->replica_set = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(ca->bucket_stats_percpu = alloc_percpu(struct bucket_stats)) ||
	    !(ca->journal.seq	= kcalloc(bch_nr_journal_buckets(&ca->sb),
					  sizeof(u64), GFP_KERNEL)) ||
	    !(ca->bio_prio = bio_kmalloc(GFP_NOIO, bucket_pages(ca))))
		goto err;

	ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);

	total_reserve = ca->free_inc.size;
	for (i = 0; i < RESERVE_NR; i++)
		total_reserve += ca->free[i].size;
	pr_debug("%zu buckets reserved", total_reserve);

	for (i = 0; i < ARRAY_SIZE(ca->gc_buckets); i++) {
		ca->gc_buckets[i].n_replicas = 1;
		ca->gc_buckets[i].reserve = RESERVE_MOVINGGC;
		ca->gc_buckets[i].group = &ca->self;
	}

	ca->tiering_write_point.n_replicas = 1;
	ca->tiering_write_point.reserve = RESERVE_TIERING;
	ca->tiering_write_point.group = &ca->self;

	kobject_get(&c->kobj);
	ca->set = c;

	bch_moving_init_cache(ca);
	bch_tiering_init_cache(ca);

	sprintf(buf, "cache%u", ca->sb.nr_this_dev);

	err = "error creating kobject";
	if (kobject_add(&ca->kobj,
			&part_to_dev(ca->disk_sb.bdev->bd_part)->kobj,
			"bcache") ||
	    sysfs_create_link(&ca->kobj, &c->kobj, "set") ||
	    sysfs_create_link(&c->kobj, &ca->kobj, buf))
		goto err;

	kobject_get(&ca->kobj);
	rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], ca);

	if (ca->sb.seq > c->sb.seq)
		cache_sb_to_cache_set(c, ca->disk_sb.sb);

	*ret = ca;
	return NULL;
err:
	bch_cache_stop(ca);
	return err;
}

static const char *register_cache(struct bcache_superblock *sb,
				  struct cache_set **ret)
{
	char name[BDEVNAME_SIZE];
	const char *err;
	struct cache *ca;
	struct cache_set *c;

	mutex_lock(&bch_register_lock);

	list_for_each_entry(c, &bch_cache_sets, list)
		if (!memcmp(&c->sb.set_uuid, &sb->sb->set_uuid,
			    sizeof(uuid_le))) {
			if ((err = (can_attach_cache(sb->sb, c) ?:
				    cache_alloc(sb, c, &ca))))
				goto err;

			goto out;
		}

	err = bch_cache_set_alloc(sb->sb, &c);
	if (err)
		goto err;

	err = cache_alloc(sb, c, &ca);
	if (err)
		goto err_stop;
out:
	kobject_put(&ca->kobj);
	*ret = c;
	mutex_unlock(&bch_register_lock);

	pr_info("registered cache device %s", bdevname(ca->disk_sb.bdev, name));
	return NULL;
err_stop:
	bch_cache_set_stop(c);
err:
	mutex_unlock(&bch_register_lock);
	return err;
}

int bch_cache_set_add_cache(struct cache_set *c, const char *path)
{
	struct bcache_superblock sb;
	const char *err;
	struct cache *ca;
	struct cache_member_rcu *new_mi, *old_mi;
	struct cache_member mi;
	unsigned nr_this_dev, nr_in_set, u64s;
	int ret = -EINVAL;

	err = read_super(&sb, path);
	if (err)
		goto err;

	err = can_add_cache(sb.sb, c);
	if (err)
		goto err;

	/*
	 * Preserve the old cache member information (esp. tier)
	 * before we start bashing the disk stuff.
	 */
	mi = sb.sb->members[le16_to_cpu(sb.sb->nr_this_dev)];
	mi.last_mount = get_seconds();

	mutex_lock(&bch_register_lock);
	down_read(&c->gc_lock);
	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		goto no_slot;

	for (nr_this_dev = 0; nr_this_dev < MAX_CACHES_PER_SET; nr_this_dev++)
		if (!test_bit(nr_this_dev, c->cache_slots_used) &&
		    (nr_this_dev >= c->sb.nr_in_set ||
		     bch_is_zero(c->members->m[nr_this_dev].uuid.b, sizeof(uuid_le))))
			goto have_slot;
no_slot:
	up_read(&c->gc_lock);

	err = "no slots available in superblock";
	ret = -ENOSPC;
	goto err_unlock;

have_slot:
	nr_in_set = max_t(unsigned, nr_this_dev + 1, c->sb.nr_in_set);
	set_bit(nr_this_dev, c->cache_slots_used);
	up_read(&c->gc_lock);

	u64s = nr_in_set * (sizeof(struct cache_member) / sizeof(u64));
	err = "no space in superblock for member info";
	if (bch_super_realloc(&sb, u64s))
		goto err_unlock;

	sb.sb->nr_this_dev	= cpu_to_le16(nr_this_dev);
	sb.sb->nr_in_set	= cpu_to_le16(nr_in_set);
	sb.sb->u64s		= u64s;

	old_mi = c->members;
	new_mi = kzalloc(sizeof(struct cache_member_rcu) +
			 sizeof(struct cache_member) * nr_in_set,
			 GFP_KERNEL);
	if (!new_mi) {
		err = "cannot allocate memory";
		ret = -ENOMEM;
		goto err_put;
	}

	new_mi->nr_in_set = nr_in_set;
	memcpy(new_mi->m, old_mi->m,
	       c->sb.nr_in_set * sizeof(new_mi->m[0]));
	new_mi->m[nr_this_dev] = mi;

	memcpy(sb.sb->members, new_mi->m,
	       nr_in_set * sizeof(new_mi->m[0]));

	/* commit new member info */
	rcu_assign_pointer(c->members, new_mi);
	c->sb.nr_in_set = nr_in_set;

	kfree_rcu(old_mi, rcu);

	err = cache_alloc(&sb, c, &ca);
	if (err)
		goto err;

	bcache_write_super(c);

	err = "journal alloc failed";
	if (bch_cache_journal_alloc(ca))
		goto err_put;

	bch_notify_cache_added(ca);

	err = bch_cache_read_write(ca);
	if (err)
		goto err_put;

	kobject_put(&ca->kobj);
	mutex_unlock(&bch_register_lock);
	return 0;
err_put:
	kobject_put(&ca->kobj);
err_unlock:
	mutex_unlock(&bch_register_lock);
err:
	free_super(&sb);

	pr_err("Unable to add device: %s", err);
	return ret ?: -EINVAL;
}

const char *remove_bcache_device(char *path, bool force, struct cache_set *c)
{
	const char *err;
	struct cache *ca = NULL;
	struct block_device *bdev = NULL;
	int i;

	bdev = lookup_bdev(strim(path));
	if (IS_ERR(bdev))
		return "failed to open device, bad device name";

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i) {
		if (ca->disk_sb.bdev == bdev) {
			rcu_read_unlock();
			if (!bch_cache_remove(ca, force))
				err = "Unable to remove cache";
			else
				err = NULL;
			goto out;
		}
	}
	rcu_read_unlock();

	err = "Could not find cache for this path";
out:
	bdput(bdev);
	return err;
}

const char *set_disk_failed(uuid_le dev_uuid, struct cache_set *c)
{
	struct cache *ca;
	struct cache_member_rcu *mi;
	const char *err = NULL;
	int i;

	mutex_lock(&bch_register_lock);

	/*
	 * Find the disk which we are setting to failed,
	 * write_super will commit this updated state to
	 * disk for each cache in the cacheset.
	 */
	mi = cache_member_info_get(c);

	for (i = 0; i < c->sb.nr_in_set; i++) {
		struct cache_member *m = &mi->m[i];
		uuid_le tmp = m->uuid;

		if (!memcmp(&tmp, &dev_uuid, sizeof(dev_uuid))) {
			SET_CACHE_STATE(m, CACHE_FAILED);
			goto found;
		}
	}

	cache_member_info_put();
	mutex_unlock(&bch_register_lock);
	return "Unable to find device with this UUID";
found:

	if ((ca = rcu_dereference(c->cache[i])))
		percpu_ref_get(&ca->ref);

	cache_member_info_put();

	if (ca) {
		bch_cache_remove(ca, false);
		percpu_ref_put(&ca->ref);
	}

	bcache_write_super(c);
	mutex_unlock(&bch_register_lock);

	return err;
}

const char *register_bcache_devices(char **path, int count,
				    struct cache_set **c)
{
	const char *err;
	struct bcache_superblock sb;
	struct cached_dev **dc = NULL;
	uuid_le uuid;
	int i;

	memset(&sb, 0, sizeof(sb));
	memset(&uuid, 0, sizeof(uuid_le));

	err = "module unloading";
	if (!try_module_get(THIS_MODULE))
		return err;

	dc = kzalloc(sizeof(struct cached_dev *) * count, GFP_KERNEL);
	if (!dc)
		goto out;

	for (i = 0; i < count && path[i]; i++) {
		err = read_super(&sb, strim(path[i]));
		if (err)
			goto err;

		if (i == 0)
			uuid = sb.sb->set_uuid;

		err = "cache devices belong to different cache sets";
		if (memcmp(&sb.sb->set_uuid, &uuid, sizeof(uuid_le)))
			goto err;

		if (__SB_IS_BDEV(le64_to_cpu(sb.sb->version)))
			err = register_bdev(&sb, &dc[i]);
		else
			err = register_cache(&sb, c);

		if (err)
			goto err;
	}
out:
	kfree(dc);

	module_put(THIS_MODULE);
	return err;
err:
	for (i = 0; i < count; i++)
		if (dc[i])
			bcache_device_stop(&dc[i]->disk);

	if (*c)
		bch_cache_set_stop(*c);
	*c = NULL;
	free_super(&sb);
	goto out;
}

/* Global interfaces/init */

#define kobj_attribute_write(n, fn)					\
	static struct kobj_attribute ksysfs_##n = __ATTR(n, S_IWUSR, NULL, fn)

#define kobj_attribute_rw(n, show, store)				\
	static struct kobj_attribute ksysfs_##n =			\
		__ATTR(n, S_IWUSR|S_IRUSR, show, store)

static ssize_t register_bcache(struct kobject *, struct kobj_attribute *,
			       const char *, size_t);

kobj_attribute_write(register,		register_bcache);
kobj_attribute_write(register_quiet,	register_bcache);

static ssize_t register_bcache(struct kobject *k, struct kobj_attribute *attr,
			       const char *buffer, size_t size)
{
	ssize_t ret = -EINVAL;
	const char *err = "cannot allocate memory";
	char *path = NULL;
	struct cache_set *c = NULL;

	path = kstrndup(skip_spaces(buffer), size, GFP_KERNEL);
	if (!path)
		goto err;

	strim(path);

	err = register_bcache_devices(&path, 1, &c);
	if (err)
		goto err;

	if (c) {
		mutex_lock(&bch_register_lock);
		if (cache_set_nr_online_devices(c) == cache_set_nr_devices(c))
			err = bch_run_cache_set(c);
		mutex_unlock(&bch_register_lock);

		if (err)
			goto err;
	}

	ret = size;
out:
	kfree(path);
	return ret;
err:
	if (attr != &ksysfs_register_quiet)
		pr_info("error opening %s: %s", path, err);
	goto out;
}

static int bcache_reboot(struct notifier_block *n, unsigned long code, void *x)
{
	if (code == SYS_DOWN ||
	    code == SYS_HALT ||
	    code == SYS_POWER_OFF) {
		struct cache_set *c;

		mutex_lock(&bch_register_lock);

		if (!list_empty(&bch_cache_sets))
			pr_info("Setting all devices read only:");

		list_for_each_entry(c, &bch_cache_sets, list)
			bch_cache_set_read_only(c);

		mutex_unlock(&bch_register_lock);
	}

	return NOTIFY_DONE;
}

static struct notifier_block reboot = {
	.notifier_call	= bcache_reboot,
	.priority	= INT_MAX, /* before any real devices */
};

static ssize_t reboot_test(struct kobject *k, struct kobj_attribute *attr,
			   const char *buffer, size_t size)
{
	bcache_reboot(NULL, SYS_DOWN, NULL);
	return size;
}

kobj_attribute_write(reboot,		reboot_test);

static void bcache_exit(void)
{
	bch_debug_exit();
	bch_extent_store_exit();
	bch_fs_exit();
	bch_blockdev_exit();
	if (bcache_kset)
		kset_unregister(bcache_kset);
	if (bcache_io_wq)
		destroy_workqueue(bcache_io_wq);
	bch_chardev_exit();
	unregister_reboot_notifier(&reboot);
}

static int __init bcache_init(void)
{
	static const struct attribute *files[] = {
		&ksysfs_register.attr,
		&ksysfs_register_quiet.attr,
		&ksysfs_reboot.attr,
		NULL
	};
	int ret;

	mutex_init(&bch_register_lock);
	register_reboot_notifier(&reboot);

	ret = bch_chardev_init();
	if (ret)
		goto err;

	if (!(bcache_io_wq = create_workqueue("bcache_io")) ||
	    !(bcache_kset = kset_create_and_add("bcache", NULL, fs_kobj)) ||
	    sysfs_create_files(&bcache_kset->kobj, files) ||
	    bch_blockdev_init() ||
	    bch_fs_init() ||
	    bch_extent_store_init() ||
	    bch_debug_init())
		goto err;

	return 0;
err:
	bcache_exit();
	return -ENOMEM;
}

module_exit(bcache_exit);
module_init(bcache_init);
