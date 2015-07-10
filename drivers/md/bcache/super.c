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
#include "clock.h"
#include "debug.h"
#include "fs-gc.h"
#include "gc.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "migrate.h"
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

static int bch_chardev_major;
static struct class *bch_chardev_class;
static struct device *bch_chardev;
static DEFINE_IDR(bch_chardev_minor);

struct workqueue_struct *bcache_io_wq;

static void bch_cache_stop(struct cache *);
static int bch_cache_online(struct cache *);

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
	ret = bch_is_open_cache(bdev) || bch_is_open_backing_dev(bdev);
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

	bdev_get_queue(bdev)->backing_dev_info.capabilities |= BDI_CAP_STABLE_WRITES;

	*ret = bdev;
	return NULL;
}

static int bch_congested_fn(void *data, int bdi_bits)
{
	struct backing_dev_info *bdi;
	struct cache_set *c = data;
	struct cache *ca;
	unsigned i;
	int ret = 0;

	rcu_read_lock();
	if (bdi_bits & (1 << BDI_sync_congested)) {
		/* Reads - check all devices: */
		for_each_cache_rcu(ca, c, i) {
			bdi = blk_get_backing_dev_info(ca->disk_sb.bdev);

			if (bdi_congested(bdi, bdi_bits)) {
				ret = 1;
				break;
			}
		}
	} else {
		/* Writes only go to tier 0: */
		group_for_each_cache_rcu(ca, &c->cache_tiers[0], i) {
			bdi = blk_get_backing_dev_info(ca->disk_sb.bdev);

			if (bdi_congested(bdi, bdi_bits)) {
				ret = 1;
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
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

		if (!CACHE_SET_META_REPLICAS_HAVE(sb) ||
		    CACHE_SET_META_REPLICAS_HAVE(sb) >
		    CACHE_SET_META_REPLICAS_WANT(sb))
			return "Invalid number of metadata replicas";

		if (!CACHE_SET_DATA_REPLICAS_WANT(sb) ||
		    CACHE_SET_DATA_REPLICAS_WANT(sb) >= BKEY_EXTENT_PTRS_MAX)
			return "Invalid number of data replicas";

		if (!CACHE_SET_DATA_REPLICAS_HAVE(sb) ||
		    CACHE_SET_DATA_REPLICAS_HAVE(sb) >
		    CACHE_SET_DATA_REPLICAS_WANT(sb))
			return "Invalid number of data replicas";

		if (CACHE_SB_CSUM_TYPE(sb) >= BCH_CSUM_NR)
			return "Invalid checksum type";

		if (!CACHE_BTREE_NODE_SIZE(sb))
			return "Btree node size not set";

		if (!is_power_of_2(CACHE_BTREE_NODE_SIZE(sb)))
			return "Btree node size not a power of two";

		if (CACHE_BTREE_NODE_SIZE(sb) > BTREE_NODE_SIZE_MAX)
			return "Btree node size too large";

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

	bio = (dynamic_fault("bcache:add:super_realloc")
	       ? NULL
	       : bio_kmalloc(GFP_KERNEL, 1 << order));
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
	bio->bi_iter.bi_size	=
		roundup(set_bytes(sb),
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
	out->csum		=
		csum_set(out, sb->version < BCACHE_SB_VERSION_CDEV_V3
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
				       CACHE_META_PREFERRED_CSUM_TYPE(&c->sb));

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

void bch_check_mark_super_slowpath(struct cache_set *c, const struct bkey_i *k,
				   bool meta)
{
	struct cache_member *mi;
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(k);
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
		 : SET_CACHE_HAS_DATA)(mi + ptr->dev, true);

	cache_member_info_put();

	__bcache_write_super(c);
}

/* Cache set RO/RW: */

/*
 * For startup/shutdown of RW stuff, the dependencies are:
 *
 * - foreground writes depend on copygc and tiering (to free up space)
 *
 * - copygc and tiering depend on mark and sweep gc (they actually probably
 *   don't because they either reserve ahead of time or don't block if
 *   allocations fail, but allocations can require mark and sweep gc to run
 *   because of generation number wraparound)
 *
 * - all of the above depends on the allocator threads
 *
 * - allocator depends on the journal (when it rewrites prios and gens)
 */

static void __bch_cache_read_only(struct cache *ca);

static void __bch_cache_set_read_only(struct cache_set *c)
{
	struct closure cl;
	struct cache *ca;
	unsigned i;

	closure_init_stack(&cl);

	c->tiering_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&c->tiering_pd.rate);
	bch_tiering_read_stop(c);

	for_each_cache(ca, c, i) {
		bch_tiering_write_stop(ca);
		bch_moving_gc_stop(ca);
	}

	bch_gc_thread_stop(c);

	bch_btree_flush(c);

	for_each_cache(ca, c, i)
		bch_cache_allocator_stop(ca);

	bch_journal_flush(&c->journal, &cl);
	closure_sync(&cl);

	cancel_delayed_work_sync(&c->journal.write_work);
}

static void bch_writes_disabled(struct percpu_ref *writes)
{
	struct cache_set *c = container_of(writes, struct cache_set, writes);

	complete(&c->write_disable_complete);
}

void bch_cache_set_read_only(struct cache_set *c)
{
	lockdep_assert_held(&bch_register_lock);

	if (test_and_set_bit(CACHE_SET_RO, &c->flags))
		return;

	trace_bcache_cache_set_read_only(c);

	/*
	 * Block new foreground-end write operations from starting - any new
	 * writes will return -EROFS:
	 *
	 * (This is really blocking new _allocations_, writes to previously
	 * allocated space can still happen until stopping the allocator in
	 * bch_cache_allocator_stop()).
	 */
	init_completion(&c->write_disable_complete);
	percpu_ref_kill(&c->writes);

	bch_wake_delayed_writes((unsigned long) c);
	del_timer_sync(&c->foreground_write_wakeup);
	cancel_delayed_work_sync(&c->pd_controllers_update);

	/* Wait for outstanding writes to complete: */
	wait_for_completion(&c->write_disable_complete);

	__bch_cache_set_read_only(c);

	bch_notify_cache_set_read_only(c);
	trace_bcache_cache_set_read_only_done(c);
}

static const char *__bch_cache_set_read_write(struct cache_set *c)
{
	struct cache *ca;
	const char *err;
	unsigned i;

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

		err = "error starting tiering write workqueue";
		if (bch_tiering_write_start(ca))
			return err;
	}

	err = "error starting tiering thread";
	if (bch_tiering_read_start(c))
		goto err;

	schedule_delayed_work(&c->pd_controllers_update, 5 * HZ);

	return NULL;
err:
	__bch_cache_set_read_only(c);
	return err;
}

const char *bch_cache_set_read_write(struct cache_set *c)
{
	struct cache *ca;
	const char *err;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	if (!test_bit(CACHE_SET_RO, &c->flags))
		return NULL;

	for_each_cache(ca, c, i)
		if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
		    (err = bch_cache_allocator_start(ca))) {
			percpu_ref_put(&ca->ref);
			goto err;
		}

	err = __bch_cache_set_read_write(c);
	if (err)
		return err;

	percpu_ref_reinit(&c->writes);
	clear_bit(CACHE_SET_RO, &c->flags);

	return NULL;
err:
	__bch_cache_set_read_only(c);
	return err;
}

static void bch_cache_set_read_only_work(struct work_struct *work)
{
	struct cache_set *c =
		container_of(work, struct cache_set, read_only_work);

	mutex_lock(&bch_register_lock);
	bch_cache_set_read_only(c);
	mutex_unlock(&bch_register_lock);
}

/* Cache set startup/shutdown: */

void bch_cache_set_fail(struct cache_set *c)
{
	switch (c->opts.on_error_action) {
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

	if (c->stop_completion)
		complete(c->stop_completion);
	kfree(c);
	module_put(THIS_MODULE);
}

static void cache_set_free(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, cl);
	struct cache *ca;
	unsigned i;

	bch_btree_cache_free(c);
	bch_journal_free(&c->journal);

	mutex_lock(&bch_register_lock);
	for_each_cache(ca, c, i)
		bch_cache_stop(ca);
	mutex_unlock(&bch_register_lock);

	bch_bset_sort_state_free(&c->sort);

	kfree(c->members);
	percpu_ref_exit(&c->writes);
	bch_io_clock_exit(&c->io_clock[WRITE]);
	bch_io_clock_exit(&c->io_clock[READ]);
	bdi_destroy(&c->bdi);
	free_percpu(c->bio_decompress_worker);
	mempool_exit(&c->compression_workspace_pool);
	mempool_exit(&c->bio_bounce_pages);
	bioset_exit(&c->bio_write);
	bioset_exit(&c->bio_read);
	bioset_exit(&c->btree_read_bio);
	mempool_exit(&c->btree_reserve_pool);
	mempool_exit(&c->fill_iter);
	mempool_exit(&c->search);

	if (c->wq)
		destroy_workqueue(c->wq);

	mutex_lock(&bch_register_lock);
	list_del(&c->list);
	if (c->minor >= 0)
		idr_remove(&bch_chardev_minor, c->minor);
	mutex_unlock(&bch_register_lock);

	bch_notify_cache_set_stopped(c);

	pr_info("Cache set %pU unregistered", c->sb.set_uuid.b);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

static void cache_set_flush(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	bch_debug_exit_cache_set(c);

	if (!IS_ERR_OR_NULL(c->chardev))
		device_unregister(c->chardev);

	mutex_lock(&bch_register_lock);
	bch_cache_set_read_only(c);

	if (c->kobj.state_in_sysfs)
		kobject_del(&c->kobj);
	mutex_unlock(&bch_register_lock);

	bch_cache_accounting_destroy(&c->accounting);

	kobject_put(&c->internal);

	closure_return(cl);
}

static void __cache_set_unregister(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);

	bch_blockdevs_stop(c);

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

#define alloc_bucket_pages(gfp, ca)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(ca))))

static struct cache_set *bch_cache_set_alloc(struct cache_sb *sb,
					     struct cache_set_opts opts)
{
	struct cache_set *c;
	unsigned iter_size;
	int cpu;

	c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
	if (!c)
		return NULL;

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

	c->opts = (struct cache_set_opts) {
		   .read_only = 0,
		   .on_error_action = CACHE_ERROR_ACTION(&c->sb),
	};

	if (opts.read_only >= 0)
		c->opts.read_only = opts.read_only;
	if (opts.on_error_action >= 0)
		c->opts.on_error_action = opts.on_error_action;

	c->minor		= -1;
	c->block_bits		= ilog2(c->sb.block_size);

	sema_init(&c->sb_write_mutex, 1);
	INIT_RADIX_TREE(&c->devices, GFP_KERNEL);
	mutex_init(&c->btree_cache_lock);
	mutex_init(&c->bucket_lock);
	spin_lock_init(&c->btree_root_lock);
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

	bch_open_buckets_init(c);
	bch_tiering_init_cache_set(c);

	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->cached_devs);
	INIT_LIST_HEAD(&c->btree_cache);
	INIT_LIST_HEAD(&c->btree_cache_freeable);
	INIT_LIST_HEAD(&c->btree_cache_freed);

	mutex_init(&c->bio_bounce_pages_lock);
	INIT_WORK(&c->bio_submit_work, bch_bio_submit_work);
	spin_lock_init(&c->bio_submit_lock);
	bio_list_init(&c->read_race_list);
	spin_lock_init(&c->read_race_lock);
	INIT_WORK(&c->read_race_work, bch_read_race_work);

	seqcount_init(&c->gc_cur_lock);

	c->prio_clock[READ].hand = 1;
	c->prio_clock[READ].min_prio = 0;
	c->prio_clock[WRITE].hand = 1;
	c->prio_clock[WRITE].min_prio = 0;

	c->congested_read_threshold_us	= 2000;
	c->congested_write_threshold_us	= 20000;
	c->error_limit	= 16 << IO_ERROR_SHIFT;

	c->btree_flush_delay = 30;

	c->copy_gc_enabled = 1;
	c->tiering_enabled = 1;
	c->tiering_percent = 10;

	c->foreground_target_percent = 20;
	c->sector_reserve_percent = 20;

	mutex_init(&c->uevent_lock);

	iter_size = (btree_blocks(c) + 1) *
		sizeof(struct btree_node_iter_set);

	if (cache_set_init_fault("cache_set_alloc"))
		goto err;

	if (!(c->wq = create_workqueue("bcache")) ||
	    percpu_ref_init(&c->writes, bch_writes_disabled, 0, GFP_KERNEL) ||
	    mempool_init_slab_pool(&c->search, 1, bch_search_cache) ||
	    mempool_init_kmalloc_pool(&c->btree_reserve_pool, 1,
					BTREE_RESERVE_SIZE) ||
	    mempool_init_kmalloc_pool(&c->fill_iter, 1, iter_size) ||
	    bioset_init(&c->btree_read_bio, 1, offsetof(struct bbio, bio)) ||
	    bioset_init(&c->bio_read, 4, offsetof(struct bch_read_bio, bio.bio)) ||
	    bioset_init(&c->bio_write, 4, offsetof(struct bch_write_bio, bio.bio)) ||
	    mempool_init_page_pool(&c->bio_bounce_pages,
				   CRC32_EXTENT_SIZE_MAX / PAGE_SECTORS, 0) ||
	    mempool_init_page_pool(&c->compression_workspace_pool, 1,
				   get_order(COMPRESSION_WORKSPACE_SIZE)) ||
	    !(c->bio_decompress_worker = alloc_percpu(*c->bio_decompress_worker)) ||
	    bdi_setup_and_register(&c->bdi, "bcache") ||
	    bch_io_clock_init(&c->io_clock[READ]) ||
	    bch_io_clock_init(&c->io_clock[WRITE]) ||
	    bch_journal_alloc(&c->journal) ||
	    bch_btree_cache_alloc(c) ||
	    bch_bset_sort_state_init(&c->sort, ilog2(btree_pages(c))))
		goto err;

	for_each_possible_cpu(cpu) {
		struct bio_decompress_worker *d =
			per_cpu_ptr(c->bio_decompress_worker, cpu);

		INIT_WORK(&d->work, bch_bio_decompress_work);
		init_llist_head(&d->bio_list);
	}

	c->bdi.ra_pages		= VM_MAX_READAHEAD * 1024 / PAGE_CACHE_SIZE;
	c->bdi.congested_fn	= bch_congested_fn;
	c->bdi.congested_data	= c;
	c->bdi.capabilities	|= BDI_CAP_STABLE_WRITES;

	return c;
err:
	bch_cache_set_stop(c);
	return NULL;
}

static int bch_cache_set_online(struct cache_set *c)
{
	struct cache *ca;
	unsigned i;

	lockdep_assert_held(&bch_register_lock);

	c->minor = idr_alloc(&bch_chardev_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	c->chardev = device_create(bch_chardev_class, NULL,
				   MKDEV(bch_chardev_major, c->minor), NULL,
				   "bcache%u-ctl", c->minor);
	if (IS_ERR(c->chardev))
		return PTR_ERR(c->chardev);

	if (kobject_add(&c->kobj, NULL, "%pU", c->sb.user_uuid.b) ||
	    kobject_add(&c->internal, &c->kobj, "internal") ||
	    bch_cache_accounting_add_kobjs(&c->accounting, &c->kobj))
		return -1;

	for_each_cache(ca, c, i)
		if (bch_cache_online(ca)) {
			percpu_ref_put(&ca->ref);
			return -1;
		}

	list_add(&c->list, &bch_cache_sets);
	return 0;
}

static const char *run_cache_set(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct cache_member_rcu *mi;
	struct cache *ca;
	struct closure cl;
	unsigned i, id;
	long now;

	lockdep_assert_held(&bch_register_lock);
	BUG_ON(test_bit(CACHE_SET_RUNNING, &c->flags));

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
			struct bkey_i *k;

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
		 * bch_journal_start() can't happen sooner, or btree_gc_finish()
		 * will give spurious errors about oldest_gen > bucket_gen -
		 * this is a hack but oh well.
		 */
		bch_journal_start(c);

		for_each_cache(ca, c, i)
			if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
			    (err = bch_cache_allocator_start_once(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		bch_journal_replay(c, &journal);

		err = "error gcing inode nlinks";
		if (bch_gc_inode_nlinks(c))
			goto err;

		bch_verify_inode_refs(c);
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

		/*
		 * journal_res_get() will crash if called before this has
		 * set up the journal.pin FIFO and journal.cur pointer:
		 */
		bch_journal_start(c);
		bch_journal_set_replay_done(&c->journal);

		for_each_cache(ca, c, i)
			if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE &&
			    (err = bch_cache_allocator_start_once(ca))) {
				percpu_ref_put(&ca->ref);
				goto err;
			}

		err = "cannot allocate new btree root";
		for (id = 0; id < BTREE_ID_NR; id++)
			if (bch_btree_root_alloc(c, id, &cl))
				goto err;

		/* Wait for new btree roots to be written: */
		closure_sync(&cl);

		bkey_inode_init(&inode.k_i);
		inode.k.p.inode = BCACHE_ROOT_INO;
		inode.v.i_mode = S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO;
		inode.v.i_nlink = 2;

		err = "error creating root directory";
		if (bch_btree_insert(c, BTREE_ID_INODES,
				     &keylist_single(&inode.k_i),
				     NULL, NULL, NULL, 0))
			goto err;

		bch_journal_meta(&c->journal, &cl);
		closure_sync(&cl);

		/* Mark cache set as initialized: */
		SET_CACHE_SYNC(&c->sb, true);
	}

	bch_prio_timer_start(c, READ);
	bch_prio_timer_start(c, WRITE);

	if (c->opts.read_only) {
		bch_cache_set_read_only(c);
	} else {
		err = __bch_cache_set_read_write(c);
		if (err)
			goto err;
	}

	now = get_seconds();
	mi = cache_member_info_get(c);
	for_each_cache_rcu(ca, c, i)
		mi->m[ca->sb.nr_this_dev].last_mount = now;
	cache_member_info_put();

	bcache_write_super(c);

	bch_blockdev_volumes_start(c);

	bch_debug_init_cache_set(c);

	err = "dynamic fault";
	if (cache_set_init_fault("run_cache_set"))
		goto err;

	set_bit(CACHE_SET_RUNNING, &c->flags);
	bch_attach_backing_devs(c);

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
	    CACHE_BTREE_NODE_SIZE(&c->sb))
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

/* Cache device */

/*
 * Update the cache set's member info and then the various superblocks from one
 * device's member info:
 */
void bch_cache_member_info_update(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct cache_member *mi;

	lockdep_assert_held(&bch_register_lock);

	mi = cache_member_info_get(c)->m;
	mi[ca->sb.nr_this_dev] = ca->mi;
	cache_member_info_put();

	bcache_write_super(c);
}

static bool cache_may_remove(struct cache *ca)
{
	struct cache_set *c = ca->set;

	/*
	 * Right now, we can't remove the last device from a tier,
	 * - For tier 0, because all metadata lives in tier 0 and because
	 *   there is no way to have foreground writes go directly to tier 1.
	 * - For tier 1, because the code doesn't completely support an
	 *   empty tier 1.
	 */

	/*
	 * Turning a device read-only removes it from the cache group,
	 * so there may only be one read-write device in a tier, and yet
	 * the device we are removing is in the same tier, so we have
	 * to check for identity.
	 * Removing the last RW device from a tier requires turning the
	 * whole cache set RO.
	 */

	return c->cache_tiers[CACHE_TIER(&ca->mi)].nr_devices != 1 ||
		c->cache_tiers[CACHE_TIER(&ca->mi)].devices[0] != ca;
}

static void __bch_cache_read_only(struct cache *ca)
{
	trace_bcache_cache_read_only(ca);

	bch_tiering_write_stop(ca);
	bch_moving_gc_stop(ca);

	/*
	 * This stops new data writes (e.g. to existing open data
	 * buckets) and then waits for all existing writes to
	 * complete.
	 */
	bch_cache_allocator_stop(ca);

	/*
	 * Device data write barrier -- no non-meta-data writes should
	 * occur after this point.  However, writes to btree buckets,
	 * journal buckets, and the superblock can still occur.
	 */
	trace_bcache_cache_read_only_done(ca);
}

void bch_cache_read_only(struct cache *ca)
{
	struct cache_set *c = ca->set;
	char buf[BDEVNAME_SIZE];

	bdevname(ca->disk_sb.bdev, buf);

	lockdep_assert_held(&bch_register_lock);

	if (CACHE_STATE(&ca->mi) != CACHE_ACTIVE)
		return;

	if (!cache_may_remove(ca)) {
		pr_warning("Required member %s for %pU going RO, cache set going RO",
			   buf, &c->sb.set_uuid);
		bch_cache_set_read_only(c);
	}

	/*
	 * Stop data writes.
	 */
	__bch_cache_read_only(ca);

	pr_notice("%s read only", bdevname(ca->disk_sb.bdev, buf));
	bch_notify_cache_read_only(ca);

	SET_CACHE_STATE(&ca->mi, CACHE_RO);
	bch_cache_member_info_update(ca);
}

static void bch_cache_read_only_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, read_only_work);

	/* Going RO because of an error: */

	mutex_lock(&bch_register_lock);
	bch_cache_read_only(ca);
	mutex_unlock(&bch_register_lock);
}

static const char *__bch_cache_read_write(struct cache *ca)
{
	const char *err;

	BUG_ON(CACHE_STATE(&ca->mi) != CACHE_ACTIVE);
	lockdep_assert_held(&bch_register_lock);

	trace_bcache_cache_read_write(ca);

	err = bch_cache_allocator_start(ca);
	if (err)
		return err;

	err = "error starting tiering write workqueue";
	if (bch_tiering_write_start(ca))
		return err;

	trace_bcache_cache_read_write_done(ca);

	return NULL;

	err = "error starting moving GC thread";
	if (!bch_moving_gc_thread_start(ca))
		err = NULL;

	wake_up_process(ca->set->tiering_read);

	bch_notify_cache_read_write(ca);

	return err;
}

const char *bch_cache_read_write(struct cache *ca)
{
	const char *err;

	lockdep_assert_held(&bch_register_lock);

	if (CACHE_STATE(&ca->mi) == CACHE_ACTIVE)
		return NULL;

	if (test_bit(CACHE_DEV_REMOVING, &ca->flags))
		return "removing";

	err = __bch_cache_read_write(ca);
	if (err)
		return err;

	SET_CACHE_STATE(&ca->mi, CACHE_ACTIVE);
	bch_cache_member_info_update(ca);

	return NULL;
}

/*
 * bch_cache_stop has already returned, so we no longer hold the register
 * lock at the point this is called.
 */

void bch_cache_release(struct kobject *kobj)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);

	percpu_ref_exit(&ca->ref);
	kfree(ca);
}

static void bch_cache_free_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, free_work);
	struct cache_set *c = ca->set;
	unsigned i;

	/*
	 * These test internally and skip if never initialized,
	 * hence we don't need to test here. However, we do need
	 * to unregister them before we drop our reference to
	 * @c.
	 */
	bch_moving_gc_destroy(ca);
	bch_tiering_write_destroy(ca);

	if (c) {
		mutex_lock(&bch_register_lock);
		if (c->kobj.state_in_sysfs) {
			char buf[12];

			sprintf(buf, "cache%u", ca->sb.nr_this_dev);
			sysfs_remove_link(&c->kobj, buf);
		}
		mutex_unlock(&bch_register_lock);

		kobject_put(&c->kobj);
	}

	/*
	 * bch_cache_stop can be called in the middle of initialization
	 * of the struct cache object.
	 * As such, not all the sub-structures may be initialized.
	 * However, they were zeroed when the object was allocated.
	 */

	bioset_exit(&ca->replica_set);
	free_percpu(ca->bucket_stats_percpu);
	kfree(ca->journal.bucket_seq);
	free_pages((unsigned long) ca->disk_buckets, ilog2(bucket_pages(ca)));
	kfree(ca->prio_buckets);
	kfree(ca->bio_prio);
	vfree(ca->buckets);
	vfree(ca->bucket_gens);
	free_heap(&ca->heap);
	free_fifo(&ca->free_inc);

	for (i = 0; i < RESERVE_NR; i++)
		free_fifo(&ca->free[i]);

	free_super(&ca->disk_sb);

	if (ca->kobj.state_in_sysfs)
		kobject_del(&ca->kobj);

	kobject_put(&ca->kobj);
}

static void bch_cache_percpu_ref_release(struct percpu_ref *ref)
{
	struct cache *ca = container_of(ref, struct cache, ref);

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
	struct cache *ca = container_of(work, struct cache, remove_work);
	struct cache_set *c = ca->set;
	struct cache_member *mi;
	char name[BDEVNAME_SIZE];
	bool force = test_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);
	unsigned dev = ca->sb.nr_this_dev;
	struct closure cl;

	closure_init_stack(&cl);
	bdevname(ca->disk_sb.bdev, name);

	/*
	 * Device should already be RO, now migrate data off:
	 *
	 * XXX: locking is sketchy, bch_cache_read_write() has to check
	 * CACHE_DEV_REMOVING bit
	 */
	if (!CACHE_HAS_DATA(&ca->mi)) {
		/* Nothing to do: */
	} else if (!bch_move_data_off_device(ca)) {
		SET_CACHE_HAS_DATA(&ca->mi, false);
		bch_cache_member_info_update(ca);
	} else if (force) {
		bch_flag_data_bad(ca);

		SET_CACHE_HAS_DATA(&ca->mi, false);
		bch_cache_member_info_update(ca);
	} else {
		pr_err("Remove of %s failed, unable to migrate data off", name);
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		return;
	}

	/* Now metadata: */

	if (!CACHE_HAS_METADATA(&ca->mi)) {
		/* Nothing to do: */
	} else if (!bch_move_meta_data_off_device(ca)) {
		SET_CACHE_HAS_METADATA(&ca->mi, false);
		bch_cache_member_info_update(ca);
	} else {
		pr_err("Remove of %s failed, unable to migrate metadata off",
		       name);
		clear_bit(CACHE_DEV_REMOVING, &ca->flags);
		return;
	}

	/*
	 * Ok, really doing the remove:
	 * Drop device's prio pointer before removing it from superblock:
	 */
	bch_notify_cache_removed(ca);

	spin_lock(&c->journal.lock);
	c->journal.prio_buckets[dev] = 0;
	spin_unlock(&c->journal.lock);

	bch_journal_meta(&c->journal, &cl);
	closure_sync(&cl);

	/*
	 * Stop device before removing it from the cache set's list of devices -
	 * and get our own ref on cache set since ca is going away:
	 */
	closure_get(&c->cl);

	mutex_lock(&bch_register_lock);
	bch_cache_stop(ca);

	/*
	 * RCU barrier between dropping between c->cache and dropping from
	 * member info:
	 */
	synchronize_rcu();

	mi = cache_member_info_get(c)->m;
	memset(&mi[dev].uuid, 0, sizeof(mi[dev].uuid));
	cache_member_info_put();

	bcache_write_super(c);
	mutex_unlock(&bch_register_lock);

	closure_put(&c->cl);
}

bool bch_cache_remove(struct cache *ca, bool force)
{
	mutex_lock(&bch_register_lock);

	if (test_bit(CACHE_DEV_REMOVING, &ca->flags))
		return false;

	if (!cache_may_remove(ca)) {
		pr_err("Can't remove last device in tier %llu of %pU.",
		       CACHE_TIER(&ca->mi), ca->set->sb.set_uuid.b);
		bch_notify_cache_remove_failed(ca);
		return false;
	}

	/* First, go RO before we try to migrate data off: */
	bch_cache_read_only(ca);

	if (force)
		set_bit(CACHE_DEV_FORCE_REMOVE, &ca->flags);
	set_bit(CACHE_DEV_REMOVING, &ca->flags);
	bch_notify_cache_removing(ca);

	mutex_unlock(&bch_register_lock);

	/* Migrate the data and finish removal asynchronously: */

	queue_work(system_long_wq, &ca->remove_work);
	return true;
}

static int bch_cache_online(struct cache *ca)
{
	char buf[12];

	lockdep_assert_held(&bch_register_lock);

	sprintf(buf, "cache%u", ca->sb.nr_this_dev);

	if (kobject_add(&ca->kobj,
			&part_to_dev(ca->disk_sb.bdev->bd_part)->kobj,
			"bcache") ||
	    sysfs_create_link(&ca->kobj, &ca->set->kobj, "set") ||
	    sysfs_create_link(&ca->set->kobj, &ca->kobj, buf))
		return -1;

	return 0;
}

static const char *cache_alloc(struct bcache_superblock *sb,
			       struct cache_set *c,
			       struct cache **ret)
{
	struct cache_member_rcu *mi;
	size_t reserve_none, movinggc_reserve, free_inc_reserve, total_reserve;
	size_t heap_size;
	unsigned i;
	const char *err = "cannot allocate memory";
	struct cache *ca;

	if (cache_set_init_fault("cache_alloc"))
		return err;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		return err;

	if (percpu_ref_init(&ca->ref, bch_cache_percpu_ref_release,
			    0, GFP_KERNEL)) {
		kfree(ca);
		return err;
	}

	kobject_init(&ca->kobj, &bch_cache_ktype);

	seqcount_init(&ca->self.lock);
	ca->self.nr_devices = 1;
	ca->self.devices[0] = ca;

	INIT_WORK(&ca->free_work, bch_cache_free_work);
	INIT_WORK(&ca->read_only_work, bch_cache_read_only_work);
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

	INIT_WORK(&ca->io_error_work, bch_cache_io_error_work);

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

	if (!init_fifo(&ca->free[RESERVE_PRIO], prio_buckets(ca), GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_BTREE], BTREE_NODE_RESERVE, GFP_KERNEL) ||
	    !init_fifo(&ca->free[RESERVE_MOVINGGC],
		       movinggc_reserve, GFP_KERNEL) ||
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
	    !(ca->bucket_stats_percpu = alloc_percpu(struct bucket_stats)) ||
	    !(ca->journal.bucket_seq = kcalloc(bch_nr_journal_buckets(&ca->sb),
					       sizeof(u64), GFP_KERNEL)) ||
	    !(ca->bio_prio = bio_kmalloc(GFP_NOIO, bucket_pages(ca))) ||
	    bioset_init(&ca->replica_set, 4,
			offsetof(struct bch_write_bio, bio.bio)))
		goto err;

	ca->prio_last_buckets = ca->prio_buckets + prio_buckets(ca);

	total_reserve = ca->free_inc.size;
	for (i = 0; i < RESERVE_NR; i++)
		total_reserve += ca->free[i].size;
	pr_debug("%zu buckets reserved", total_reserve);

	for (i = 0; i < ARRAY_SIZE(ca->gc_buckets); i++) {
		ca->gc_buckets[i].nr_replicas = 1;
		ca->gc_buckets[i].reserve = RESERVE_MOVINGGC;
		ca->gc_buckets[i].group = &ca->self;
	}

	ca->tiering_write_point.nr_replicas = 1;
	ca->tiering_write_point.reserve = RESERVE_NONE;
	ca->tiering_write_point.group = &ca->self;

	kobject_get(&c->kobj);
	ca->set = c;

	kobject_get(&ca->kobj);
	rcu_assign_pointer(c->cache[ca->sb.nr_this_dev], ca);

	bch_moving_init_cache(ca);
	bch_tiering_init_cache(ca);

	if (ca->sb.seq > c->sb.seq)
		cache_sb_to_cache_set(c, ca->disk_sb.sb);

	err = "error creating kobject";
	if (c->kobj.state_in_sysfs &&
	    bch_cache_online(ca))
		goto err;

	if (ret)
		*ret = ca;
	else
		kobject_put(&ca->kobj);
	return NULL;
err:
	bch_cache_stop(ca);
	return err;
}

static struct cache_set *cache_set_lookup(uuid_le uuid)
{
	struct cache_set *c;

	lockdep_assert_held(&bch_register_lock);

	list_for_each_entry(c, &bch_cache_sets, list)
		if (!memcmp(&c->sb.set_uuid, &uuid, sizeof(uuid_le)))
			return c;

	return NULL;
}

static const char *register_cache(struct bcache_superblock *sb,
				  struct cache_set_opts opts)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";
	struct cache_set *c;

	bdevname(sb->bdev, name);

	mutex_lock(&bch_register_lock);
	c = cache_set_lookup(sb->sb->set_uuid);
	if (c) {
		if ((err = (can_attach_cache(sb->sb, c) ?:
			    cache_alloc(sb, c, NULL))))
			goto err;

		if (cache_set_nr_online_devices(c) == cache_set_nr_devices(c)) {
			err = run_cache_set(c);
			if (err)
				goto err;
		}
		goto out;
	}

	c = bch_cache_set_alloc(sb->sb, opts);
	if (!c)
		goto err;

	err = cache_alloc(sb, c, NULL);
	if (err)
		goto err_stop;

	if (cache_set_nr_online_devices(c) == cache_set_nr_devices(c)) {
		err = run_cache_set(c);
		if (err)
			goto err_stop;
	}

	err = "error creating kobject";
	if (bch_cache_set_online(c))
		goto err_stop;
out:
	mutex_unlock(&bch_register_lock);

	pr_info("registered cache device %s", name);
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

	if (dynamic_fault("bcache:add:no_slot"))
		goto no_slot;

	if (test_bit(CACHE_SET_GC_FAILURE, &c->flags))
		goto no_slot;

	for (nr_this_dev = 0; nr_this_dev < MAX_CACHES_PER_SET; nr_this_dev++)
		if (!test_bit(nr_this_dev, c->cache_slots_used) &&
		    (nr_this_dev >= c->sb.nr_in_set ||
		     bch_is_zero(c->members->m[nr_this_dev].uuid.b,
				 sizeof(uuid_le))))
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
	new_mi = (dynamic_fault("bcache:add:member_info_realloc")
		  ? NULL
		  : kzalloc(sizeof(struct cache_member_rcu) +
			    sizeof(struct cache_member) * nr_in_set,
			    GFP_KERNEL));
	if (!new_mi) {
		err = "cannot allocate memory";
		ret = -ENOMEM;
		goto err_unlock;
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
		goto err_unlock;

	bcache_write_super(c);

	err = "journal alloc failed";
	if (bch_cache_journal_alloc(ca))
		goto err_put;

	bch_notify_cache_added(ca);

	err = __bch_cache_read_write(ca);
	if (err)
		goto err_put;

	kobject_put(&ca->kobj);
	mutex_unlock(&bch_register_lock);
	return 0;
err_put:
	bch_cache_stop(ca);
err_unlock:
	mutex_unlock(&bch_register_lock);
err:
	free_super(&sb);

	pr_err("Unable to add device: %s", err);
	return ret ?: -EINVAL;
}

const char *bch_register_cache_set(char * const *devices, unsigned nr_devices,
				   struct cache_set_opts opts,
				   struct cache_set **ret)
{
	const char *err;
	struct cache_set *c = NULL;
	struct bcache_superblock *sb;
	uuid_le uuid;
	unsigned i;

	memset(&uuid, 0, sizeof(uuid_le));

	if (!nr_devices)
		return "need at least one device";

	if (!try_module_get(THIS_MODULE))
		return "module unloading";

	err = "cannot allocate memory";
	sb = kcalloc(nr_devices, sizeof(*sb), GFP_KERNEL);
	if (!sb)
		goto err;

	for (i = 0; i < nr_devices; i++) {
		err = read_super(&sb[i], devices[i]);
		if (err)
			goto err;

		err = "attempting to register backing device";
		if (__SB_IS_BDEV(le64_to_cpu(sb[i].sb->version)))
			goto err;
	}

	err = "cache set already registered";
	mutex_lock(&bch_register_lock);
	if (cache_set_lookup(sb->sb->set_uuid))
		goto err;

	err = "cannot allocate memory";
	c = bch_cache_set_alloc(sb[0].sb, opts);
	if (!c)
		goto err_unlock;

	for (i = 0; i < nr_devices; i++) {
		err = cache_alloc(&sb[i], c, NULL);
		if (err)
			goto err_unlock;
	}

	err = "insufficient devices";
	if (cache_set_nr_online_devices(c) != cache_set_nr_devices(c))
		goto err_unlock;

	err = run_cache_set(c);
	if (err)
		goto err_unlock;

	err = "error creating kobject";
	if (bch_cache_set_online(c))
		goto err_unlock;

	if (ret) {
		closure_get(&c->cl);
		*ret = c;
	}

	mutex_unlock(&bch_register_lock);

	err = NULL;
out:
	kfree(sb);
	module_put(THIS_MODULE);
	return err;
err_unlock:
	if (c)
		bch_cache_set_stop(c);
	mutex_unlock(&bch_register_lock);
err:
	for (i = 0; i < nr_devices; i++)
		free_super(&sb[i]);
	goto out;
}

const char *bch_register_one(const char *path)
{
	struct bcache_superblock sb;
	const char *err;

	err = read_super(&sb, path);
	if (err)
		return err;

	if (__SB_IS_BDEV(le64_to_cpu(sb.sb->version))) {
		mutex_lock(&bch_register_lock);
		err = bch_backing_dev_register(&sb);
		mutex_unlock(&bch_register_lock);
	} else {
		err = register_cache(&sb, cache_set_opts_empty());
	}

	free_super(&sb);
	return err;
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

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	if (!(path = kstrndup(skip_spaces(buffer), size, GFP_KERNEL)))
		goto err;

	err = bch_register_one(strim(path));
	if (err)
		goto err;

	ret = size;
out:
	kfree(path);
	module_put(THIS_MODULE);
	return ret;
err:
	if (attr != &ksysfs_register_quiet)
		pr_err("error opening %s: %s", path, err);
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
	bch_fs_exit();
	bch_blockdev_exit();
	if (bcache_kset)
		kset_unregister(bcache_kset);
	if (bcache_io_wq)
		destroy_workqueue(bcache_io_wq);
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		device_destroy(bch_chardev_class,
			       MKDEV(bch_chardev_major, 0));
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		class_destroy(bch_chardev_class);
	if (bch_chardev_major > 0)
		unregister_chrdev(bch_chardev_major, "bcache");
	unregister_reboot_notifier(&reboot);
}

static const struct file_operations bch_chardev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch_chardev_ioctl,
	.open		= nonseekable_open,
};

static int __init bcache_init(void)
{
	static const struct attribute *files[] = {
		&ksysfs_register.attr,
		&ksysfs_register_quiet.attr,
		&ksysfs_reboot.attr,
		NULL
	};

	mutex_init(&bch_register_lock);
	register_reboot_notifier(&reboot);
	closure_debug_init();
	bkey_pack_test();

	bch_chardev_major = register_chrdev(0, "bcache-ctl", &bch_chardev_fops);
	if (bch_chardev_major < 0)
		goto err;

	bch_chardev_class = class_create(THIS_MODULE, "bcache");
	if (IS_ERR(bch_chardev_class))
		goto err;

	bch_chardev = device_create(bch_chardev_class, NULL,
				    MKDEV(bch_chardev_major, 255),
				    NULL, "bcache-ctl");
	if (IS_ERR(bch_chardev))
		goto err;

	if (!(bcache_io_wq = create_workqueue("bcache_io")) ||
	    !(bcache_kset = kset_create_and_add("bcache", NULL, fs_kobj)) ||
	    sysfs_create_files(&bcache_kset->kobj, files) ||
	    bch_blockdev_init() ||
	    bch_fs_init() ||
	    bch_debug_init())
		goto err;

	return 0;
err:
	bcache_exit();
	return -ENOMEM;
}

module_exit(bcache_exit);
module_init(bcache_init);
