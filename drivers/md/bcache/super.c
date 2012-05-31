
#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "request.h"
#include "sysfs.h"

#include <linux/buffer_head.h>
#include <linux/debugfs.h>
#include <linux/genhd.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/sort.h>
#include <linux/sysfs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kent Overstreet <kent.overstreet@gmail.com>");

static const char bcache_magic[] = {
	0xc6, 0x85, 0x73, 0xf6, 0x4e, 0x1a, 0x45, 0xca,
	0x82, 0x65, 0xf5, 0x7f, 0x48, 0xba, 0x6d, 0x81
};

static const char invalid_uuid[] = {
	0xa0, 0x3e, 0xf8, 0xed, 0x3e, 0xe1, 0xb8, 0x78,
	0xc8, 0x50, 0xfc, 0x5e, 0xcb, 0x16, 0xcd, 0x99
};

/* Default is -1; we skip past it for struct cached_dev's cache mode */
const char * const bcache_cache_modes[] = {
	"default",
	"writethrough",
	"writeback",
	"writearound",
	"none",
	NULL
};

static const char * const cache_replacement_policies[] = {
	"lru",
	"fifo",
	"random",
	NULL
};

struct uuid_entry_v0 {
	uint8_t		uuid[16];
	uint8_t		label[32];
	uint32_t	first_reg;
	uint32_t	last_reg;
	uint32_t	invalidated;
	uint32_t	pad;
};

struct uuid_entry {
	union {
		struct {
			uint8_t		uuid[16];
			uint8_t		label[32];
			uint32_t	first_reg;
			uint32_t	last_reg;
			uint32_t	invalidated;

			uint32_t	flags;
			/* Size of flash only volumes */
			uint64_t	sectors;
		};

		uint8_t	pad[128];
	};
};

BITMASK(UUID_FLASH_ONLY,	struct uuid_entry, flags, 0, 1);

/* We keep absolute totals of various statistics, and addionally a set of three
 * rolling averages.
 *
 * Every so often, a timer goes off and rescales the rolling averages.
 * accounting_rescale[] is how many times the timer has to go off before we
 * rescale each set of numbers; that gets us half lives of 5 minutes, one hour,
 * and one day.
 *
 * accounting_delay is how often the timer goes off - 22 times in 5 minutes,
 * and accounting_weight is what we use to rescale:
 *
 * pow(31 / 32, 22) ~= 1/2
 *
 * So that we don't have to increment each set of numbers every time we (say)
 * get a cache hit, we increment a single atomic_t and when the rescale
 * function it runs it resets the atomic counter to 0 and adds its old value to
 * each of the exported numbers.
 *
 * To reduce rounding error, the numbers in struct cache_accounting are all
 * stored left shifted by 16, and scaled back in the sysfs show() function.
 */

static const unsigned accounting_rescale[]	= { 0, 1, 12, 288 };
static const unsigned accounting_delay		= (HZ * 300) / 22;
static const unsigned accounting_weight		= 32;

static const char * const accounting_types[]	= {
	"total", "five_minute", "hour", "day" };

static struct kobject *bcache_kobj;
static struct mutex register_lock;
static LIST_HEAD(uncached_devices);
static LIST_HEAD(cache_sets);
static int bcache_major, bcache_minor;
static wait_queue_head_t unregister_wait;

struct workqueue_struct *bcache_wq;

static int uuid_write(struct cache_set *);
static void bcache_device_stop(struct bcache_device *);

static void __cached_dev_free(struct kobject *);
static void cached_dev_run(struct cached_dev *);
static int cached_dev_attach(struct cached_dev *, struct cache_set *);
static void cached_dev_detach(struct cached_dev *);

static void __flash_dev_free(struct kobject *);
static int flash_dev_create(struct cache_set *c, uint64_t size);

static void __cache_set_free(struct kobject *);
static void cache_set_unregister(struct cache_set *);
static void cache_set_stop(struct cache_set *);
static void bcache_write_super(struct cache_set *);

static void cache_free(struct kobject *);

#include "sysfs.c"

#define BTREE_MAX_PAGES		(256 * 1024 / PAGE_SIZE)

/* Superblock */

static const char *read_super(struct cache_sb *sb, struct block_device *bdev,
			      struct page **res)
{
	const char *err;
	struct cache_sb *s;
	struct buffer_head *bh = __bread(bdev, 1, SB_SIZE);

	if (!bh)
		return "IO error";

	s = (struct cache_sb *) bh->b_data;

	sb->offset		= le64_to_cpu(s->offset);
	sb->version		= le64_to_cpu(s->version);

	memcpy(sb->magic,	s->magic, 16);
	memcpy(sb->uuid,	s->uuid, 16);
	memcpy(sb->set_uuid,	s->set_uuid, 16);
	memcpy(sb->label,	s->label, SB_LABEL_SIZE);

	sb->flags		= le64_to_cpu(s->flags);
	sb->seq			= le64_to_cpu(s->seq);

	sb->nbuckets		= le64_to_cpu(s->nbuckets);
	sb->block_size		= le16_to_cpu(s->block_size);
	sb->bucket_size		= le16_to_cpu(s->bucket_size);

	sb->nr_in_set		= le16_to_cpu(s->nr_in_set);
	sb->nr_this_dev		= le16_to_cpu(s->nr_this_dev);
	sb->last_mount		= le32_to_cpu(s->last_mount);

	sb->first_bucket	= le16_to_cpu(s->first_bucket);
	sb->keys		= le16_to_cpu(s->keys);

	for (int i = 0; i < SB_JOURNAL_BUCKETS; i++)
		sb->d[i] = le64_to_cpu(s->d[i]);

	pr_debug("read sb version %llu, flags %llu, seq %llu, journal size %u",
		 sb->version, sb->flags, sb->seq, sb->keys);

	err = "Not a bcache superblock";
	if (sb->offset != SB_SECTOR)
		goto err;

	if (memcmp(sb->magic, bcache_magic, 16))
		goto err;

	err = "Too many journal buckets";
	if (sb->keys > SB_JOURNAL_BUCKETS)
		goto err;

	err = "Bad checksum";
	if (s->csum != csum_set(s))
		goto err;

	err = "Bad UUID";
	if (is_zero(sb->uuid, 16))
		goto err;

	err = "Unsupported superblock version";
	if (sb->version > BCACHE_SB_VERSION)
		goto err;

	err = "Bad block/bucket size";
	if (!is_power_of_2(sb->block_size) || sb->block_size > PAGE_SECTORS ||
	    !is_power_of_2(sb->bucket_size) || sb->bucket_size < PAGE_SECTORS)
		goto err;

	err = "Too many buckets";
	if (sb->nbuckets > LONG_MAX)
		goto err;

	err = "Not enough buckets";
	if (sb->nbuckets < 1 << 7)
		goto err;

	err = "Invalid superblock: device too small";
	if (get_capacity(bdev->bd_disk) < sb->bucket_size * sb->nbuckets)
		goto err;

	if (sb->version == CACHE_BACKING_DEV)
		goto out;

	err = "Bad UUID";
	if (is_zero(sb->set_uuid, 16))
		goto err;

	err = "Bad cache device number in set";
	if (!sb->nr_in_set ||
	    sb->nr_in_set <= sb->nr_this_dev ||
	    sb->nr_in_set > MAX_CACHES_PER_SET)
		goto err;

	err = "Journal buckets not sequential";
	for (unsigned i = 0; i < sb->keys; i++)
		if (sb->d[i] != sb->first_bucket + i)
			goto err;

	err = "Too many journal buckets";
	if (sb->first_bucket + sb->keys > sb->nbuckets)
		goto err;

	err = "Invalid superblock: first bucket comes before end of super";
	if (sb->first_bucket * sb->bucket_size < 16)
		goto err;
out:
	sb->last_mount = get_seconds();
	err = NULL;

	get_page(bh->b_page);
	*res = bh->b_page;
err:
	put_bh(bh);
	return err;
}

static void write_bdev_super_endio(struct bio *bio, int error)
{
	struct cached_dev *d = bio->bi_private;
	/* XXX: error checking */

	closure_put(&d->sb_write.cl);
}

static void __write_super(struct cache_sb *sb, struct bio *bio)
{
	struct cache_sb *out = page_address(bio->bi_io_vec[0].bv_page);

	bio->bi_sector	= SB_SECTOR;
	bio->bi_rw	= REQ_SYNC|REQ_META;
	bio->bi_size	= SB_SIZE;
	bio_map(bio, NULL);

	out->offset		= cpu_to_le64(sb->offset);
	out->version		= cpu_to_le64(sb->version);

	memcpy(out->uuid,	sb->uuid, 16);
	memcpy(out->set_uuid,	sb->set_uuid, 16);
	memcpy(out->label,	sb->label, SB_LABEL_SIZE);

	out->flags		= cpu_to_le64(sb->flags);
	out->seq		= cpu_to_le64(sb->seq);

	out->last_mount		= cpu_to_le32(sb->last_mount);
	out->first_bucket	= cpu_to_le16(sb->first_bucket);
	out->keys		= cpu_to_le16(sb->keys);

	for (int i = 0; i < sb->keys; i++)
		out->d[i] = cpu_to_le64(sb->d[i]);

	out->csum = csum_set(out);

	pr_debug("ver %llu, flags %llu, seq %llu",
		 sb->version, sb->flags, sb->seq);

	submit_bio(REQ_WRITE, bio);
}

void write_bdev_super(struct cached_dev *d, struct closure *parent)
{
	struct closure *cl = &d->sb_write.cl;
	struct bio *bio = &d->sb_bio;

	closure_lock(&d->sb_write, parent);

	bio_reset(bio);
	bio->bi_bdev	= d->bdev;
	bio->bi_end_io	= write_bdev_super_endio;
	bio->bi_private = d;

	closure_get(cl);
	__write_super(&d->sb, bio);

	closure_return(cl);
}

static void write_super_endio(struct bio *bio, int error)
{
	struct cache *c = bio->bi_private;

	count_io_errors(c, error, "writing superblock");
	closure_put(&c->set->sb_write.cl);
}

static void bcache_write_super(struct cache_set *c)
{
	struct closure *cl = &c->sb_write.cl;
	struct cache *ca;

	closure_lock(&c->sb_write, &c->cl);

	c->sb.seq++;

	for_each_cache(ca, c) {
		struct bio *bio = &ca->sb_bio;

		ca->sb.version		= BCACHE_SB_VERSION;
		ca->sb.seq		= c->sb.seq;
		ca->sb.last_mount	= c->sb.last_mount;

		SET_CACHE_SYNC(&ca->sb, CACHE_SYNC(&c->sb));

		bio_reset(bio);
		bio->bi_bdev	= ca->bdev;
		bio->bi_end_io	= write_super_endio;
		bio->bi_private = ca;

		closure_get(cl);
		__write_super(&ca->sb, bio);
	}

	closure_return(cl);
}

/* UUID io */

static void uuid_endio(struct bio *bio, int error)
{
	/* XXX: check for io errors */
	bcache_endio(container_of(bio->bi_private, struct cache_set,
				  uuid_write),
		     bio, error, "accessing uuids");
}

static void uuid_io(struct cache_set *c, unsigned long rw,
		    struct bkey *k, struct closure *parent)
{
	struct closure *cl = &c->uuid_write.cl;

	BUG_ON(!parent);
	closure_lock(&c->uuid_write, parent);

	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bio *bio = PTR_CACHE(c, k, i)->uuid_bio;

		bio_reset(bio);
		bio->bi_rw	= REQ_SYNC|REQ_META|rw;
		bio->bi_size	= KEY_SIZE(k) << 9;

		bio->bi_end_io	= uuid_endio;
		bio->bi_private = cl;
		bio_map(bio, c->uuids);

		submit_bbio_split(bio, c, k, i);

		if (!(rw & WRITE))
			break;
	}

	pr_debug("%s UUIDs at %s", rw & REQ_WRITE ? "wrote" : "read",
		 pkey(&c->uuid_bucket));

	for (struct uuid_entry *u = c->uuids; u < c->uuids + c->nr_uuids; u++)
		if (!is_zero(u->uuid, 16))
			pr_debug("Slot %zi: %pU: %s: 1st: %u last: %u inv: %u",
				 u - c->uuids, u->uuid, u->label,
				 u->first_reg, u->last_reg, u->invalidated);

	closure_return(cl);
}

static char *uuid_read(struct cache_set *c, struct jset *j, struct closure *cl)
{
	struct bkey *k = &j->uuid_bucket;

	if (__ptr_invalid(c, 1, k))
		return "bad uuid pointer";

	bkey_copy(&c->uuid_bucket, k);
	uuid_io(c, READ_SYNC, k, cl);

	if (j->version < BCACHE_JSET_VERSION_UUIDv1) {
		struct uuid_entry_v0	*u0 = (void *) c->uuids;
		struct uuid_entry	*u1 = (void *) c->uuids;

		closure_sync(cl);

		/*
		 * Since the new uuid entry is bigger than the old, we have to
		 * convert starting at the highest memory address and work down
		 * in order to do it in place
		 */

		for (int i = c->nr_uuids - 1;
		     i >= 0;
		     --i) {
			memcpy(u1[i].uuid,	u0[i].uuid, 16);
			memcpy(u1[i].label,	u0[i].label, 32);

			u1[i].first_reg		= u0[i].first_reg;
			u1[i].last_reg		= u0[i].last_reg;
			u1[i].invalidated	= u0[i].invalidated;

			u1[i].flags	= 0;
			u1[i].sectors	= 0;
		}
	}

	return NULL;
}

static int __uuid_write(struct cache_set *c)
{
	BKEY_PADDED(key) k;
	struct closure cl;
	closure_init_stack(&cl);

	lockdep_assert_held(&register_lock);

	if (pop_bucket_set(c, BTREE_PRIO, &k.key, 1, &cl))
		return 1;

	SET_KEY_SIZE(&k.key, c->sb.bucket_size);
	uuid_io(c, REQ_WRITE, &k.key, &cl);
	closure_sync(&cl);

	bkey_copy(&c->uuid_bucket, &k.key);
	__bkey_put(c, &k.key);
	return 0;
}

static int uuid_write(struct cache_set *c)
{
	int ret = __uuid_write(c);

	if (!ret)
		bcache_journal_meta(c, NULL);

	return ret;
}

static struct uuid_entry *uuid_find(struct cache_set *c, const char *uuid)
{
	for (struct uuid_entry *u = c->uuids;
	     u < c->uuids + c->nr_uuids; u++)
		if (!memcmp(u->uuid, uuid, 16))
			return u;

	return NULL;
}

static struct uuid_entry *uuid_find_empty(struct cache_set *c)
{
	static const char zero_uuid[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	return uuid_find(c, zero_uuid);
}

/*
 * Bucket priorities/gens:
 *
 * For each bucket, we store on disk its
   * 8 bit gen
   * 16 bit priority
 *
 * See alloc.c for an explanation of the gen. The priority is used to implement
 * lru (and in the future other) cache replacement policies; for most purposes
 * it's just an opaque integer.
 *
 * The gens and the priorities don't have a whole lot to do with each other, and
 * it's actually the gens that must be written out at specific times - it's no
 * big deal if the priorities don't get written, if we lose them we just reuse
 * buckets in suboptimal order.
 *
 * On disk they're stored in a packed array, and in as many buckets are required
 * to fit them all. The buckets we use to store them form a list; the journal
 * header points to the first bucket, the first bucket points to the second
 * bucket, et cetera.
 *
 * This code is primarily used by the allocation code; periodically (whenever
 * it runs out of buckets to allocate from) the allocation code will invalidate
 * some buckets, but it can't use those buckets until their new gens are safely
 * on disk.
 *
 * So it calls prio_write(), which does a bunch of work and eventually stores
 * the pointer to the new first prio bucket in the current open journal entry
 * header; when that journal entry is written, we can mark the buckets that have
 * been invalidated as being ready for use by toggling c->prio_written.
 */

static void prio_endio(struct bio *bio, int error)
{
	struct cache *c = bio->bi_private;
	BUG_ON(c->prio_bio->bi_flags & (1 << BIO_HAS_POOL));
	count_io_errors(c, error, "writing priorities");

	bio_put(bio);
	closure_put(&c->prio);
}

static void prio_io(struct cache *c, uint64_t bucket, unsigned long rw)
{
	struct bio *bio = c->prio_bio;

	bio_reset(bio);
	bio->bi_sector	= bucket * c->sb.bucket_size;
	bio->bi_bdev	= c->bdev;
	bio->bi_rw	= REQ_SYNC|REQ_META|rw;
	bio->bi_size	= bucket_bytes(c);

	bio->bi_end_io	= prio_endio;
	bio->bi_private = c;
	bio_map(bio, c->disk_buckets);

	closure_bio_submit(bio, &c->prio, c->set ? c->set->bio_split : NULL);
}

#define buckets_free(c)	"free %zu, free_inc %zu, unused %zu",		\
	fifo_used(&c->free), fifo_used(&c->free_inc), fifo_used(&c->unused)

static void prio_write_done(struct closure *cl)
{
	struct cache *c = container_of(cl, struct cache, prio);

	pr_debug("free %zu, free_inc %zu, unused %zu", fifo_used(&c->free),
		 fifo_used(&c->free_inc), fifo_used(&c->unused));
	blktrace_msg(c, "Finished priorities: " buckets_free(c));

	mutex_lock(&c->set->bucket_lock);

	/*
	 * XXX: Terrible hack
	 *
	 * We really should be using this closure as the lock for writing
	 * priorities, but we don't - we use c->prio_written. So we have to
	 * finish with the closure before we unlock bucket_lock:
	 */
	set_closure_fn(&c->prio, NULL, NULL);
	closure_set_stopped(&c->prio);
	closure_put(&c->prio);

	atomic_set(&c->prio_written, 1);
	mutex_unlock(&c->set->bucket_lock);

	closure_wake_up(&c->set->bucket_wait);
}

static void prio_write_journal(struct closure *cl)
{
	struct cache *c = container_of(cl, struct cache, prio);

	pr_debug("free %zu, free_inc %zu, unused %zu", fifo_used(&c->free),
		 fifo_used(&c->free_inc), fifo_used(&c->unused));
	blktrace_msg(c, "Journalling priorities: " buckets_free(c));

	mutex_lock(&c->set->bucket_lock);

	for (unsigned i = 0; i < prio_buckets(c); i++)
		c->prio_buckets[i] = c->prio_next[i];

	c->prio_alloc = 0;
	c->need_save_prio = 0;

	/*
	 * We have to call bcache_journal_meta() with bucket_lock still held,
	 * because after we set prio_buckets = prio_next things are inconsistent
	 * until the next journal entry is updated
	 */
	bcache_journal_meta(c->set, cl);

	mutex_unlock(&c->set->bucket_lock);

	continue_at(cl, prio_write_done, system_wq);
}

static void prio_write_bucket(struct closure *cl)
{
	struct cache *c = container_of(cl, struct cache, prio);
	struct prio_set *p = c->disk_buckets;
	struct bucket_disk *d = p->data, *end = d + prios_per_bucket(c);

	unsigned i = c->prio_write++;

	for (struct bucket *b = c->buckets + i * prios_per_bucket(c);
	     b < c->buckets + c->sb.nbuckets && d < end;
	     b++, d++) {
		d->prio = cpu_to_le16(b->prio);
		d->gen = b->disk_gen;
	}

	if (c->prio_write != prio_buckets(c))
		p->next_bucket = c->prio_next[c->prio_write];

	p->magic = pset_magic(c);
	p->csum = crc64(&p->magic, bucket_bytes(c) - 8);

	prio_io(c, c->prio_next[i], REQ_WRITE);

	continue_at(cl, c->prio_write == prio_buckets(c)
		    ? prio_write_journal
		    : prio_write_bucket, system_wq);
}

void prio_write(struct cache *c)
{
	lockdep_assert_held(&c->set->bucket_lock);
	BUG_ON(atomic_read(&c->prio_written));
	BUG_ON(c->prio_alloc != prio_buckets(c));

	closure_init(&c->prio, &c->set->cl);

	for (struct bucket *b = c->buckets;
	     b < c->buckets + c->sb.nbuckets; b++)
		b->disk_gen = b->gen;

	c->prio_write = 0;
	c->disk_buckets->seq++;

	atomic_long_add(c->sb.bucket_size * prio_buckets(c),
			&c->meta_sectors_written);

	atomic_set(&c->prio_written, -1);

	pr_debug("free %zu, free_inc %zu, unused %zu", fifo_used(&c->free),
		 fifo_used(&c->free_inc), fifo_used(&c->unused));
	blktrace_msg(c, "Starting priorities: " buckets_free(c));

	continue_at(&c->prio, prio_write_bucket, system_wq);
}

static int prio_read(struct cache *c, uint64_t bucket)
{
	struct prio_set *p = c->disk_buckets;
	struct bucket_disk *d = p->data + prios_per_bucket(c), *end = d;

	closure_init(&c->prio, NULL);

	for (struct bucket *b = c->buckets;
	     b < c->buckets + c->sb.nbuckets;
	     b++, d++) {
		if (d == end) {
			c->prio_buckets[c->prio_write++] = bucket;

			prio_io(c, bucket, READ_SYNC);
			closure_sync(&c->prio);

			/* XXX: doesn't get error handling right with splits */
			if (!test_bit(BIO_UPTODATE, &c->prio_bio->bi_flags))
				continue_at(&c->prio, NULL, NULL, -1);

			if (p->csum != crc64(&p->magic, bucket_bytes(c) - 8))
				printk(KERN_WARNING "bcache: "
				       "bad csum reading priorities\n");

			if (p->magic != pset_magic(c))
				printk(KERN_WARNING "bcache: "
				       "bad magic reading priorities\n");

			bucket = p->next_bucket;
			d = p->data;
		}

		b->prio = le16_to_cpu(d->prio);
		b->gen = b->disk_gen = b->last_gc = b->gc_gen = d->gen;
	}

	continue_at(&c->prio, NULL, NULL, 0);
}

/* Bcache device */

static int open_dev(struct block_device *b, fmode_t mode)
{
	struct bcache_device *d = b->bd_disk->private_data;
	if (atomic_read(&d->closing))
		return -ENXIO;

	closure_get(&d->cl);
	return 0;
}

static int release_dev(struct gendisk *b, fmode_t mode)
{
	struct bcache_device *d = b->private_data;
	closure_put(&d->cl);
	return 0;
}

static int ioctl_dev(struct block_device *b, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	struct bcache_device *d = b->bd_disk->private_data;
	return d->ioctl(d, mode, cmd, arg);
}

static const struct block_device_operations bcache_ops = {
	.open		= open_dev,
	.release	= release_dev,
	.ioctl		= ioctl_dev,
	.owner		= THIS_MODULE,
};

static void bcache_device_stop(struct bcache_device *d)
{
	if (!atomic_xchg(&d->closing, 1))
		closure_queue(&d->cl);
}

static void bcache_device_detach(struct bcache_device *d)
{
	lockdep_assert_held(&register_lock);

	if (atomic_read(&d->detaching)) {
		struct uuid_entry *u = d->c->uuids + d->id;

		SET_UUID_FLASH_ONLY(u, 0);
		memcpy(u->uuid, invalid_uuid, 16);
		u->invalidated = cpu_to_le32(get_seconds());
		uuid_write(d->c);

		atomic_set(&d->detaching, 0);
	}

	d->c->devices[d->id] = NULL;
	closure_put(&d->c->caching);
	d->c = NULL;
}

static void bcache_device_attach(struct bcache_device *d, struct cache_set *c,
				 unsigned id)
{
	BUG_ON(atomic_read(&c->closing));

	d->id = id;
	d->c = c;
	c->devices[id] = d;

	closure_get(&c->caching);
}

static void bcache_device_link(struct bcache_device *d, struct cache_set *c,
			       const char *name)
{
	snprintf(d->name, BCACHEDEVNAME_SIZE,
		 "%s%u", name, d->id);

	WARN(sysfs_create_link(&d->kobj, &c->kobj, "cache") ||
	     sysfs_create_link(&c->kobj, &d->kobj, d->name),
	     "Couldn't create device <-> cache set symlinks");
}

static void bcache_device_free(struct bcache_device *d)
{
	lockdep_assert_held(&register_lock);

	printk(KERN_INFO "bcache: %s stopped\n", d->disk->disk_name);

	if (d->c)
		bcache_device_detach(d);

	if (d->disk)
		del_gendisk(d->disk);
	if (d->disk && d->disk->queue)
		blk_cleanup_queue(d->disk->queue);
	if (d->disk)
		put_disk(d->disk);

	if (d->unaligned_bvec)
		mempool_destroy(d->unaligned_bvec);
	if (d->bio_split)
		bioset_free(d->bio_split);

	closure_debug_destroy(&d->cl);
}

static int bcache_device_init(struct bcache_device *d, unsigned block_size)
{
	struct request_queue *q;

	if (!(d->bio_split = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(d->unaligned_bvec = mempool_create_kmalloc_pool(1,
				sizeof(struct bio_vec) * BIO_MAX_PAGES)))
		return -ENOMEM;

	d->disk = alloc_disk(1);
	if (!d->disk)
		return -ENOMEM;

	snprintf(d->disk->disk_name, DISK_NAME_LEN, "bcache%i", bcache_minor);

	d->disk->major		= bcache_major;
	d->disk->first_minor	= bcache_minor++;
	d->disk->fops		= &bcache_ops;
	d->disk->private_data	= d;

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	blk_queue_make_request(q, NULL);
	d->disk->queue			= q;
	q->queuedata			= d;
	q->backing_dev_info.congested_data = d;
	q->limits.max_hw_sectors	= UINT_MAX;
	q->limits.max_sectors		= UINT_MAX;
	q->limits.max_segment_size	= UINT_MAX;
	q->limits.max_segments		= BIO_MAX_PAGES;
	q->limits.max_discard_sectors	= UINT_MAX;
	q->limits.io_min		= block_size;
	q->limits.logical_block_size	= block_size;
	q->limits.physical_block_size	= block_size;
	set_bit(QUEUE_FLAG_NONROT,	&d->disk->queue->queue_flags);
	set_bit(QUEUE_FLAG_DISCARD,	&d->disk->queue->queue_flags);

	return 0;
}

/* Cached device */

static void calc_cached_dev_sectors(struct cache_set *c)
{
	uint64_t sectors = 0;
	struct cached_dev *dc;

	list_for_each_entry(dc, &c->cached_devs, list)
		sectors += bdev_sectors(dc->bdev);

	c->cached_dev_sectors = sectors;
}

static void cached_dev_run(struct cached_dev *dc)
{
	struct bcache_device *d = &dc->disk;

	if (atomic_xchg(&dc->running, 1))
		return;

	if (!d->c &&
	    BDEV_STATE(&dc->sb) != BDEV_STATE_NONE) {
		struct closure cl;
		closure_init_stack(&cl);

		SET_BDEV_STATE(&dc->sb, BDEV_STATE_STALE);
		write_bdev_super(dc, &cl);
		closure_sync(&cl);
	}

	add_disk(d->disk);
#if 0
	char *env[] = { "SYMLINK=label" , NULL };
	kobject_uevent_env(&disk_to_dev(d->disk)->kobj, KOBJ_CHANGE, env);
#endif
	if (sysfs_create_link(&d->kobj, &disk_to_dev(d->disk)->kobj, "dev") ||
	    sysfs_create_link(&disk_to_dev(d->disk)->kobj, &d->kobj, "bcache"))
		pr_debug("error creating sysfs link");
}

static void cached_dev_detach_finish(struct work_struct *w)
{
	struct cached_dev *d = container_of(w, struct cached_dev, detach);
	char buf[BDEVNAME_SIZE];
	struct closure cl;
	closure_init_stack(&cl);

	mutex_lock(&register_lock);

	BUG_ON(!atomic_read(&d->disk.detaching));
	BUG_ON(atomic_read(&d->count));

	memset(&d->sb.set_uuid, 0, 16);
	SET_BDEV_STATE(&d->sb, BDEV_STATE_NONE);

	write_bdev_super(d, &cl);
	closure_sync(&cl);

	bcache_device_detach(&d->disk);
	list_move(&d->list, &uncached_devices);

	mutex_unlock(&register_lock);

	printk(KERN_DEBUG "bcache: Caching disabled for %s\n",
	       bdevname(d->bdev, buf));
}

static void cached_dev_detach(struct cached_dev *d)
{
	lockdep_assert_held(&register_lock);

	if (atomic_xchg(&d->disk.detaching, 1))
		return;

	bcache_writeback_queue(d);
	cached_dev_put(d);
}

static int cached_dev_attach(struct cached_dev *d, struct cache_set *c)
{
	uint32_t rtime = cpu_to_le32(get_seconds());
	struct uuid_entry *u;
	char buf[BDEVNAME_SIZE];

	bdevname(d->bdev, buf);

	if (d->disk.c ||
	    atomic_read(&c->closing) ||
	    memcmp(d->sb.set_uuid, c->sb.set_uuid, 16))
		return -ENOENT;

	if (d->sb.block_size < c->sb.block_size) {
		/* Will die */
		err_printk("Couldn't attach %s: block size "
			   "less than set's block size\n", buf);
		return -EINVAL;
	}

	u = uuid_find(c, d->sb.uuid);

	if (u &&
	    (BDEV_STATE(&d->sb) == BDEV_STATE_STALE ||
	     BDEV_STATE(&d->sb) == BDEV_STATE_NONE)) {
		memcpy(u->uuid, invalid_uuid, 16);
		u->invalidated = cpu_to_le32(get_seconds());
		u = NULL;
	}

	if (!u) {
		if (BDEV_STATE(&d->sb) == BDEV_STATE_DIRTY) {
			err_printk("Couldn't find uuid for %s in set\n", buf);
			return -ENOENT;
		}

		u = uuid_find_empty(c);
		if (!u) {
			err_printk("Not caching %s, no room for UUID\n", buf);
			return -EINVAL;
		}
	}

	/* Deadlocks since we're called via sysfs...
	sysfs_remove_file(&d->kobj, &sysfs_attach);
	 */

	if (is_zero(u->uuid, 16)) {
		struct closure cl;
		closure_init_stack(&cl);

		memcpy(u->uuid, d->sb.uuid, 16);
		memcpy(u->label, d->sb.label, SB_LABEL_SIZE);
		u->first_reg = u->last_reg = rtime;
		uuid_write(c);

		memcpy(d->sb.set_uuid, c->sb.set_uuid, 16);
		SET_BDEV_STATE(&d->sb, BDEV_STATE_CLEAN);

		write_bdev_super(d, &cl);
		closure_sync(&cl);
	} else {
		u->last_reg = rtime;
		uuid_write(c);
	}

	bcache_device_attach(&d->disk, c, u - c->uuids);
	bcache_device_link(&d->disk, c, "bdev");
	list_move(&d->list, &c->cached_devs);
	calc_cached_dev_sectors(c);

	smp_wmb();
	/*
	 * d->c must be set before d->count != 0 - paired with the mb in
	 * cached_dev_get()
	 */
	atomic_set(&d->count, 1);

	if (BDEV_STATE(&d->sb) == BDEV_STATE_DIRTY) {
		atomic_set(&d->has_dirty, 1);
		atomic_inc(&d->count);
		bcache_writeback_queue(d);
	}

	cached_dev_run(d);

	printk(KERN_INFO "bcache: Caching %s as %s on set %pU\n",
	       bdevname(d->bdev, buf), d->disk.disk->disk_name,
	       d->disk.c->sb.set_uuid);
	return 0;
}

static void __cached_dev_free(struct kobject *kobj)
{
	struct cached_dev *d = container_of(kobj, struct cached_dev, disk.kobj);
	kfree(d);
	module_put(THIS_MODULE);
}

static void cached_dev_free(struct closure *cl)
{
	struct cached_dev *d = container_of(cl, struct cached_dev, disk.cl);

	/* XXX: background writeback could be in progress... */
	cancel_delayed_work_sync(&d->refill_dirty);
	cancel_delayed_work_sync(&d->read_dirty);
	cancel_delayed_work_sync(&d->writeback_rate_update);

	mutex_lock(&register_lock);

	bcache_device_free(&d->disk);
	list_del(&d->list);

	mutex_unlock(&register_lock);

	if (d->bio_passthrough)
		mempool_destroy(d->bio_passthrough);

	if (!IS_ERR_OR_NULL(d->bdev)) {
		blk_sync_queue(bdev_get_queue(d->bdev));
		blkdev_put(d->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	}

	wake_up(&unregister_wait);

	kobject_put(&d->disk.kobj);
}

static void cached_dev_flush(struct closure *cl)
{
	struct cached_dev *cd = container_of(cl, struct cached_dev, disk.cl);
	struct bcache_device *d = &cd->disk;

	destroy_cache_accounting(&cd->accounting);
	sysfs_remove_link(&d->kobj, d->name);
	sysfs_remove_link(&d->kobj, "cache");
	kobject_del(&d->kobj);

	continue_at(cl, cached_dev_free, system_wq);
}

static int cached_dev_init(struct cached_dev *d, unsigned block_size)
{
	int err;

	closure_init(&d->disk.cl, NULL);
	set_closure_fn(&d->disk.cl, cached_dev_flush, system_wq);

	__module_get(THIS_MODULE);
	INIT_LIST_HEAD(&d->list);
	cached_dev_kobject_init(d);
	init_cache_accounting(&d->accounting, &d->disk.cl);

	if (bcache_device_init(&d->disk, block_size))
		goto err;

	spin_lock_init(&d->dirty_lock);
	spin_lock_init(&d->io_lock);
	closure_init_unlocked(&d->sb_write);
	INIT_WORK(&d->detach, cached_dev_detach_finish);

	d->sequential_merge		= true;
	d->sequential_cutoff		= 4 << 20;

	INIT_LIST_HEAD(&d->io_lru);
	d->sb_bio.bi_max_vecs	= 1;
	d->sb_bio.bi_io_vec	= d->sb_bio.bi_inline_vecs;

	for (struct io *j = d->io; j < d->io + RECENT_IO; j++) {
		list_add(&j->lru, &d->io_lru);
		hlist_add_head(&j->hash, d->io_hash + RECENT_IO);
	}

	bcache_writeback_init_cached_dev(d);

	err = -ENOMEM;
	d->bio_passthrough = mempool_create_slab_pool(32, passthrough_cache);
	if (!d->bio_passthrough)
		goto err;

	return 0;
err:
	bcache_device_stop(&d->disk);
	return err;
}

/* Cached device - bcache superblock */

static const char *register_bdev(struct cache_sb *sb, struct page *sb_page,
				 struct block_device *bdev, struct cached_dev *d)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";
	struct gendisk *g;
	struct cache_set *c;

	if (!d || cached_dev_init(d, sb->block_size << 9) != 0)
		return err;

	memcpy(&d->sb, sb, sizeof(struct cache_sb));
	d->sb_bio.bi_io_vec[0].bv_page = sb_page;
	d->bdev = bdev;
	d->bdev->bd_holder = d;

	g = d->disk.disk;

	set_capacity(g, d->bdev->bd_part->nr_sects - 16);

	cached_dev_request_init(d);

	err = "error creating kobject";
	if (kobject_add(&d->disk.kobj, &part_to_dev(bdev->bd_part)->kobj,
			"bcache"))
		goto err;
	if (add_cache_accounting_kobjs(&d->accounting, &d->disk.kobj))
		goto err;

	list_add(&d->list, &uncached_devices);
	list_for_each_entry(c, &cache_sets, list)
		cached_dev_attach(d, c);

	if (BDEV_STATE(&d->sb) == BDEV_STATE_NONE ||
	    BDEV_STATE(&d->sb) == BDEV_STATE_STALE)
		cached_dev_run(d);

	return NULL;
err:
	kobject_put(&d->disk.kobj);
	printk(KERN_DEBUG "bcache: error opening %s: %s\n",
	       bdevname(bdev, name), err);
	/*
	 * Return NULL instead of an error because kobject_put() cleans
	 * everything up
	 */
	return NULL;
}

/* Flash only volumes */

static void __flash_dev_free(struct kobject *kobj)
{
	struct bcache_device *d = container_of(kobj, struct bcache_device,
					       kobj);
	kfree(d);
}

static void flash_dev_free(struct closure *cl)
{
	struct bcache_device *d = container_of(cl, struct bcache_device, cl);
	bcache_device_free(d);
	kobject_put(&d->kobj);
}

static void flash_dev_flush(struct closure *cl)
{
	struct bcache_device *d = container_of(cl, struct bcache_device, cl);

	sysfs_remove_link(&d->c->kobj, d->name);
	sysfs_remove_link(&d->kobj, "cache");
	kobject_del(&d->kobj);
	continue_at(cl, flash_dev_free, system_wq);
}

static int flash_dev_run(struct cache_set *c, struct uuid_entry *u)
{
	struct bcache_device *d = kzalloc(sizeof(struct bcache_device),
					  GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	closure_init(&d->cl, NULL);
	set_closure_fn(&d->cl, flash_dev_flush, system_wq);

	flash_dev_kobject_init(d);

	if (bcache_device_init(d, block_bytes(c)))
		goto err;

	bcache_device_attach(d, c, u - c->uuids);
	set_capacity(d->disk, u->sectors);
	flash_dev_request_init(d);
	add_disk(d->disk);

	if (kobject_add(&d->kobj, &disk_to_dev(d->disk)->kobj, "bcache"))
		goto err;

	bcache_device_link(d, c, "volume");

	return 0;
err:
	kobject_put(&d->kobj);
	return -ENOMEM;
}

static int flash_devs_run(struct cache_set *c)
{
	int ret = 0;

	for (struct uuid_entry *u = c->uuids;
	     u < c->uuids + c->nr_uuids && !ret;
	     u++)
		if (UUID_FLASH_ONLY(u))
			ret = flash_dev_run(c, u);

	return ret;
}

static int flash_dev_create(struct cache_set *c, uint64_t size)
{
	struct uuid_entry *u;

	if (atomic_read(&c->closing))
		return -EINTR;

	u = uuid_find_empty(c);
	if (!u) {
		err_printk("Can't create volume, no room for UUID\n");
		return -EINVAL;
	}

	get_random_bytes(u->uuid, 16);
	memset(u->label, 0, 32);
	u->first_reg = u->last_reg = cpu_to_le32(get_seconds());

	SET_UUID_FLASH_ONLY(u, 1);
	u->sectors = size >> 9;

	uuid_write(c);

	return flash_dev_run(c, u);
}

/* Cache set */

__printf(2, 3)
bool cache_set_error(struct cache_set *c, const char *m, ...)
{
	va_list args;

	if (atomic_read(&c->closing))
		return false;

	/* XXX: we can be called from atomic context
	acquire_console_sem();
	*/

	printk(KERN_ERR "bcache: error on %pU: ", c->sb.set_uuid);

	va_start(args, m);
	vprintk(m, args);
	va_end(args);

	printk(", disabling caching\n");

	cache_set_unregister(c);
	return true;
}

static void __cache_set_free(struct kobject *kobj)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
	kfree(c);
	module_put(THIS_MODULE);
}

static void cache_set_free(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, cl);
	struct cache *ca;

	bcache_open_buckets_free(c);
	bcache_btree_cache_free(c);
	bcache_journal_free(c);

	for_each_cache(ca, c)
		if (ca)
			kobject_put(&ca->kobj);

	free_pages((unsigned long) c->uuids, ilog2(bucket_pages(c)));
	free_pages((unsigned long) c->sort, ilog2(bucket_pages(c)));

	kfree(c->fill_iter);
	if (c->bio_split)
		bioset_free(c->bio_split);
	if (c->bio_meta)
		mempool_destroy(c->bio_meta);
	if (c->search)
		mempool_destroy(c->search);
	kfree(c->devices);

	mutex_lock(&register_lock);
	list_del(&c->list);
	mutex_unlock(&register_lock);

	printk(KERN_INFO "bcache: Cache set %pU unregistered\n",
	       c->sb.set_uuid);
	wake_up(&unregister_wait);

	closure_debug_destroy(&c->cl);
	kobject_put(&c->kobj);
}

static void cache_set_flush(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);
	struct btree *b;

	destroy_cache_accounting(&c->accounting);

	kobject_put(&c->internal);
	kobject_del(&c->kobj);

	if (!IS_ERR_OR_NULL(c->root))
		list_add(&c->root->list, &c->btree_cache);

	/* Should skip this if we're unregistering because of an error */
	list_for_each_entry(b, &c->btree_cache, list)
		if (btree_node_dirty(b))
			btree_write(b, true, NULL);

	closure_return(cl);
}

static void __cache_set_unregister(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, caching);
	struct cached_dev *d, *t;

	mutex_lock(&register_lock);

	if (atomic_read(&c->unregistering))
		list_for_each_entry_safe(d, t, &c->cached_devs, list)
			cached_dev_detach(d);

	for (size_t i = 0; i < c->nr_uuids; i++)
		if (c->devices[i])
			bcache_device_stop(c->devices[i]);

	mutex_unlock(&register_lock);

	continue_at(cl, cache_set_flush, system_wq);
}

static void cache_set_stop(struct cache_set *c)
{
	if (!atomic_xchg(&c->closing, 1))
		closure_queue(&c->caching);
}

static void cache_set_unregister(struct cache_set *c)
{
	atomic_set(&c->unregistering, 1);
	cache_set_stop(c);
}

#define alloc_bucket_pages(gfp, c)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(c))))

struct cache_set *cache_set_alloc(struct cache_sb *sb)
{
	int iter_size;
	struct cache_set *c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
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

	cache_set_kobject_init(c);
	init_cache_accounting(&c->accounting, &c->cl);

	memcpy(c->sb.set_uuid, sb->set_uuid, 16);
	c->sb.block_size	= sb->block_size;
	c->sb.bucket_size	= sb->bucket_size;
	c->sb.nr_in_set		= sb->nr_in_set;
	c->sb.last_mount	= sb->last_mount;
	c->bucket_bits		= ilog2(sb->bucket_size);
	c->block_bits		= ilog2(sb->block_size);
	c->nr_uuids		= bucket_bytes(c) / sizeof(struct uuid_entry);

	c->btree_pages		= c->sb.bucket_size / PAGE_SECTORS;
	if (c->btree_pages > BTREE_MAX_PAGES)
		c->btree_pages = max_t(int, c->btree_pages / 4,
				       BTREE_MAX_PAGES);

	mutex_init(&c->bucket_lock);
	mutex_init(&c->fill_lock);
	mutex_init(&c->sort_lock);
	spin_lock_init(&c->sort_time_lock);
	closure_init_unlocked(&c->sb_write);
	closure_init_unlocked(&c->uuid_write);
	spin_lock_init(&c->btree_read_time_lock);

	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->cached_devs);
	INIT_LIST_HEAD(&c->btree_cache);
	INIT_LIST_HEAD(&c->btree_cache_freeable);
	INIT_LIST_HEAD(&c->btree_cache_freed);
	INIT_LIST_HEAD(&c->data_buckets);

	c->search = mempool_create_slab_pool(32, search_cache);
	if (!c->search)
		goto err;

	iter_size = (sb->bucket_size / sb->block_size + 1) *
		sizeof(struct btree_iter_set);

	if (!(c->devices = kzalloc(c->nr_uuids * sizeof(void *), GFP_KERNEL)) ||
	    !(c->bio_meta = mempool_create_kmalloc_pool(2,
				sizeof(struct bbio) + sizeof(struct bio_vec) *
				bucket_pages(c))) ||
	    !(c->bio_split = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(c->fill_iter = kmalloc(iter_size, GFP_KERNEL)) ||
	    !(c->sort = alloc_bucket_pages(GFP_KERNEL, c)) ||
	    !(c->uuids = alloc_bucket_pages(GFP_KERNEL, c)) ||
	    bcache_journal_alloc(c) ||
	    bcache_btree_cache_alloc(c) ||
	    bcache_open_buckets_alloc(c))
		goto err;

	c->fill_iter->size = sb->bucket_size / sb->block_size;

	c->congested_read_threshold_us	= 2000;
	c->congested_write_threshold_us	= 20000;
	c->error_limit	= 8 << IO_ERROR_SHIFT;

	return c;
err:
	cache_set_unregister(c);
	return NULL;
}

static void run_cache_set(struct cache_set *c)
{
	const char *err = "cannot allocate memory";
	struct cached_dev *d, *t;
	struct cache *ca;

	struct btree_op op;
	btree_op_init_stack(&op);
	op.lock = SHRT_MAX;

	for_each_cache(ca, c)
		c->nbuckets += ca->sb.nbuckets;

	if (CACHE_SYNC(&c->sb)) {
		LIST_HEAD(journal);
		struct bkey *k;
		struct jset *j;

		err = "cannot allocate memory for journal";
		if (bcache_journal_read(c, &journal, &op))
			goto err;

		printk(KERN_DEBUG "bcache: btree_journal_read() done\n");

		err = "no journal entries found";
		if (list_empty(&journal))
			goto err;

		j = &list_entry(journal.prev, struct journal_replay, list)->j;

		err = "IO error reading priorities";
		for_each_cache(ca, c) {
			if (prio_read(ca, j->prio_bucket[ca->sb.nr_this_dev]))
				goto err;
		}

		k = &j->btree_root;

		err = "bad btree root";
		if (__ptr_invalid(c, j->btree_level + 1, k))
			goto err;

		err = "error reading btree root";
		c->root = get_bucket(c, k, j->btree_level, &op);
		if (IS_ERR_OR_NULL(c->root))
			goto err;

		list_del_init(&c->root->list);
		rw_unlock(true, c->root);

		err = uuid_read(c, j, &op.cl);
		if (err)
			goto err;

		err = "error in recovery";
		if (btree_check(c, &op))
			goto err;

		bcache_journal_mark(c, &journal);
		btree_gc_finish(c);
		printk(KERN_DEBUG "bcache: btree_check() done\n");

		/*
		 * bcache_journal_next() can't happen sooner, or
		 * btree_gc_finish() will give spurious errors about last_gc >
		 * gc_gen - this is a hack but oh well.
		 */
		bcache_journal_next(&c->journal);

		/*
		 * First place it's safe to allocate: btree_check() and
		 * btree_gc_finish() have to run before we have buckets to
		 * allocate, and pop_bucket() might cause a journal entry to be
		 * written so bcache_journal_next() has to be called first
		 *
		 * If the uuids were in the old format we have to rewrite them
		 * before the next journal entry is written:
		 */
		if (j->version < BCACHE_JSET_VERSION_UUID)
			__uuid_write(c);

		bcache_journal_replay(c, &journal, &op);
	} else {
		printk(KERN_NOTICE "bcache: invalidating existing data\n");
		/* Don't want invalidate_buckets() to queue a gc yet */
		closure_lock(&c->gc, NULL);

		for_each_cache(ca, c) {
			ca->sb.keys = clamp_t(int, ca->sb.nbuckets >> 7,
					      2, SB_JOURNAL_BUCKETS);

			for (int i = 0; i < ca->sb.keys; i++)
				ca->sb.d[i] = ca->sb.first_bucket + i;
		}

		btree_gc_finish(c);

		err = "cannot allocate new UUID bucket";
		if (uuid_write(c))
			goto err_unlock_gc;

		err = "cannot allocate new btree root";
		c->root = bcache_btree_alloc(c, 0, &op.cl);
		if (IS_ERR_OR_NULL(c->root))
			goto err_unlock_gc;

		bkey_copy_key(&c->root->key, &MAX_KEY);
		btree_write(c->root, true, &op);

		mutex_lock(&c->bucket_lock);
		for_each_cache(ca, c) {
			free_some_buckets(ca);
			prio_write(ca);
		}
		mutex_unlock(&c->bucket_lock);

		/*
		 * Wait for prio_write() to finish, so the SET_CACHE_SYNC()
		 * doesn't race
		 */
		for_each_cache(ca, c)
			closure_wait_event(&c->bucket_wait, &op.cl,
				   atomic_read(&ca->prio_written) == -1);

		bcache_btree_set_root(c->root);
		rw_unlock(true, c->root);

		/*
		 * We don't want to write the first journal entry until
		 * everything is set up - fortunately journal entries won't be
		 * written until the SET_CACHE_SYNC() here:
		 */
		SET_CACHE_SYNC(&c->sb, true);

		bcache_journal_next(&c->journal);
		bcache_journal_meta(c, &op.cl);

		/* Unlock */
		closure_set_stopped(&c->gc.cl);
		closure_put(&c->gc.cl);
	}

	closure_sync(&op.cl);
	c->sb.last_mount = get_seconds();
	bcache_write_super(c);

	list_for_each_entry_safe(d, t, &uncached_devices, list)
		cached_dev_attach(d, c);

	flash_devs_run(c);

	return;
err_unlock_gc:
	closure_set_stopped(&c->gc.cl);
	closure_put(&c->gc.cl);
err:
	closure_sync(&op.cl);
	/* XXX: test this, it's broken */
	cache_set_error(c, err);
}

static bool can_attach_cache(struct cache *ca, struct cache_set *c)
{
	return ca->sb.block_size	== c->sb.block_size &&
		ca->sb.bucket_size	== c->sb.block_size &&
		ca->sb.nr_in_set	== c->sb.nr_in_set;
}

static const char *register_cache_set(struct cache *ca)
{
	char buf[12];
	const char *err = "cannot allocate memory";
	struct cache_set *c;

	list_for_each_entry(c, &cache_sets, list)
		if (!memcmp(c->sb.set_uuid, ca->sb.set_uuid, 16)) {
			if (c->cache[ca->sb.nr_this_dev])
				return "duplicate cache set member";

			if (!can_attach_cache(ca, c))
				return "cache sb does not match set";

			if (!CACHE_SYNC(&ca->sb))
				SET_CACHE_SYNC(&c->sb, false);

			goto found;
		}

	c = cache_set_alloc(&ca->sb);
	if (!c)
		return err;

	err = "error creating kobject";
	if (kobject_add(&c->kobj, bcache_kobj, "%pU", c->sb.set_uuid) ||
	    kobject_add(&c->internal, &c->kobj, "internal"))
		goto err;

	if (add_cache_accounting_kobjs(&c->accounting, &c->kobj))
		goto err;

	list_add(&c->list, &cache_sets);
found:
	sprintf(buf, "cache%i", ca->sb.nr_this_dev);
	if (sysfs_create_link(&ca->kobj, &c->kobj, "set") ||
	    sysfs_create_link(&c->kobj, &ca->kobj, buf))
		goto err;

	if (ca->sb.seq > c->sb.seq) {
		c->sb.version		= ca->sb.version;
		memcpy(c->sb.set_uuid, ca->sb.set_uuid, 16);
		c->sb.flags             = ca->sb.flags;
		c->sb.seq		= ca->sb.seq;
		pr_debug("set version = %llu", c->sb.version);
	}

	ca->set = c;
	ca->set->cache[ca->sb.nr_this_dev] = ca;
	c->cache_by_alloc[c->caches_loaded++] = ca;

	if (c->caches_loaded == c->sb.nr_in_set)
		run_cache_set(c);

	return NULL;
err:
	cache_set_unregister(c);
	return err;
}

/* Cache device */

static void cache_free(struct kobject *kobj)
{
	struct cache *c = container_of(kobj, struct cache, kobj);

	if (c->set)
		c->set->cache[c->sb.nr_this_dev] = NULL;

	if (!IS_ERR_OR_NULL(c->debug))
		debugfs_remove(c->debug);

	free_discards(c);

	if (c->prio_bio)
		bio_put(c->prio_bio);
	if (c->uuid_bio)
		bio_put(c->uuid_bio);

	free_pages((unsigned long) c->disk_buckets, ilog2(bucket_pages(c)));
	kfree(c->prio_buckets);
	vfree(c->buckets);

	if (c->discard_page)
		put_page(c->discard_page);

	free_heap(&c->heap);
	free_fifo(&c->unused);
	free_fifo(&c->free_inc);
	free_fifo(&c->free);

	if (c->sb_bio.bi_inline_vecs[0].bv_page)
		put_page(c->sb_bio.bi_io_vec[0].bv_page);

	if (!IS_ERR_OR_NULL(c->bdev)) {
		blk_sync_queue(bdev_get_queue(c->bdev));
		blkdev_put(c->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	}

	kfree(c);
	module_put(THIS_MODULE);
}

static int cache_alloc(struct cache_sb *sb, struct cache *c)
{
	size_t free;
	struct bucket *b;

	if (!c)
		return -ENOMEM;

	__module_get(THIS_MODULE);
	cache_kobject_init(c);

	memcpy(&c->sb, sb, sizeof(struct cache_sb));

	INIT_LIST_HEAD(&c->discards);

	bio_init(&c->sb_bio);
	c->sb_bio.bi_max_vecs	= 1;
	c->sb_bio.bi_io_vec	= c->sb_bio.bi_inline_vecs;

	bio_init(&c->journal.bio);
	c->journal.bio.bi_max_vecs = 8;
	c->journal.bio.bi_io_vec = c->journal.bio.bi_inline_vecs;

	free = roundup_pow_of_two(c->sb.nbuckets) >> 9;
	free = max_t(size_t, free, 16);
	free = max_t(size_t, free, prio_buckets(c) + 4);

	if (!init_fifo(&c->free,	free, GFP_KERNEL) ||
	    !init_fifo(&c->free_inc,	free << 2, GFP_KERNEL) ||
	    !init_fifo(&c->unused,	free << 2, GFP_KERNEL) ||
	    !init_heap(&c->heap,	free << 3, GFP_KERNEL) ||
	    !(c->discard_page	= alloc_page(__GFP_ZERO|GFP_KERNEL)) ||
	    !(c->buckets	= vmalloc(sizeof(struct bucket) *
					  c->sb.nbuckets)) ||
	    !(c->prio_buckets	= kzalloc(sizeof(uint64_t) * prio_buckets(c) *
					  2, GFP_KERNEL)) ||
	    !(c->disk_buckets	= alloc_bucket_pages(GFP_KERNEL, c)) ||
	    !(c->uuid_bio	= bbio_kmalloc(GFP_KERNEL, bucket_pages(c))) ||
	    !(c->prio_bio	= bio_kmalloc(GFP_KERNEL, bucket_pages(c))))
		goto err;

	c->prio_next = c->prio_buckets + prio_buckets(c);

	memset(c->buckets, 0, c->sb.nbuckets * sizeof(struct bucket));
	for_each_bucket(b, c)
		atomic_set(&b->pin, 0);

	if (alloc_discards(c))
		goto err;

	return 0;
err:
	kobject_put(&c->kobj);
	return -ENOMEM;
}

static const char *register_cache(struct cache_sb *sb, struct page *sb_page,
				  struct block_device *bdev, struct cache *c)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";

	if (cache_alloc(sb, c) != 0)
		return err;

	c->sb_bio.bi_io_vec[0].bv_page = sb_page;
	c->bdev = bdev;
	c->bdev->bd_holder = c;

	if (blk_queue_discard(bdev_get_queue(c->bdev)))
		c->discard = CACHE_DISCARD(&c->sb);

	err = "error creating kobject";
	if (kobject_add(&c->kobj, &disk_to_dev(bdev->bd_disk)->kobj, "bcache"))
		goto err;

	err = register_cache_set(c);
	if (err)
		goto err;

	bcache_debug_init_cache(c);

	printk(KERN_DEBUG "bcache: registered cache device %s\n",
	       bdevname(bdev, name));

	return NULL;
err:
	kobject_put(&c->kobj);
	printk(KERN_DEBUG "bcache: error opening %s: %s\n",
	       bdevname(bdev, name), err);
	/* Return NULL instead of an error because kobject_put() cleans
	 * everything up
	 */
	return NULL;
}

/* Global interfaces/init */

static ssize_t register_bcache(struct kobject *, struct kobj_attribute *,
			       const char *, size_t);

kobj_attribute_write(register,		register_bcache);
kobj_attribute_write(register_quiet,	register_bcache);

static ssize_t register_bcache(struct kobject *k, struct kobj_attribute *attr,
			       const char *buffer, size_t size)
{
	ssize_t ret = size;
	const char *err = "cannot allocate memory";
	char *path = NULL;
	struct cache_sb *sb = NULL;
	struct block_device *bdev = NULL;
	struct page *sb_page = NULL;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	mutex_lock(&register_lock);

	if (!(path = kstrndup(buffer, size, GFP_KERNEL)) ||
	    !(sb = kmalloc(sizeof(struct cache_sb), GFP_KERNEL)))
		goto err;

	err = "failed to open device";
	bdev = blkdev_get_by_path(strim(path),
				  FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				  sb);
	if (bdev == ERR_PTR(-EBUSY))
		err = "device busy";

	if (IS_ERR(bdev) ||
	    set_blocksize(bdev, 4096))
		goto err;

	err = read_super(sb, bdev, &sb_page);
	if (err)
		goto err_close;

	if (sb->version == CACHE_BACKING_DEV) {
		struct cached_dev *d = kzalloc(sizeof(*d), GFP_KERNEL);

		err = register_bdev(sb, sb_page, bdev, d);
	} else {
		struct cache *c = kzalloc(sizeof(*c), GFP_KERNEL);

		err = register_cache(sb, sb_page, bdev, c);
	}

	if (err) {
		/* register_(bdev|cache) will only return an error if they
		 * didn't get far enough to create the kobject - if they did,
		 * the kobject destructor will do this cleanup.
		 */
		put_page(sb_page);
err_close:
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
err:
		if (attr != &ksysfs_register_quiet)
			printk(KERN_DEBUG "bcache: error opening %s: %s\n",
			       path, err);
		ret = -EINVAL;
	}

	kfree(sb);
	kfree(path);
	mutex_unlock(&register_lock);
	module_put(THIS_MODULE);
	return ret;
}

static int bcache_reboot(struct notifier_block *n, unsigned long code, void *x)
{
	if (code == SYS_DOWN ||
	    code == SYS_HALT ||
	    code == SYS_POWER_OFF) {
		DEFINE_WAIT(wait);
		unsigned long start = jiffies;
		bool stopped = false;

		struct cache_set *c, *tc;
		struct cached_dev *dc, *tdc;

		mutex_lock(&register_lock);

		if (list_empty(&cache_sets) && list_empty(&uncached_devices))
			goto out;

		printk(KERN_INFO "bcache: Stopping all devices:\n");

		list_for_each_entry_safe(c, tc, &cache_sets, list)
			cache_set_stop(c);

		list_for_each_entry_safe(dc, tdc, &uncached_devices, list)
			bcache_device_stop(&dc->disk);

		/* What's a condition variable? */
		while (1) {
			long timeout = start + 2 * HZ - jiffies;

			stopped = list_empty(&cache_sets) &&
				list_empty(&uncached_devices);

			if (timeout < 0 || stopped)
				break;

			prepare_to_wait(&unregister_wait, &wait,
					TASK_UNINTERRUPTIBLE);

			mutex_unlock(&register_lock);
			schedule_timeout(timeout);
			mutex_lock(&register_lock);
		}

		finish_wait(&unregister_wait, &wait);

		printk(KERN_INFO "bcache: %s\n", stopped
		       ? "All devices stopped"
		       : "Timeout waiting for devices to be closed");
out:
		mutex_unlock(&register_lock);
	}

	return NOTIFY_DONE;
}

static struct notifier_block reboot = {
	.notifier_call	= bcache_reboot,
	.priority	= INT_MAX, /* before any real devices */
};

static void bcache_exit(void)
{
	bcache_debug_exit();
	bcache_writeback_exit();
	bcache_request_exit();
	bcache_btree_exit();
	if (bcache_kobj)
		kobject_put(bcache_kobj);
	if (bcache_wq)
		destroy_workqueue(bcache_wq);
	unregister_blkdev(bcache_major, "bcache");
	unregister_reboot_notifier(&reboot);
}

static int __init bcache_init(void)
{
	static const struct attribute *files[] = {
		&ksysfs_register.attr,
		&ksysfs_register_quiet.attr,
		NULL
	};

	mutex_init(&register_lock);
	init_waitqueue_head(&unregister_wait);
	register_reboot_notifier(&reboot);

	bcache_major = register_blkdev(0, "bcache");
	if (bcache_major < 0)
		return bcache_major;

	if (!(bcache_wq = create_workqueue("bcache")) ||
	    !(bcache_kobj = kobject_create_and_add("bcache", fs_kobj)) ||
	    sysfs_create_files(bcache_kobj, files) ||
	    bcache_btree_init() ||
	    bcache_request_init() ||
	    bcache_writeback_init() ||
	    bcache_debug_init(bcache_kobj))
		goto err;

	return 0;
err:
	bcache_exit();
	return -ENOMEM;
}

module_exit(bcache_exit);
module_init(bcache_init);
