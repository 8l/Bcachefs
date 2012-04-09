
#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "request.h"

#include <linux/buffer_head.h>
#include <linux/debugfs.h>
#include <linux/genhd.h>
#include <linux/module.h>
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

struct workqueue_struct *bcache_wq;

static void cached_dev_run(struct cached_dev *);
static int cached_dev_attach(struct cached_dev *, struct cache_set *);
static void cached_dev_detach(struct cached_dev *);

#define BTREE_MAX_PAGES		(256 * 1024 / PAGE_SIZE)

/* Sysfs */

#define KTYPE(type, _release)						\
static const struct sysfs_ops type ## _ops = {				\
	.show		= type ## _show,				\
	.store		= type ## _store				\
};									\
static struct kobj_type type ## _obj = {				\
	.release	= _release,					\
	.sysfs_ops	= &type ## _ops,				\
	.default_attrs	= type ## _files				\
}

#define SHOW(fn)							\
static ssize_t fn ## _show(struct kobject *kobj, struct attribute *attr,\
			   char *buf)					\

#define STORE(fn)							\
static ssize_t fn ## _store(struct kobject *kobj, struct attribute *attr,\
			    const char *buf, size_t size)		\

#define SHOW_LOCKED(fn)							\
SHOW(fn)								\
{									\
	ssize_t ret;							\
	mutex_lock(&register_lock);					\
	ret = __ ## fn ## _show(kobj, attr, buf);			\
	mutex_unlock(&register_lock);					\
	return ret;							\
}

#define STORE_LOCKED(fn)						\
STORE(fn)								\
{									\
	ssize_t ret;							\
	mutex_lock(&register_lock);					\
	ret = __ ## fn ## _store(kobj, attr, buf, size);		\
	mutex_unlock(&register_lock);					\
	return ret;							\
}

write_attribute(attach);
write_attribute(detach);
write_attribute(unregister);
write_attribute(clear_stats);
write_attribute(trigger_gc);
write_attribute(prune_cache);

read_attribute(bucket_size);
read_attribute(block_size);
read_attribute(nbuckets);
read_attribute(tree_depth);
read_attribute(root_usage_percent);
read_attribute(priority_stats);
read_attribute(btree_cache_size);
read_attribute(btree_cache_max_chain);
read_attribute(cache_available_percent);
read_attribute(written);
read_attribute(btree_written);
read_attribute(metadata_written);
read_attribute(btree_avg_keys_written);
read_attribute(active_journal_entries);

sysfs_time_stats_attribute(btree_gc,	sec, ms);
sysfs_time_stats_attribute(btree_split, sec, us);
sysfs_time_stats_attribute(btree_sort,	ms,  us);
sysfs_time_stats_attribute(btree_read,	ms,  us);
sysfs_time_stats_attribute(try_harder,	ms,  us);

read_attribute(btree_nodes);
read_attribute(btree_used_percent);
read_attribute(average_key_size);
read_attribute(dirty_data);
read_attribute(bset_tree_stats);

read_attribute(state);
read_attribute(cache_read_races);
read_attribute(writeback_keys_done);
read_attribute(writeback_keys_failed);
read_attribute(io_errors);
read_attribute(congested);
rw_attribute(congested_read_threshold_us);
rw_attribute(congested_write_threshold_us);

rw_attribute(sequential_cutoff);
rw_attribute(sequential_merge);
rw_attribute(data_csum);
rw_attribute(cache_mode);
rw_attribute(writeback_metadata);
rw_attribute(writeback_running);
rw_attribute(writeback_percent);
rw_attribute(writeback_delay);
rw_attribute(synchronous);
rw_attribute(async_journal);
rw_attribute(discard);
rw_attribute(running);
rw_attribute(label);
rw_attribute(readahead);
rw_attribute(io_error_limit);
rw_attribute(io_error_halflife);
rw_attribute(verify);
rw_attribute(key_merging_disabled);
rw_attribute(gc_always_rewrite);
rw_attribute(freelist_percent);
rw_attribute(cache_replacement_policy);
rw_attribute(btree_shrinker_disabled);

read_attribute(cache_hits);
read_attribute(cache_misses);
read_attribute(cache_bypass_hits);
read_attribute(cache_bypass_misses);
read_attribute(cache_hit_ratio);
read_attribute(cache_readaheads);
read_attribute(cache_miss_collisions);
read_attribute(bypassed);

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

	return_f(cl, NULL, NULL);
}

static void write_super_endio(struct bio *bio, int error)
{
	struct cache *c = bio->bi_private;

	count_io_errors(c, error, "writing superblock");
	closure_put(&c->set->sb_write.cl);
}

void bcache_write_super(struct cache_set *c, struct closure *parent)
{
	struct closure *cl = &c->sb_write.cl;
	struct cache *ca;

	closure_lock(&c->sb_write, parent);

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

	return_f(cl, NULL, NULL);
}

/* UUID io */

static void uuid_endio(struct bio *bio, int error)
{
	/* XXX: check for io errors */
	bcache_endio(container_of(bio->bi_private, struct cache_set,
				  uuid_write),
		     bio, error, "accessing uuids");
	closure_put(bio->bi_private);
}

static void uuid_io(struct cache_set *c, unsigned long rw,
		    struct bkey *k, struct closure *cl)
{
	lockdep_assert_held(&register_lock);
	closure_init(&c->uuid_write, cl);
	cl = &c->uuid_write;

	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bio *bio = PTR_CACHE(c, k, i)->uuid_bio;

		bio_reset(bio);
		bio->bi_rw	= REQ_SYNC|REQ_META|rw;
		bio->bi_size	= KEY_SIZE(k) << 9;

		bio->bi_end_io	= uuid_endio;
		bio->bi_private = cl;
		bio_map(bio, c->uuids);

		closure_get(cl);
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
	return_f(cl, NULL, NULL);
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

	if (pop_bucket_set(c, btree_prio, &k.key, 1, &cl))
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
	__uuid_write(c);

	bcache_journal_meta(c, NULL);
	return 0;
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

	set_closure_fn(&c->prio, NULL, NULL);
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

	return_f(cl, prio_write_done, system_wq);
}

static void prio_write_bucket(struct closure *cl)
{
	struct cache *c = container_of(cl, struct cache, prio);
	struct prio_set *p = c->disk_buckets;
	struct bucket_disk *d = p->data, *end = d + prios_per_bucket(c);

	int i = c->prio_write++;

	if (c->prio_write != prio_buckets(c)) {
		p->next_bucket = c->prio_next[c->prio_write];
		set_closure_fn(&c->prio, prio_write_bucket, system_wq);
	} else
		set_closure_fn(&c->prio, prio_write_journal, system_wq);

	for (struct bucket *b = c->buckets + i * prios_per_bucket(c);
	     b < c->buckets + c->sb.nbuckets && d < end;
	     b++, d++) {
		d->prio = cpu_to_le16(b->prio);
		d->gen = b->disk_gen;
	}

	p->magic = pset_magic(c);
	p->csum = crc64(&p->magic, bucket_bytes(c) - 8);

	prio_io(c, c->prio_next[i], REQ_WRITE);
}

void prio_write(struct cache *c, struct closure *cl)
{
	lockdep_assert_held(&c->set->bucket_lock);
	BUG_ON(atomic_read(&c->prio_written));
	BUG_ON(c->prio_alloc != prio_buckets(c));

	for (struct bucket *b = c->buckets;
	     b < c->buckets + c->sb.nbuckets; b++)
		b->disk_gen = b->gen;

	closure_init(&c->prio, cl);
	set_closure_fn(&c->prio, prio_write_bucket, system_wq);

	c->prio_write = 0;
	c->disk_buckets->seq++;

	atomic_long_add(c->sb.bucket_size * prio_buckets(c),
			&c->meta_sectors_written);

	atomic_set(&c->prio_written, -1);
	closure_put(&c->prio);

	pr_debug("free %zu, free_inc %zu, unused %zu", fifo_used(&c->free),
		 fifo_used(&c->free_inc), fifo_used(&c->unused));
	blktrace_msg(c, "Starting priorities: " buckets_free(c));
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

			closure_get(&c->prio);
			prio_io(c, bucket, READ_SYNC);
			closure_sync(&c->prio);

			/* XXX: doesn't get error handling right with splits */
			if (!test_bit(BIO_UPTODATE, &c->prio_bio->bi_flags))
				return_f(&c->prio, NULL, NULL, -1);

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

	return_f(&c->prio, NULL, NULL, 0);
}

/* Backing device - sysfs */

static void scale_accounting(unsigned long data)
{
	struct cache_accounting *d = (struct cache_accounting *) data;

	for (int i = 0; i < 7; i++) {
		unsigned long t = atomic_xchg(&d->all[i], 0);
		t <<= 16;

		for (int j = 0; j < 4; j++)
			d->sets[j].all[i] += t;
	}

	for (int j = 1; j < 4; j++) {
		struct cache_accounting_set *a = &d->sets[j];

		if (++a->rescale == accounting_rescale[j]) {
			a->rescale = 0;

			for (int i = 0; i < 7; i++) {
				a->all[i] *= accounting_weight - 1;
				a->all[i] /= accounting_weight;
			}
		}
	}

	d->timer.expires += accounting_delay;
	add_timer(&d->timer);
}

#define PRINT_ACCOUNTING()						\
do {									\
	var_print(cache_hits);						\
	var_print(cache_misses);					\
	var_print(cache_bypass_hits);					\
	var_print(cache_bypass_misses);					\
									\
	sysfs_print(cache_hit_ratio,					\
		    DIV_SAFE(var(cache_hits) * 100,			\
			     var(cache_hits) + var(cache_misses)));	\
									\
	var_print(cache_readaheads);					\
	var_print(cache_miss_collisions);				\
	sysfs_hprint(bypassed,	var(sectors_bypassed) << 9);		\
} while (0)

SHOW(cached_dev_accounting)
{
	struct cache_accounting_set *a =
		container_of(kobj, struct cache_accounting_set, kobj);

#define var(stat)		(a->stat >> 16)

	PRINT_ACCOUNTING();

#undef var
	return 0;
}

SHOW(cache_set_accounting)
{
	struct cache_set *c = container_of(kobj->parent, struct cache_set,
					   kobj);
	int idx = kobj - c->accounting;

#define var(stat)					\
({							\
	struct cached_dev *d;				\
	unsigned long ret = 0;				\
	list_for_each_entry(d, &c->devices, list)	\
		ret += d->stats.sets[idx].stat;	\
	ret >> 16;					\
})

	PRINT_ACCOUNTING();

#undef var
	return 0;
}

static struct attribute *accounting_files[] = {
	&sysfs_cache_hits,
	&sysfs_cache_misses,
	&sysfs_cache_bypass_hits,
	&sysfs_cache_bypass_misses,
	&sysfs_cache_hit_ratio,
	&sysfs_cache_readaheads,
	&sysfs_cache_miss_collisions,
	&sysfs_bypassed,
	NULL
};

static void unregister_fake(struct kobject *k)
{
}

SHOW(__cached_dev)
{
	struct cached_dev *d = container_of(kobj, struct cached_dev, kobj);
	const char *states[] = { "no cache", "clean", "dirty", "inconsistent" };

#define var(stat)		(d->stat)

	if (attr == &sysfs_cache_mode)
		return sprint_string_list(buf, bcache_cache_modes + 1,
					  BDEV_CACHE_MODE(&d->sb));

	var_printf(verify,		"%i");
	var_printf(data_csum,		"%i");
	var_printf(writeback_metadata,	"%i");
	var_printf(writeback_running,	"%i");
	var_print(writeback_delay);
	var_print(writeback_percent);

	var_printf(sequential_merge,	"%i");
	var_hprint(sequential_cutoff);
	var_hprint(readahead);

	sysfs_print(running,		atomic_read(&d->running));
	sysfs_print(state,		states[BDEV_STATE(&d->sb)]);

	if (attr == &sysfs_label) {
		memcpy(buf, d->sb.label, SB_LABEL_SIZE);
		buf[SB_LABEL_SIZE + 1] = '\0';
		strcat(buf, "\n");
		return strlen(buf);
	}

#undef var
	return 0;
}
SHOW_LOCKED(cached_dev)

STORE(__cached_dev)
{
	struct cached_dev *d = container_of(kobj, struct cached_dev, kobj);
	unsigned v = size;
	struct cache_set *c;
	struct closure cl;
	closure_init_stack(&cl);

#define d_strtoul(var)		sysfs_strtoul(var, d->var)
#define d_strtoi_h(var)		sysfs_hatoi(var, d->var)

	d_strtoul(verify);
	d_strtoul(data_csum);
	d_strtoul(writeback_metadata);
	d_strtoul(writeback_running);
	d_strtoul(writeback_delay);
	sysfs_strtoul_clamp(writeback_percent, d->writeback_percent, 0, 40);

	d_strtoul(sequential_merge);
	d_strtoi_h(sequential_cutoff);
	d_strtoi_h(readahead);

	if (attr == &sysfs_clear_stats)
		memset(&d->stats.total.all, 0, sizeof(unsigned long) * 7);

	if (attr == &sysfs_running &&
	    strtoul_or_return(buf))
		cached_dev_run(d);

	if (attr == &sysfs_cache_mode) {
		ssize_t v = read_string_list(buf, bcache_cache_modes + 1);

		if (v < 0)
			return v;

		if ((unsigned) v != BDEV_CACHE_MODE(&d->sb)) {
			SET_BDEV_CACHE_MODE(&d->sb, v);
			write_bdev_super(d, NULL);
		}
	}

	if (attr == &sysfs_label) {
		memcpy(d->sb.label, buf, SB_LABEL_SIZE);
		write_bdev_super(d, NULL);
		if (d->c) {
			memcpy(d->c->uuids[d->id].label, buf, SB_LABEL_SIZE);
			uuid_write(d->c);
		}
	}

	if (attr == &sysfs_attach) {
		if (parse_uuid(buf, d->sb.set_uuid) < 16)
			return -EINVAL;

		list_for_each_entry(c, &cache_sets, list) {
			v = cached_dev_attach(d, c);
			if (!v)
				return size;
		}
		size = v;
	}

	if (attr == &sysfs_detach && d->c)
		cached_dev_detach(d);

	/* XXX: this looks sketchy as hell */
	if (attr == &sysfs_unregister &&
	    !atomic_xchg(&d->unregister, 1))
		kobject_put(&d->kobj);

	return size;
}

STORE(cached_dev)
{
	mutex_lock(&register_lock);
	size = __cached_dev_store(kobj, attr, buf, size);

	if (attr == &sysfs_writeback_running ||
	    attr == &sysfs_writeback_percent)
		bcache_writeback_queue(container_of(kobj, struct cached_dev,
						    kobj));

	mutex_unlock(&register_lock);
	return size;
}

/* Backing device */

static void cached_dev_run(struct cached_dev *d)
{
	if (atomic_xchg(&d->running, 1))
		return;

	if (!d->c &&
	    BDEV_STATE(&d->sb) != BDEV_STATE_NONE) {
		struct closure cl;
		closure_init_stack(&cl);

		SET_BDEV_STATE(&d->sb, BDEV_STATE_STALE);
		write_bdev_super(d, &cl);
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

void cached_dev_detach_finish(struct work_struct *w)
{
	struct cached_dev *d = container_of(w, struct cached_dev, detach);
	char buf[BDEVNAME_SIZE];
	struct closure cl;
	closure_init_stack(&cl);

	mutex_lock(&register_lock);

	BUG_ON(!atomic_read(&d->closing));
	BUG_ON(atomic_read(&d->count));

	memset(&d->sb.set_uuid, 0, 16);
	SET_BDEV_STATE(&d->sb, BDEV_STATE_NONE);

	write_bdev_super(d, &cl);
	closure_sync(&cl);

	memcpy(d->c->uuids[d->id].uuid, invalid_uuid, 16);
	d->c->uuids[d->id].invalidated = cpu_to_le32(get_seconds());
	uuid_write(d->c);

	sprintf(buf, "bdev%i", d->id);

	sysfs_remove_link(&d->c->kobj, buf);
	sysfs_remove_link(&d->kobj, "cache");

	list_move(&d->list, &uncached_devices);
	atomic_set(&d->closing, 0);
	kobject_put(&d->c->kobj);
	d->c = NULL;

	printk(KERN_DEBUG "bcache: Caching disabled for %s\n",
	       bdevname(d->bdev, buf));

	mutex_unlock(&register_lock);
}

static void cached_dev_detach(struct cached_dev *d)
{
	lockdep_assert_held(&register_lock);

	if (atomic_xchg(&d->closing, 1))
		return;

	bcache_writeback_queue(d);
	cached_dev_put(d);
}

static int cached_dev_attach(struct cached_dev *d, struct cache_set *c)
{
	uint32_t rtime = cpu_to_le32(get_seconds());
	struct uuid_entry *u;
	struct closure cl;
	const char *msg = "looked up";
	char buf[BDEVNAME_SIZE];
	bdevname(d->bdev, buf);

	closure_init_stack(&cl);
	if (d->c ||
	    atomic_read(&c->closing) ||
	    memcmp(d->sb.set_uuid, c->sb.set_uuid, 16))
		return -ENOENT;

	if (d->sb.block_size < c->sb.block_size) {
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

	sprintf(buf, "bdev%zi", u - c->uuids);
	if (sysfs_create_link(&d->kobj, &c->kobj, "cache") ||
	    sysfs_create_link(&c->kobj, &d->kobj, buf))
		return -ENOMEM;

	/* Deadlocks since we're called via sysfs...
	sysfs_remove_file(&d->kobj, &sysfs_attach);
	 */

	if (is_zero(u->uuid, 16)) {
		memcpy(u->uuid, d->sb.uuid, 16);
		memcpy(u->label, d->sb.label, SB_LABEL_SIZE);
		u->first_reg = u->last_reg = rtime;
		uuid_write(c);

		memcpy(d->sb.set_uuid, c->sb.set_uuid, 16);
		SET_BDEV_STATE(&d->sb, BDEV_STATE_CLEAN);

		write_bdev_super(d, &cl);
		closure_sync(&cl);

		msg = "inserted new";
	} else {
		u->last_reg = rtime;
		uuid_write(c);
	}

	d->id = u - c->uuids;
	d->c = c;
	kobject_get(&c->kobj);
	list_move(&d->list, &c->devices);

	smp_wmb();
	/* d->c must be set before d->count != 0 */
	atomic_set(&d->count, 1);

	if (BDEV_STATE(&d->sb) == BDEV_STATE_DIRTY) {
		atomic_long_set(&d->last_refilled, jiffies ?: 1);
		atomic_inc(&d->count);
		bcache_writeback_queue(d);
	}

	cached_dev_run(d);

	printk(KERN_INFO "bcache: Caching %s, %s UUID %pU\n",
	       bdevname(d->bdev, buf), msg, d->sb.uuid);
	return 0;
}

static void cached_dev_free(struct kobject *kobj)
{
	char name[BDEVNAME_SIZE] = "(unknown)";
	struct cached_dev *d = container_of(kobj, struct cached_dev, kobj);

	lockdep_assert_held(&register_lock);

	/* XXX: background writeback could be in progress... */
	cancel_delayed_work_sync(&d->refill);

	if (d->c)
		kobject_put(&d->c->kobj);

	if (!IS_ERR_OR_NULL(d->bdev)) {
		bdevname(d->bdev, name);
		blk_sync_queue(bdev_get_queue(d->bdev));
		blkdev_put(d->bdev, FMODE_READ|FMODE_WRITE);
	}

	if (d->bio_passthrough)
		mempool_destroy(d->bio_passthrough);
	if (d->unaligned_bvec)
		mempool_destroy(d->unaligned_bvec);
	if (d->bio_split)
		bioset_free(d->bio_split);

	printk(KERN_INFO "bcache: Device %s unregistered\n", name);

	list_del(&d->list);
	kfree(d);
	module_put(THIS_MODULE);
}

static struct cached_dev *cached_dev_alloc(void)
{
	static struct attribute *cached_dev_files[] = {
		&sysfs_attach,
		&sysfs_detach,
		/* Not ready yet
		&sysfs_unregister,
		*/
#if 0
		&sysfs_data_csum,
#endif
		&sysfs_cache_mode,
		&sysfs_writeback_metadata,
		&sysfs_writeback_running,
		&sysfs_writeback_delay,
		&sysfs_writeback_percent,
		&sysfs_sequential_cutoff,
		&sysfs_sequential_merge,
		&sysfs_clear_stats,
		&sysfs_running,
		&sysfs_state,
		&sysfs_label,
		&sysfs_readahead,
#ifdef CONFIG_BCACHE_DEBUG
		&sysfs_verify,
#endif
		NULL
	};
	KTYPE(cached_dev, cached_dev_free);

	static const struct sysfs_ops accounting_ops = {
		.show = cached_dev_accounting_show,
		.store = NULL
	};
	static struct kobj_type accounting_obj = {
		.release = unregister_fake,
		.sysfs_ops = &accounting_ops,
		.default_attrs = accounting_files
	};

	struct cached_dev *d = kzalloc(sizeof(struct cached_dev), GFP_KERNEL);
	if (!d)
		return NULL;

	__module_get(THIS_MODULE);
	kobject_init(&d->kobj, &cached_dev_obj);

	for (int i = 0; i < 4; i++)
		kobject_init(&d->stats.sets[i].kobj, &accounting_obj);

	INIT_LIST_HEAD(&d->list);
	spin_lock_init(&d->lock);
	closure_init_unlocked(&d->sb_write);
	INIT_WORK(&d->detach, cached_dev_detach_finish);

	init_timer(&d->stats.timer);
	d->stats.timer.expires	= jiffies + accounting_delay;
	d->stats.timer.data	= (unsigned long) &d->stats;
	d->stats.timer.function	= scale_accounting;
	add_timer(&d->stats.timer);

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

	if (!(d->bio_split = bioset_create(4, offsetof(struct bbio, bio))) ||
	    !(d->unaligned_bvec = mempool_create_kmalloc_pool(1,
				sizeof(struct bio_vec) * BIO_MAX_PAGES)) ||
	    !(d->bio_passthrough =
			mempool_create_slab_pool(32, passthrough_cache)))
		goto err;

	return d;
err:
	cached_dev_free(&d->kobj);
	return NULL;
}

/* Backing device - bcache superblock */

static int open_dev(struct block_device *b, fmode_t mode)
{
	struct cached_dev *d = b->bd_disk->private_data;
	kobject_get(&d->kobj);
	return 0;
}

static int release_dev(struct gendisk *b, fmode_t mode)
{
	struct cached_dev *d = b->private_data;
	kobject_put(&d->kobj);
	return 0;
}

static int ioctl_dev(struct block_device *b, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	struct cached_dev *d = b->bd_disk->private_data;
	return __blkdev_driver_ioctl(d->bdev, mode, cmd, arg);
}

static const struct block_device_operations bcache_ops = {
	.open		= open_dev,
	.release	= release_dev,
	.ioctl		= ioctl_dev,
	.owner		= THIS_MODULE,
};

static int bcache_congested(void *data, int bits)
{
	struct cached_dev *d = data;
	struct request_queue *q;
	int ret = 0;

	q = bdev_get_queue(d->bdev);
	if (bdi_congested(&q->backing_dev_info, bits))
		return 1;

	if (cached_dev_get(d)) {
		struct cache *ca;

		for_each_cache(ca, d->c) {
			q = bdev_get_queue(ca->bdev);
			ret |= bdi_congested(&q->backing_dev_info, bits);
		}

		cached_dev_put(d);
	}

	return ret;
}

static void bcache_unplug(struct request_queue *q)
{
	struct cached_dev *d = q->queuedata;

	blk_unplug(bdev_get_queue(d->bdev));

	if (cached_dev_get(d)) {
		struct cache *c;

		for_each_cache(c, d->c)
			blk_unplug(bdev_get_queue(c->bdev));

		cached_dev_put(d);
	}
}

static const char *register_bdev(struct cache_sb *sb, struct page *sb_page,
				 struct block_device *bdev)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";
	struct cache_set *c;
	struct request_queue *q;

	struct cached_dev *d = cached_dev_alloc();
	if (!d)
		return err;

	memcpy(&d->sb, sb, sizeof(struct cache_sb));
	d->sb_bio.bi_io_vec[0].bv_page = sb_page;
	d->bdev = bdev;
	d->bdev->bd_holder = d;

	d->disk = alloc_disk(1);
	if (!d->disk)
		goto err;

	snprintf(d->disk->disk_name, DISK_NAME_LEN, "bcache%i", bcache_minor);
	set_capacity(d->disk, d->bdev->bd_part->nr_sects - 16);

	d->disk->major		= bcache_major;
	d->disk->first_minor	= bcache_minor++;
	d->disk->fops		= &bcache_ops;
	d->disk->queue		= blk_alloc_queue(GFP_KERNEL);
	d->disk->private_data	= d;
	if (!d->disk->queue)
		goto err;

	blk_queue_make_request(d->disk->queue, bcache_make_request);

	q = bdev_get_queue(d->bdev);

	d->disk->queue->unplug_fn		= bcache_unplug;
	d->disk->queue->queuedata		= d;
	d->disk->queue->limits.max_hw_sectors	= UINT_MAX;
	d->disk->queue->limits.max_sectors	= UINT_MAX;
	d->disk->queue->limits.max_segment_size	= UINT_MAX;
	d->disk->queue->limits.max_segments	= BIO_MAX_PAGES;
	d->disk->queue->limits.max_discard_sectors = UINT_MAX;
	d->disk->queue->limits.logical_block_size  = block_bytes(d);
	d->disk->queue->limits.physical_block_size = block_bytes(d);
	set_bit(QUEUE_FLAG_NONROT,	&d->disk->queue->queue_flags);
	set_bit(QUEUE_FLAG_DISCARD,	&d->disk->queue->queue_flags);

	d->disk->queue->backing_dev_info.congested_fn = bcache_congested;
	d->disk->queue->backing_dev_info.congested_data = d;

	err = "error creating kobject";
	if (kobject_add(&d->kobj, &part_to_dev(bdev->bd_part)->kobj, "bcache"))
		goto err;

	for (int i = 0; i < 4; i++)
		if (kobject_add(&d->stats.sets[i].kobj, &d->kobj,
				"stats_%s", accounting_types[i]))
			goto err;

	list_add(&d->list, &uncached_devices);
	list_for_each_entry(c, &cache_sets, list)
		cached_dev_attach(d, c);

	if (BDEV_STATE(&d->sb) == BDEV_STATE_NONE ||
	    BDEV_STATE(&d->sb) == BDEV_STATE_STALE)
		cached_dev_run(d);

	return NULL;
err:
	kobject_put(&d->kobj);
	printk(KERN_DEBUG "bcache: error opening %s: %s\n",
	       bdevname(bdev, name), err);
	/* Return NULL instead of an error because kobject_put() cleans
	 * everything up
	 */
	return NULL;
}

/* Cache set - sysfs */

SHOW(__cache_set)
{
	unsigned root_usage(struct cache_set *c)
	{
		unsigned bytes = 0;
		struct bkey *k;

		for_each_key_filter(c->root, k, ptr_bad)
			bytes += bkey_bytes(k);

		return (bytes * 100) / btree_bytes(c);
	}

	size_t cache_size(struct cache_set *c)
	{
		size_t ret = 0;
		struct btree *b;

		mutex_lock(&c->bucket_lock);
		list_for_each_entry(b, &c->lru, lru)
			ret += 1 << (b->page_order + PAGE_SHIFT);

		mutex_unlock(&c->bucket_lock);
		return ret;
	}

	unsigned cache_max_chain(struct cache_set *c)
	{
		unsigned ret = 0;
		mutex_lock(&c->bucket_lock);

		for (struct hlist_head *h = c->bucket_hash;
		     h < c->bucket_hash + (1 << BUCKET_HASH_BITS);
		     h++) {
			unsigned i = 0;
			struct hlist_node *p;

			hlist_for_each(p, h)
				i++;

			ret = max(ret, i);
		}

		mutex_unlock(&c->bucket_lock);
		return ret;
	}

	unsigned btree_used(struct cache_set *c)
	{
		return div64_u64(c->gc_stats.key_bytes * 100,
				 (c->gc_stats.nodes ?: 1) * btree_bytes(c));
	}

	unsigned average_key_size(struct cache_set *c)
	{
		return c->gc_stats.nkeys
			? div64_u64(c->gc_stats.data, c->gc_stats.nkeys)
			: 0;
	}

	struct cache_set *c = container_of(kobj, struct cache_set, kobj);

	sysfs_print(synchronous,		CACHE_SYNC(&c->sb));
	sysfs_print(async_journal,		CACHE_ASYNC_JOURNAL(&c->sb));
	sysfs_hprint(bucket_size,		bucket_bytes(c));
	sysfs_hprint(block_size,		block_bytes(c));
	sysfs_print(tree_depth,			c->root->level);
	sysfs_print(root_usage_percent,		root_usage(c));
	sysfs_print(btree_avg_keys_written,
		    DIV_SAFE(atomic_long_read(&c->keys_write_count),
			     atomic_long_read(&c->btree_write_count)));

	sysfs_hprint(btree_cache_size,		cache_size(c));
	sysfs_print(btree_cache_max_chain,	cache_max_chain(c));
	sysfs_print(cache_available_percent,	100 - c->gc_stats.in_use);

	sysfs_print_time_stats(&c->btree_gc_time,	btree_gc, sec, ms);
	sysfs_print_time_stats(&c->btree_split_time,	btree_split, sec, us);
	sysfs_print_time_stats(&c->sort_time,		btree_sort, ms, us);
	sysfs_print_time_stats(&c->btree_read_time,	btree_read, ms, us);
	sysfs_print_time_stats(&c->try_harder_time,	try_harder, ms, us);

	sysfs_print(btree_used_percent,	btree_used(c));
	sysfs_print(btree_nodes,	c->gc_stats.nodes);
	sysfs_hprint(dirty_data,	c->gc_stats.dirty);
	sysfs_hprint(average_key_size,	average_key_size(c));

	sysfs_print(cache_read_races,
		    atomic_long_read(&c->cache_read_races));

	sysfs_print(writeback_keys_done,
		    atomic_long_read(&c->writeback_keys_done));
	sysfs_print(writeback_keys_failed,
		    atomic_long_read(&c->writeback_keys_failed));

	/* See count_io_errors for why 88 */
	sysfs_print(io_error_halflife,	c->error_decay * 88);
	sysfs_print(io_error_limit,	c->error_limit >> IO_ERROR_SHIFT);

	sysfs_hprint(congested,
		     ((uint64_t) bcache_get_congested(c)) << 9);
	sysfs_print(congested_read_threshold_us,
		    c->congested_read_threshold_us);
	sysfs_print(congested_write_threshold_us,
		    c->congested_write_threshold_us);

	sysfs_print(active_journal_entries,	fifo_used(&c->journal.pin));
	sysfs_printf(verify,			"%i", c->verify);
	sysfs_printf(key_merging_disabled,	"%i", c->key_merging_disabled);
	sysfs_printf(gc_always_rewrite,		"%i", c->gc_always_rewrite);
	sysfs_printf(btree_shrinker_disabled,	"%i", c->shrinker_disabled);

	if (attr == &sysfs_bset_tree_stats)
		return bset_print_stats(c, buf);

	return 0;
}
SHOW_LOCKED(cache_set)

STORE(__cache_set)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
	struct closure cl;
	closure_init_stack(&cl);

	if (attr == &sysfs_unregister &&
	    !atomic_xchg(&c->closing, 1))
		schedule_work(&c->unregister);

	if (attr == &sysfs_synchronous) {
		bool sync = strtoul_or_return(buf);

		if (sync != CACHE_SYNC(&c->sb)) {
			SET_CACHE_SYNC(&c->sb, sync);
			bcache_write_super(c, NULL);
		}
	}

	if (attr == &sysfs_async_journal) {
		bool sync = strtoul_or_return(buf);

		if (sync != CACHE_ASYNC_JOURNAL(&c->sb)) {
			SET_CACHE_ASYNC_JOURNAL(&c->sb, sync);
			bcache_write_super(c, NULL);
		}
	}

	if (attr == &sysfs_clear_stats) {
		atomic_long_set(&c->writeback_keys_done,	0);
		atomic_long_set(&c->writeback_keys_failed,	0);
		atomic_long_set(&c->btree_write_count,		0);
		atomic_long_set(&c->keys_write_count,		0);

		memset(&c->gc_stats, 0, sizeof(struct gc_stat));
	}

	if (attr == &sysfs_trigger_gc)
		queue_work(bcache_wq, &c->gc_work);

	if (attr == &sysfs_prune_cache) {
		unsigned long v = strtoul_or_return(buf);
		c->shrink.shrink(&c->shrink, v, NULL);
	}

	sysfs_strtoul(congested_read_threshold_us,
		      c->congested_read_threshold_us);
	sysfs_strtoul(congested_write_threshold_us,
		      c->congested_write_threshold_us);

	if (attr == &sysfs_io_error_limit)
		c->error_limit = strtoul_or_return(buf) << IO_ERROR_SHIFT;

	/* See count_io_errors() for why 88 */
	if (attr == &sysfs_io_error_halflife)
		c->error_decay = strtoul_or_return(buf) / 88;

	sysfs_strtoul(verify,			c->verify);
	sysfs_strtoul(key_merging_disabled,	c->key_merging_disabled);
	sysfs_strtoul(gc_always_rewrite,	c->gc_always_rewrite);
	sysfs_strtoul(btree_shrinker_disabled,	c->shrinker_disabled);

	return size;
}
STORE_LOCKED(cache_set)

SHOW(cache_set_internal)
{
	struct cache_set *c = container_of(kobj, struct cache_set, internal);
	return cache_set_show(&c->kobj, attr, buf);
}

STORE(cache_set_internal)
{
	struct cache_set *c = container_of(kobj, struct cache_set, internal);
	return cache_set_store(&c->kobj, attr, buf, size);
}

/* Cache set */

bool cache_set_error(struct cache_set *c, const char *m, ...)
{
	va_list args;

	if (atomic_xchg(&c->closing, 1))
		return false;

	/* XXX: we can be called from atomic context
	acquire_console_sem();
	*/

	printk(KERN_ERR "bcache: error on %pU: ", c->sb.set_uuid);

	va_start(args, m);
	vprintk(m, args);
	va_end(args);

	printk(", disabling caching\n");

	queue_work(bcache_wq, &c->unregister);
	return true;
}

static void cache_set_free(struct kobject *kobj)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);
	struct cache *ca;
	struct btree *b;

	struct btree_op op;
	btree_op_init_stack(&op);

	lockdep_assert_held(&register_lock);

	/* Wait for/cancel any pending gc: we take gc_lock so that gc can't
	 * requeue itself while we're canceling the work
	 * Only safe (?) because gc_work uses trylock
	 */
	mutex_lock(&c->gc_lock);
	cancel_work_sync(&c->gc_work);
	mutex_unlock(&c->gc_lock);

	if (!IS_ERR_OR_NULL(c->root))
		list_add(&c->root->lru, &c->lru);

	/* Should skip this if we're unregistering because of an error */
	list_for_each_entry(b, &c->lru, lru)
		if (b->write)
			btree_write(b, true, &op);

	/*
	 * The if (ca) is a hack - when we finish multiple cache device support
	 * we'll need a more general solution.
	 */
	for_each_cache(ca, c)
		if (ca)
			closure_wait_event(&c->bucket_wait, &op.cl,
					   atomic_read(&ca->prio_written) >= 0);

	closure_sync(&op.cl);

	/*
	 * bcache_journal_wait() calls journal_try_write() - should do the wait
	 * without the write if unregistering because of an error
	 *
	 * XXX: doesn't handle an in flight journal write
	 */
	if (c->journal.cur)
		bcache_journal_meta(c, &op.cl);

	closure_sync(&op.cl);

	cancel_work_sync(&c->journal.work);

	bcache_open_buckets_free(c);
	bcache_btree_cache_free(c);
	bcache_journal_free(c);

	/* Don't free cache until no io could be pending */
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

	printk(KERN_INFO "bcache: Cache set %pU unregistered\n",
	       c->sb.set_uuid);

	list_del(&c->list);
	kfree(c);
	module_put(THIS_MODULE);
}

static void cache_set_unregister(struct work_struct *w)
{
	struct cache_set *c = container_of(w, struct cache_set, unregister);
	struct cached_dev *d, *t;

	kobject_del(&c->kobj);

	mutex_lock(&register_lock);

	kobject_put(&c->internal);

	for (int i = 0; i < 4; i++)
		kobject_put(&c->accounting[i]);

	list_for_each_entry_safe(d, t, &c->devices, list)
		cached_dev_detach(d);

	kobject_put(&c->kobj);

	mutex_unlock(&register_lock);
}

#define alloc_bucket_pages(gfp, c)			\
	((void *) __get_free_pages(__GFP_ZERO|gfp, ilog2(bucket_pages(c))))

struct cache_set *cache_set_alloc(struct cache_sb *sb)
{
	static struct attribute *cache_set_files[] = {
		&sysfs_unregister,
		&sysfs_synchronous,
		&sysfs_async_journal,
		&sysfs_bucket_size,
		&sysfs_block_size,
		&sysfs_tree_depth,
		&sysfs_root_usage_percent,
		&sysfs_btree_cache_size,
		&sysfs_cache_available_percent,

		&sysfs_average_key_size,
		&sysfs_dirty_data,

		&sysfs_io_error_limit,
		&sysfs_io_error_halflife,
		&sysfs_congested,
		&sysfs_congested_read_threshold_us,
		&sysfs_congested_write_threshold_us,
		&sysfs_clear_stats,
		NULL
	};
	KTYPE(cache_set, cache_set_free);

	static struct attribute *cache_set_internal_files[] = {
		&sysfs_active_journal_entries,

		sysfs_time_stats_attribute_list(btree_gc, sec, ms)
		sysfs_time_stats_attribute_list(btree_split, sec, us)
		sysfs_time_stats_attribute_list(btree_sort, ms, us)
		sysfs_time_stats_attribute_list(btree_read, ms, us)
		sysfs_time_stats_attribute_list(try_harder, ms, us)

		&sysfs_btree_avg_keys_written,
		&sysfs_btree_nodes,
		&sysfs_btree_used_percent,
		&sysfs_btree_cache_max_chain,

		&sysfs_bset_tree_stats,
		&sysfs_cache_read_races,
		&sysfs_writeback_keys_done,
		&sysfs_writeback_keys_failed,

		&sysfs_trigger_gc,
		&sysfs_prune_cache,
#ifdef CONFIG_BCACHE_DEBUG
		&sysfs_verify,
		&sysfs_key_merging_disabled,
#endif
		&sysfs_gc_always_rewrite,
		&sysfs_btree_shrinker_disabled,
		NULL
	};
	KTYPE(cache_set_internal, unregister_fake);

	static const struct sysfs_ops accounting_ops = {
		.show = cache_set_accounting_show,
		.store = NULL
	};
	static struct kobj_type accounting_obj = {
		.release = unregister_fake,
		.sysfs_ops = &accounting_ops,
		.default_attrs = accounting_files
	};

	int iter_size;
	struct cache_set *c = kzalloc(sizeof(struct cache_set), GFP_KERNEL);
	if (!c)
		return NULL;

	__module_get(THIS_MODULE);
	kobject_init(&c->kobj, &cache_set_obj);
	kobject_init(&c->internal, &cache_set_internal_obj);

	for (int i = 0; i < 4; i++)
		kobject_init(&c->accounting[i], &accounting_obj);

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
	mutex_init(&c->gc_lock);
	mutex_init(&c->fill_lock);
	mutex_init(&c->sort_lock);
	spin_lock_init(&c->sort_time_lock);
	closure_init_unlocked(&c->sb_write);
	spin_lock_init(&c->btree_read_time_lock);

	INIT_WORK(&c->unregister, cache_set_unregister);
	INIT_LIST_HEAD(&c->list);
	INIT_LIST_HEAD(&c->devices);
	INIT_LIST_HEAD(&c->lru);
	INIT_LIST_HEAD(&c->freed);
	INIT_LIST_HEAD(&c->data_buckets);

	c->search = mempool_create_slab_pool(32, search_cache);
	if (!c->search)
		goto err;

	iter_size = (sb->bucket_size / sb->block_size + 1) *
		sizeof(struct btree_iter_set);

	if (!(c->bio_meta = mempool_create_kmalloc_pool(2,
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
	cache_set_free(&c->kobj);
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

		list_del_init(&c->root->lru);
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
		mutex_lock(&c->gc_lock);

		for_each_cache(ca, c) {
			ca->sb.keys = clamp_t(int, ca->sb.nbuckets >> 7,
					      2, SB_JOURNAL_BUCKETS);

			for (int i = 0; i < ca->sb.keys; i++)
				ca->sb.d[i] = ca->sb.first_bucket + i;
		}

		btree_gc_finish(c);

		err = "cannot allocate new UUID bucket";
		if (uuid_write(c))
			goto err;

		err = "cannot allocate new btree root";
		c->root = bcache_btree_alloc(c, 0, &op.cl);
		if (IS_ERR_OR_NULL(c->root))
			goto err;

		bkey_copy_key(&c->root->key, &MAX_KEY);
		btree_write(c->root, true, &op);

		mutex_lock(&c->bucket_lock);
		for_each_cache(ca, c) {
			free_some_buckets(ca);
			prio_write(ca, &op.cl);
		}
		mutex_unlock(&c->bucket_lock);

		closure_sync(&op.cl);
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
		mutex_unlock(&c->gc_lock);
	}

	closure_sync(&op.cl);
	c->sb.last_mount = get_seconds();
	bcache_write_super(c, NULL);

	list_for_each_entry_safe(d, t, &uncached_devices, list)
		cached_dev_attach(d, c);

	return;
err:
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

	for (int i = 0; i < 4; i++)
		if (kobject_add(&c->accounting[i], &c->kobj,
				"stats_%s", accounting_types[i]))
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
	schedule_work(&c->unregister);
	return err;
}

/* Cache device */

SHOW(__cache)
{
	struct cache *c = container_of(kobj, struct cache, kobj);

	sysfs_hprint(bucket_size,	bucket_bytes(c));
	sysfs_hprint(block_size,	block_bytes(c));
	sysfs_print(nbuckets,		c->sb.nbuckets);
	sysfs_print(discard,		c->discard);
	sysfs_hprint(written, atomic_long_read(&c->sectors_written) << 9);
	sysfs_hprint(btree_written,
		     atomic_long_read(&c->btree_sectors_written) << 9);
	sysfs_hprint(metadata_written,
		     (atomic_long_read(&c->meta_sectors_written) +
		      atomic_long_read(&c->btree_sectors_written)) << 9);

	sysfs_print(io_errors,
		    atomic_read(&c->io_errors) >> IO_ERROR_SHIFT);

	sysfs_print(freelist_percent, c->free.size * 100 /
		    ((size_t) c->sb.nbuckets));

	if (attr == &sysfs_cache_replacement_policy)
		return sprint_string_list(buf, cache_replacement_policies,
					  CACHE_REPLACEMENT(&c->sb));

	if (attr == &sysfs_priority_stats) {
		int cmp(const void *l, const void *r)
		{	return *((uint16_t *) r) - *((uint16_t *) l); }

		/* Number of quantiles we compute */
		const unsigned nq = 31;

		size_t n = c->sb.nbuckets, i, unused, btree;
		uint64_t sum = 0;
		uint16_t q[nq], *p, *cached;
		ssize_t ret;

		cached = p = vmalloc(c->sb.nbuckets * sizeof(uint16_t));
		if (!p)
			return -ENOMEM;

		mutex_lock(&c->set->bucket_lock);
		for (i = c->sb.first_bucket; i < n; i++)
			p[i] = c->buckets[i].prio;
		mutex_unlock(&c->set->bucket_lock);

		sort(p, n, sizeof(uint16_t), cmp, NULL);

		while (n &&
		       !cached[n - 1])
			--n;

		unused = c->sb.nbuckets - n;

		while (cached < p + n &&
		       *cached == btree_prio)
			cached++;

		btree = cached - p;
		n -= btree;

		for (i = 0; i < n; i++)
			sum += initial_prio - cached[i];

		if (n)
			do_div(sum, n);

		for (i = 0; i < nq; i++)
			q[i] = initial_prio - cached[n * (i + 1) / (nq + 1)];

		vfree(p);

		ret = snprintf(buf, PAGE_SIZE,
			       "Unused:		%zu%%\n"
			       "Metadata:	%zu%%\n"
			       "Average:	%llu\n"
			       "Sectors per Q:	%zu\n"
			       "Quantiles:	[",
			       unused * 100 / (size_t) c->sb.nbuckets,
			       btree * 100 / (size_t) c->sb.nbuckets, sum,
			       n * c->sb.bucket_size / (nq + 1));

		for (i = 0; i < nq && ret < (ssize_t) PAGE_SIZE; i++)
			ret += snprintf(buf + ret, PAGE_SIZE - ret,
					i < nq - 1 ? "%u " : "%u]\n", q[i]);

		buf[PAGE_SIZE - 1] = '\0';
		return ret;
	}

	return 0;
}
SHOW_LOCKED(cache)

STORE(__cache)
{
	struct cache *c = container_of(kobj, struct cache, kobj);
	struct closure cl;
	closure_init_stack(&cl);

	if (attr == &sysfs_discard) {
		bool v = strtoul_or_return(buf);

		if (blk_queue_discard(bdev_get_queue(c->bdev)))
			c->discard = v;

		if (v != CACHE_DISCARD(&c->sb)) {
			SET_CACHE_DISCARD(&c->sb, v);
			bcache_write_super(c->set, NULL);
		}
	}

	if (attr == &sysfs_cache_replacement_policy) {
		ssize_t v = read_string_list(buf, cache_replacement_policies);

		if (v < 0)
			return v;

		if ((unsigned) v != CACHE_REPLACEMENT(&c->sb)) {
			mutex_lock(&c->set->bucket_lock);
			SET_CACHE_REPLACEMENT(&c->sb, v);
			mutex_unlock(&c->set->bucket_lock);

			bcache_write_super(c->set, NULL);
		}
	}

	if (attr == &sysfs_freelist_percent) {
		DECLARE_FIFO(long, free);
		long i;
		size_t p = strtoul_or_return(buf);

		p = clamp_t(size_t,
			    ((size_t) c->sb.nbuckets * p) / 100,
			    roundup_pow_of_two(c->sb.nbuckets) >> 9,
			    c->sb.nbuckets / 2);

		if (!init_fifo_exact(&free, p, GFP_KERNEL))
			return -ENOMEM;

		mutex_lock(&c->set->bucket_lock);

		fifo_move(&free, &c->free);
		fifo_swap(&free, &c->free);

		mutex_unlock(&c->set->bucket_lock);

		while (fifo_pop(&free, i))
			atomic_dec(&c->buckets[i].pin);

		free_fifo(&free);
	}

	if (attr == &sysfs_clear_stats) {
		atomic_long_set(&c->sectors_written, 0);
		atomic_long_set(&c->btree_sectors_written, 0);
		atomic_long_set(&c->meta_sectors_written, 0);
		atomic_set(&c->io_count, 0);
		atomic_set(&c->io_errors, 0);
	}

	return size;
}
STORE_LOCKED(cache)

static void cache_free(struct kobject *kobj)
{
	struct cache *c = container_of(kobj, struct cache, kobj);

	lockdep_assert_held(&register_lock);

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
		blkdev_put(c->bdev, FMODE_READ|FMODE_WRITE);
	}

	kfree(c);
	module_put(THIS_MODULE);
}

static struct cache *cache_alloc(struct cache_sb *sb)
{
	static struct attribute *cache_files[] = {
		&sysfs_bucket_size,
		&sysfs_block_size,
		&sysfs_nbuckets,
		&sysfs_priority_stats,
		&sysfs_discard,
		&sysfs_written,
		&sysfs_btree_written,
		&sysfs_metadata_written,
		&sysfs_io_errors,
		&sysfs_clear_stats,
		&sysfs_freelist_percent,
		&sysfs_cache_replacement_policy,
		NULL
	};
	KTYPE(cache, cache_free);

	size_t free;
	struct bucket *b;
	struct cache *c = kzalloc(sizeof(struct cache), GFP_KERNEL);
	if (!c)
		return NULL;

	__module_get(THIS_MODULE);
	kobject_init(&c->kobj, &cache_obj);

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

	return c;
err:
	kobject_put(&c->kobj);
	return NULL;
}

static const char *register_cache(struct cache_sb *sb, struct page *sb_page,
				  struct block_device *bdev)
{
	char name[BDEVNAME_SIZE];
	const char *err = "cannot allocate memory";
	struct cache *c = cache_alloc(sb);
	if (!c)
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

	if (sb->version == CACHE_BACKING_DEV)
		err = register_bdev(sb, sb_page, bdev);
	else
		err = register_cache(sb, sb_page, bdev);

	if (err) {
		/* register_(bdev|cache) will only return an error if they
		 * didn't get far enough to create the kobject - if they did,
		 * the kobject destructor will do this cleanup.
		 */
		put_page(sb_page);
err_close:
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE);
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
}

static int __init bcache_init(void)
{
	static const struct attribute *files[] = {
		&ksysfs_register.attr,
		&ksysfs_register_quiet.attr,
		NULL
	};

	mutex_init(&register_lock);

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
