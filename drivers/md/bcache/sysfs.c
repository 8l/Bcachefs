/*
 * bcache sysfs interfaces
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "sysfs.h"
#include "btree.h"
#include "journal.h"
#include "request.h"
#include "writeback.h"

#include <linux/blkdev.h>
#include <linux/sort.h>

static const char * const cache_replacement_policies[] = {
	"lru",
	"fifo",
	"random",
	NULL
};

static const char * const error_actions[] = {
	"unregister",
	"panic",
	NULL
};

write_attribute(attach);
write_attribute(detach);
write_attribute(unregister);
write_attribute(stop);
write_attribute(clear_stats);
write_attribute(trigger_gc);
write_attribute(prune_cache);
write_attribute(flash_vol_create);

read_attribute(bucket_size);
read_attribute(block_size);
read_attribute(nbuckets);
read_attribute(tree_depth);
read_attribute(root_usage_percent);
read_attribute(priority_stats);
read_attribute(reserve_stats);
read_attribute(btree_cache_size);
read_attribute(cache_available_percent);
read_attribute(written);
read_attribute(btree_written);
read_attribute(metadata_written);
read_attribute(journal_debug);

sysfs_time_stats_attribute(btree_gc,	sec, ms);
sysfs_time_stats_attribute(btree_split, sec, us);
sysfs_time_stats_attribute(btree_sort,	ms,  us);
sysfs_time_stats_attribute(btree_read,	ms,  us);

read_attribute(btree_gc_count);

read_attribute(btree_nodes);
read_attribute(btree_used_percent);
read_attribute(average_key_size);
read_attribute(dirty_data);
read_attribute(dirty_buckets);
read_attribute(cached_data);
read_attribute(cached_buckets);
read_attribute(meta_buckets);
read_attribute(alloc_buckets);
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
rw_attribute(data_csum);
rw_attribute(cache_mode);
rw_attribute(writeback_metadata);
rw_attribute(writeback_running);
rw_attribute(writeback_percent);
sysfs_pd_controller_attribute(writeback);

read_attribute(stripe_size);
read_attribute(partial_stripes_expensive);

rw_attribute(synchronous);
rw_attribute(journal_delay_ms);
rw_attribute(discard);
rw_attribute(running);
rw_attribute(label);
rw_attribute(readahead);
rw_attribute(errors);
rw_attribute(io_error_limit);
rw_attribute(io_error_halflife);
rw_attribute(btree_scan_ratelimit);
rw_attribute(verify);
rw_attribute(bypass_torture_test);
rw_attribute(key_merging_disabled);
rw_attribute(gc_always_rewrite);
rw_attribute(expensive_debug_checks);
rw_attribute(cache_replacement_policy);
rw_attribute(btree_shrinker_disabled);

rw_attribute(copy_gc_enabled);
rw_attribute(tiering_enabled);
sysfs_pd_controller_attribute(tiering);

rw_attribute(size);
rw_attribute(meta_replicas);
rw_attribute(data_replicas);
rw_attribute(tier);
sysfs_pd_controller_attribute(copy_gc);

SHOW(__bch_cached_dev)
{
	struct cached_dev *dc = container_of(kobj, struct cached_dev,
					     disk.kobj);
	const char *states[] = { "no cache", "clean", "dirty", "inconsistent" };

#define var(stat)		(dc->stat)

	if (attr == &sysfs_cache_mode)
		return bch_snprint_string_list(buf, PAGE_SIZE,
					       bch_cache_modes + 1,
					       BDEV_CACHE_MODE(&dc->sb));

	sysfs_printf(data_csum,		"%i", dc->disk.data_csum);
	var_printf(verify,		"%i");
	var_printf(bypass_torture_test,	"%i");
	var_printf(writeback_metadata,	"%i");
	var_printf(writeback_running,	"%i");
	var_print(writeback_percent);
	sysfs_pd_controller_show(writeback, &dc->writeback_pd);

	sysfs_hprint(dirty_data,
		     bcache_dev_sectors_dirty(&dc->disk) << 9);

	sysfs_hprint(stripe_size,	dc->disk.stripe_size << 9);
	var_printf(partial_stripes_expensive,	"%u");

	var_hprint(sequential_cutoff);
	var_hprint(readahead);

	sysfs_print(running,		atomic_read(&dc->running));
	sysfs_print(state,		states[BDEV_STATE(&dc->sb)]);

	if (attr == &sysfs_label) {
		memcpy(buf, dc->sb.label, SB_LABEL_SIZE);
		buf[SB_LABEL_SIZE + 1] = '\0';
		strcat(buf, "\n");
		return strlen(buf);
	}

#undef var
	return 0;
}
SHOW_LOCKED(bch_cached_dev)

STORE(__cached_dev)
{
	struct cached_dev *dc = container_of(kobj, struct cached_dev,
					     disk.kobj);
	unsigned v = size;
	struct cache_set *c;
	struct kobj_uevent_env *env;

#define d_strtoul(var)		sysfs_strtoul(var, dc->var)
#define d_strtoul_nonzero(var)	sysfs_strtoul_clamp(var, dc->var, 1, INT_MAX)
#define d_strtoi_h(var)		sysfs_hatoi(var, dc->var)

	sysfs_strtoul(data_csum,	dc->disk.data_csum);
	d_strtoul(verify);
	d_strtoul(bypass_torture_test);
	d_strtoul(writeback_metadata);
	d_strtoul(writeback_running);
	sysfs_strtoul_clamp(writeback_percent, dc->writeback_percent, 0, 40);
	sysfs_pd_controller_store(writeback, &dc->writeback_pd);

	d_strtoi_h(sequential_cutoff);
	d_strtoi_h(readahead);

	if (attr == &sysfs_clear_stats)
		bch_cache_accounting_clear(&dc->accounting);

	if (attr == &sysfs_running &&
	    strtoul_or_return(buf))
		bch_cached_dev_run(dc);

	if (attr == &sysfs_cache_mode) {
		ssize_t v = bch_read_string_list(buf, bch_cache_modes + 1);

		if (v < 0)
			return v;

		if ((unsigned) v != BDEV_CACHE_MODE(&dc->sb)) {
			SET_BDEV_CACHE_MODE(&dc->sb, v);
			bch_write_bdev_super(dc, NULL);
		}
	}

	if (attr == &sysfs_label) {
		if (size > SB_LABEL_SIZE)
			return -EINVAL;

		mutex_lock(&dc->disk.inode_lock);

		memcpy(dc->sb.label, buf, size);
		if (size < SB_LABEL_SIZE)
			dc->sb.label[size] = '\0';
		if (size && dc->sb.label[size - 1] == '\n')
			dc->sb.label[size - 1] = '\0';

		memcpy(dc->disk.inode.i_label,
		       dc->sb.label, SB_LABEL_SIZE);

		bch_write_bdev_super(dc, NULL);

		if (dc->disk.c)
			bch_inode_update(dc->disk.c, &dc->disk.inode.i_inode);

		mutex_unlock(&dc->disk.inode_lock);

		env = kzalloc(sizeof(struct kobj_uevent_env), GFP_KERNEL);
		if (!env)
			return -ENOMEM;
		add_uevent_var(env, "DRIVER=bcache");
		add_uevent_var(env, "CACHED_UUID=%pU", dc->sb.uuid.b),
		add_uevent_var(env, "CACHED_LABEL=%s", buf);
		kobject_uevent_env(
			&disk_to_dev(dc->disk.disk)->kobj, KOBJ_CHANGE, env->envp);
		kfree(env);
	}

	if (attr == &sysfs_attach) {
		if (uuid_parse(buf, &dc->sb.set_uuid))
			return -EINVAL;

		list_for_each_entry(c, &bch_cache_sets, list) {
			v = bch_cached_dev_attach(dc, c);
			if (!v)
				return size;
		}

		pr_err("Can't attach %s: cache set not found", buf);
		size = v;
	}

	if (attr == &sysfs_detach && dc->disk.c)
		bch_cached_dev_detach(dc);

	if (attr == &sysfs_stop)
		bcache_device_stop(&dc->disk);

	return size;
}

STORE(bch_cached_dev)
{
	struct cached_dev *dc = container_of(kobj, struct cached_dev,
					     disk.kobj);

	mutex_lock(&bch_register_lock);
	size = __cached_dev_store(kobj, attr, buf, size);

	if (attr == &sysfs_writeback_running)
		bch_writeback_queue(dc);

	if (attr == &sysfs_writeback_percent)
		schedule_delayed_work(&dc->writeback_pd.update,
				      dc->writeback_pd.update_seconds * HZ);

	mutex_unlock(&bch_register_lock);
	return size;
}

static struct attribute *bch_cached_dev_files[] = {
	&sysfs_attach,
	&sysfs_detach,
	&sysfs_stop,
#if 0
	&sysfs_data_csum,
#endif
	&sysfs_cache_mode,
	&sysfs_writeback_metadata,
	&sysfs_writeback_running,
	&sysfs_writeback_percent,
	sysfs_pd_controller_files(writeback),
	&sysfs_dirty_data,
	&sysfs_stripe_size,
	&sysfs_partial_stripes_expensive,
	&sysfs_sequential_cutoff,
	&sysfs_clear_stats,
	&sysfs_running,
	&sysfs_state,
	&sysfs_label,
	&sysfs_readahead,
#ifdef CONFIG_BCACHE_DEBUG
	&sysfs_verify,
	&sysfs_bypass_torture_test,
#endif
	NULL
};
KTYPE(bch_cached_dev);

SHOW(bch_flash_dev)
{
	struct bcache_device *d = container_of(kobj, struct bcache_device,
					       kobj);

	sysfs_printf(data_csum,	"%i", d->data_csum);
	sysfs_hprint(size,	d->inode.i_inode.i_size);

	if (attr == &sysfs_label) {
		memcpy(buf, d->inode.i_label, SB_LABEL_SIZE);
		buf[SB_LABEL_SIZE + 1] = '\0';
		strcat(buf, "\n");
		return strlen(buf);
	}

	return 0;
}

STORE(__bch_flash_dev)
{
	struct bcache_device *d = container_of(kobj, struct bcache_device,
					       kobj);

	sysfs_strtoul(data_csum,	d->data_csum);

	if (attr == &sysfs_size) {
		uint64_t v;
		strtoi_h_or_return(buf, v);

		mutex_lock(&d->inode_lock);

		d->inode.i_inode.i_size = v;
		bch_inode_update(d->c, &d->inode.i_inode);
		set_capacity(d->disk, d->inode.i_inode.i_size >> 9);

		mutex_unlock(&d->inode_lock);
	}

	if (attr == &sysfs_label) {
		mutex_lock(&d->inode_lock);

		memcpy(d->inode.i_label, buf, SB_LABEL_SIZE);
		bch_inode_update(d->c, &d->inode.i_inode);

		mutex_unlock(&d->inode_lock);
	}

	if (attr == &sysfs_unregister) {
		set_bit(BCACHE_DEV_DETACHING, &d->flags);
		bcache_device_stop(d);
	}

	return size;
}
STORE_LOCKED(bch_flash_dev)

static struct attribute *bch_flash_dev_files[] = {
	&sysfs_unregister,
#if 0
	&sysfs_data_csum,
#endif
	&sysfs_label,
	&sysfs_size,
	NULL
};
KTYPE(bch_flash_dev);

struct bset_stats_op {
	struct btree_op op;
	size_t nodes;
	struct bset_stats stats;
};

static int bch_btree_bset_stats(struct btree_op *b_op, struct btree *b)
{
	struct bset_stats_op *op = container_of(b_op, struct bset_stats_op, op);

	op->nodes++;
	bch_btree_keys_stats(&b->keys, &op->stats);

	return MAP_CONTINUE;
}

static int bch_bset_print_stats(struct cache_set *c, char *buf)
{
	struct bset_stats_op op;
	unsigned id;
	int ret;

	for (id = 0; id < BTREE_ID_NR; id++) {
		memset(&op, 0, sizeof(op));
		bch_btree_op_init(&op.op, id, -1);

		if (c->btree_roots[id]) {
			ret = bch_btree_map_nodes(&op.op, c, NULL,
						  bch_btree_bset_stats,
						  MAP_ALL_NODES);
			if (ret < 0)
				return ret;
		}
	}

	return snprintf(buf, PAGE_SIZE,
			"btree nodes:		%zu\n"
			"written sets:		%zu\n"
			"unwritten sets:		%zu\n"
			"written key bytes:	%zu\n"
			"unwritten key bytes:	%zu\n"
			"floats:			%zu\n"
			"failed:			%zu\n",
			op.nodes,
			op.stats.sets_written, op.stats.sets_unwritten,
			op.stats.bytes_written, op.stats.bytes_unwritten,
			op.stats.floats, op.stats.failed);
}

static unsigned bch_root_usage(struct cache_set *c)
{
	unsigned bytes = 0;
	struct bkey *k;
	struct btree *b;
	struct btree_iter iter;

	goto lock_root;

	do {
		six_unlock_read(&b->lock);
lock_root:
		b = c->btree_roots[BTREE_ID_EXTENTS];
		six_lock_read(&b->lock);
	} while (b != c->btree_roots[BTREE_ID_EXTENTS]);

	for_each_key_filter(&b->keys, k, &iter, bch_ptr_bad)
		bytes += bkey_bytes(k);

	six_unlock_read(&b->lock);

	return (bytes * 100) / btree_bytes(c);
}

static size_t bch_cache_size(struct cache_set *c)
{
	size_t ret = 0;
	struct btree *b;

	mutex_lock(&c->bucket_lock);
	list_for_each_entry(b, &c->btree_cache, list)
		ret += 1 << (b->keys.page_order + PAGE_SHIFT);

	mutex_unlock(&c->bucket_lock);
	return ret;
}

static unsigned bch_cache_available_percent(struct cache_set *c)
{
	return div64_u64((u64) buckets_available(c) * 100,
			 c->nbuckets ?: 1);
}

static unsigned bch_btree_used(struct cache_set *c)
{
	return div64_u64(c->gc_stats.key_bytes * 100,
			 (c->gc_stats.nodes ?: 1) * btree_bytes(c));
}

static unsigned bch_average_key_size(struct cache_set *c)
{
	return c->gc_stats.nkeys
		? div64_u64(c->gc_stats.data, c->gc_stats.nkeys)
		: 0;
}

SHOW(__bch_cache_set)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);

	sysfs_print(synchronous,		CACHE_SYNC(&c->sb));
	sysfs_print(journal_delay_ms,		c->journal.delay_ms);
	sysfs_hprint(bucket_size,		bucket_bytes(c));
	sysfs_hprint(block_size,		block_bytes(c));

	sysfs_hprint(btree_cache_size,		bch_cache_size(c));
	sysfs_print(cache_available_percent,	bch_cache_available_percent(c));

	sysfs_print(btree_gc_count,		bch_gc_count(c));

	sysfs_print_time_stats(&c->btree_gc_time,	btree_gc, sec, ms);
	sysfs_print_time_stats(&c->btree_split_time,	btree_split, sec, us);
	sysfs_print_time_stats(&c->sort.time,		btree_sort, ms, us);
	sysfs_print_time_stats(&c->btree_read_time,	btree_read, ms, us);

	sysfs_print(btree_used_percent,	bch_btree_used(c));
	sysfs_print(btree_nodes,	c->gc_stats.nodes);
	sysfs_hprint(average_key_size,	bch_average_key_size(c));

	sysfs_print(cache_read_races,
		    atomic_long_read(&c->cache_read_races));

	sysfs_print(writeback_keys_done,
		    atomic_long_read(&c->writeback_keys_done));
	sysfs_print(writeback_keys_failed,
		    atomic_long_read(&c->writeback_keys_failed));

	if (attr == &sysfs_errors)
		return bch_snprint_string_list(buf, PAGE_SIZE, error_actions,
					       c->on_error);

	/* See count_io_errors for why 88 */
	sysfs_print(io_error_halflife,	c->error_decay * 88);
	sysfs_print(io_error_limit,	c->error_limit >> IO_ERROR_SHIFT);

	sysfs_hprint(congested,
		     ((uint64_t) bch_get_congested(c)) << 9);
	sysfs_print(congested_read_threshold_us,
		    c->congested_read_threshold_us);
	sysfs_print(congested_write_threshold_us,
		    c->congested_write_threshold_us);

	if (attr == &sysfs_journal_debug)
		return bch_journal_print_debug(&c->journal, buf);

	sysfs_printf(verify,			"%i", c->verify);
	sysfs_printf(key_merging_disabled,	"%i", c->key_merging_disabled);
	sysfs_printf(expensive_debug_checks,
		     "%i", c->expensive_debug_checks);
	sysfs_printf(gc_always_rewrite,		"%i", c->gc_always_rewrite);
	sysfs_printf(btree_shrinker_disabled,	"%i", c->shrinker_disabled);
	sysfs_printf(copy_gc_enabled,		"%i", c->copy_gc_enabled);
	sysfs_printf(tiering_enabled,		"%i", c->tiering_enabled);
	sysfs_pd_controller_show(tiering,	&c->tiering_pd);

	sysfs_print(btree_scan_ratelimit,	c->btree_scan_ratelimit);

	sysfs_printf(meta_replicas,		"%u", c->meta_replicas);
	sysfs_printf(data_replicas,		"%u", c->data_replicas);

	if (!test_bit(CACHE_SET_RUNNING, &c->flags))
		return -EPERM;

	if (attr == &sysfs_bset_tree_stats)
		return bch_bset_print_stats(c, buf);

	sysfs_print(tree_depth, c->btree_roots[BTREE_ID_EXTENTS]->level);
	sysfs_print(root_usage_percent,		bch_root_usage(c));

	return 0;
}
SHOW_LOCKED(bch_cache_set)

STORE(__bch_cache_set)
{
	struct cache_set *c = container_of(kobj, struct cache_set, kobj);

	if (attr == &sysfs_unregister) {
		bch_cache_set_unregister(c);
		return size;
	}

	if (attr == &sysfs_stop) {
		bch_cache_set_stop(c);
		return size;
	}

	if (attr == &sysfs_synchronous) {
		bool sync = strtoul_or_return(buf);

		if (sync != CACHE_SYNC(&c->sb)) {
			SET_CACHE_SYNC(&c->sb, sync);
			bcache_write_super(c);
		}

		return size;
	}

	if (attr == &sysfs_clear_stats) {
		atomic_long_set(&c->writeback_keys_done,	0);
		atomic_long_set(&c->writeback_keys_failed,	0);

		memset(&c->gc_stats, 0, sizeof(struct gc_stat));
		bch_cache_accounting_clear(&c->accounting);

		return size;
	}

	sysfs_strtoul(congested_read_threshold_us,
		      c->congested_read_threshold_us);
	sysfs_strtoul(congested_write_threshold_us,
		      c->congested_write_threshold_us);

	if (attr == &sysfs_errors) {
		ssize_t v = bch_read_string_list(buf, error_actions);

		if (v < 0)
			return v;

		c->on_error = v;
		return size;
	}

	if (attr == &sysfs_io_error_limit) {
		c->error_limit = strtoul_or_return(buf) << IO_ERROR_SHIFT;
		return size;
	}

	/* See count_io_errors() for why 88 */
	if (attr == &sysfs_io_error_halflife) {
		c->error_decay = strtoul_or_return(buf) / 88;
		return size;
	}

	sysfs_strtoul(journal_delay_ms,		c->journal.delay_ms);
	sysfs_strtoul(verify,			c->verify);
	sysfs_strtoul(key_merging_disabled,	c->key_merging_disabled);
	sysfs_strtoul(expensive_debug_checks,	c->expensive_debug_checks);
	sysfs_strtoul(gc_always_rewrite,	c->gc_always_rewrite);
	sysfs_strtoul(btree_shrinker_disabled,	c->shrinker_disabled);
	sysfs_strtoul(copy_gc_enabled,		c->copy_gc_enabled);
	sysfs_strtoul(btree_scan_ratelimit,	c->btree_scan_ratelimit);

	if (attr == &sysfs_copy_gc_enabled) {
		struct cache *ca;
		unsigned i;
		ssize_t ret = strtoul_safe(buf, c->copy_gc_enabled)
			?: (ssize_t) size;

		for_each_cache(ca, c, i)
			if (ca->moving_gc_thread)
				wake_up_process(ca->moving_gc_thread);
		return ret;
	}

	if (attr == &sysfs_tiering_enabled) {
		ssize_t ret = strtoul_safe(buf, c->tiering_enabled)
			?: (ssize_t) size;

		if (c->tiering_thread)
			wake_up_process(c->tiering_thread);
		return ret;
	}

	sysfs_pd_controller_store(tiering,	&c->tiering_pd);

	sysfs_strtoul_clamp(meta_replicas,
			    c->meta_replicas, 1, BKEY_PAD_PTRS);
	sysfs_strtoul_clamp(data_replicas,
			    c->data_replicas, 1, BKEY_PAD_PTRS);

	if (!test_bit(CACHE_SET_RUNNING, &c->flags))
		return -EPERM;

	if (test_bit(CACHE_SET_STOPPING, &c->flags))
		return -EINTR;

	if (attr == &sysfs_flash_vol_create) {
		int r;
		u64 v;

		strtoi_h_or_return(buf, v);
		r = bch_flash_dev_create(c, v);
		if (r)
			return r;
	}

	if (attr == &sysfs_trigger_gc)
		wake_up_gc(c, true);

	if (attr == &sysfs_prune_cache) {
		struct shrink_control sc;

		sc.gfp_mask = GFP_KERNEL;
		sc.nr_to_scan = strtoul_or_return(buf);
		c->btree_cache_shrink.scan_objects(&c->btree_cache_shrink, &sc);
	}

	return size;
}
STORE_LOCKED(bch_cache_set)

SHOW(bch_cache_set_internal)
{
	struct cache_set *c = container_of(kobj, struct cache_set, internal);
	return bch_cache_set_show(&c->kobj, attr, buf);
}

STORE(bch_cache_set_internal)
{
	struct cache_set *c = container_of(kobj, struct cache_set, internal);
	return bch_cache_set_store(&c->kobj, attr, buf, size);
}

static void bch_cache_set_internal_release(struct kobject *k)
{
}

static struct attribute *bch_cache_set_files[] = {
	&sysfs_unregister,
	&sysfs_stop,
	&sysfs_synchronous,
	&sysfs_journal_delay_ms,
	&sysfs_flash_vol_create,

	&sysfs_bucket_size,
	&sysfs_block_size,
	&sysfs_tree_depth,
	&sysfs_root_usage_percent,
	&sysfs_btree_cache_size,
	&sysfs_cache_available_percent,

	&sysfs_average_key_size,

	&sysfs_errors,
	&sysfs_io_error_limit,
	&sysfs_io_error_halflife,
	&sysfs_congested,
	&sysfs_congested_read_threshold_us,
	&sysfs_congested_write_threshold_us,
	&sysfs_clear_stats,

	&sysfs_meta_replicas,
	&sysfs_data_replicas,
	NULL
};
KTYPE(bch_cache_set);

static struct attribute *bch_cache_set_internal_files[] = {
	&sysfs_journal_debug,

	sysfs_time_stats_attribute_list(btree_gc, sec, ms)
	sysfs_time_stats_attribute_list(btree_split, sec, us)
	sysfs_time_stats_attribute_list(btree_sort, ms, us)
	sysfs_time_stats_attribute_list(btree_read, ms, us)

	&sysfs_btree_gc_count,

	&sysfs_btree_nodes,
	&sysfs_btree_used_percent,

	&sysfs_bset_tree_stats,
	&sysfs_cache_read_races,
	&sysfs_writeback_keys_done,
	&sysfs_writeback_keys_failed,

	&sysfs_trigger_gc,
	&sysfs_prune_cache,
#ifdef CONFIG_BCACHE_DEBUG
	&sysfs_verify,
	&sysfs_key_merging_disabled,
	&sysfs_expensive_debug_checks,
#endif
	&sysfs_gc_always_rewrite,
	&sysfs_btree_shrinker_disabled,
	&sysfs_copy_gc_enabled,
	&sysfs_tiering_enabled,
	sysfs_pd_controller_files(tiering),
	NULL
};
KTYPE(bch_cache_set_internal);

static ssize_t show_priority_stats(struct cache *ca, char *buf)
{
	int cmp(const void *l, const void *r)
	{	return *((u16 *) r) - *((u16 *) l); }

	struct bucket *b;
	size_t n = ca->sb.nbuckets, i;
	size_t unused = 0, available = 0, dirty = 0, meta = 0;
	u64 sum = 0;
	/* Compute 31 quantiles */
	u16 q[31], *p, *cached;
	ssize_t ret;

	cached = p = vmalloc(ca->sb.nbuckets * sizeof(u16));
	if (!p)
		return -ENOMEM;

	mutex_lock(&ca->set->bucket_lock);
	for_each_bucket(b, ca) {
		if (b->mark.is_metadata)
			meta++;
		else if (b->mark.dirty_sectors)
			dirty++;
		else if (b->mark.cached_sectors)
			available++;
		else
			unused++;
	}

	for (i = ca->sb.first_bucket; i < n; i++)
		p[i] = ca->buckets[i].read_prio;
	mutex_unlock(&ca->set->bucket_lock);

	sort(p, n, sizeof(u16), cmp, NULL);

	while (n &&
	       !cached[n - 1])
		--n;

	unused = ca->sb.nbuckets - n;

	for (i = 0; i < n; i++)
		sum += INITIAL_PRIO - cached[i];

	if (n)
		do_div(sum, n);

	for (i = 0; i < ARRAY_SIZE(q); i++)
		q[i] = INITIAL_PRIO - cached[n * (i + 1) /
			(ARRAY_SIZE(q) + 1)];

	vfree(p);

	ret = scnprintf(buf, PAGE_SIZE,
			"Unused:		%zu%% (%zu)\n"
			"Clean:		%zu%% (%zu)\n"
			"Dirty:		%zu%% (%zu)\n"
			"Metadata:	%zu%% (%zu)\n"
			"Average:	%llu\n"
			"Sectors per Q:	%zu\n"
			"Quantiles:	[",
			unused * 100 / (size_t) ca->sb.nbuckets, unused,
			available * 100 / (size_t) ca->sb.nbuckets, available,
			dirty * 100 / (size_t) ca->sb.nbuckets, dirty,
			meta * 100 / (size_t) ca->sb.nbuckets, meta, sum,
			n * ca->sb.bucket_size / (ARRAY_SIZE(q) + 1));

	for (i = 0; i < ARRAY_SIZE(q); i++)
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "%u ", q[i]);
	ret--;

	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "]\n");

	return ret;

}

static ssize_t show_reserve_stats(struct cache *ca, char *buf)
{
	enum alloc_reserve i;
	ssize_t ret;

	mutex_lock(&ca->set->bucket_lock);

	ret = scnprintf(buf, PAGE_SIZE,
			"free_inc:\t%zu\t%zu\n",
			fifo_used(&ca->free_inc),
			ca->free_inc.size);

	for (i = 0; i < RESERVE_NR; i++)
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "free[%u]:\t%zu\t%zu\n", i,
				 fifo_used(&ca->free[i]),
				 ca->free[i].size);

	mutex_unlock(&ca->set->bucket_lock);

	return ret;
}

SHOW(__bch_cache)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);
	struct bucket_stats stats;

	mutex_lock(&ca->set->bucket_lock);
	memcpy(&stats, &ca->bucket_stats[ca->set->gc_mark_valid ? 0 : 1],
	       sizeof(stats));
	mutex_unlock(&ca->set->bucket_lock);

	sysfs_hprint(bucket_size,	bucket_bytes(ca));
	sysfs_hprint(block_size,	block_bytes(ca));
	sysfs_print(nbuckets,		ca->sb.nbuckets);
	sysfs_print(discard,		ca->discard);
	sysfs_hprint(written, atomic_long_read(&ca->sectors_written) << 9);
	sysfs_hprint(btree_written,
		     atomic_long_read(&ca->btree_sectors_written) << 9);
	sysfs_hprint(metadata_written,
		     (atomic_long_read(&ca->meta_sectors_written) +
		      atomic_long_read(&ca->btree_sectors_written)) << 9);

	sysfs_print(io_errors,
		    atomic_read(&ca->io_errors) >> IO_ERROR_SHIFT);

	sysfs_hprint(dirty_data,
		     atomic64_read(&stats.sectors_dirty) << 9);
	sysfs_print(dirty_buckets,
		     atomic_read(&stats.buckets_dirty));
	sysfs_hprint(cached_data,
		     atomic64_read(&stats.sectors_cached) << 9);
	sysfs_print(cached_buckets,
		    atomic_read(&stats.buckets_cached));
	sysfs_print(meta_buckets,
		    atomic_read(&stats.buckets_meta));
	sysfs_print(alloc_buckets,
		    atomic_read(&stats.buckets_alloc));

	sysfs_pd_controller_show(copy_gc, &ca->moving_gc_pd);

	if (attr == &sysfs_cache_replacement_policy)
		return bch_snprint_string_list(buf, PAGE_SIZE,
					       cache_replacement_policies,
					       CACHE_REPLACEMENT(&ca->sb));

	sysfs_print(tier,		CACHE_TIER(&ca->sb));

	if (attr == &sysfs_priority_stats)
		return show_priority_stats(ca, buf);
	if (attr == &sysfs_reserve_stats)
		return show_reserve_stats(ca, buf);

	return 0;
}
SHOW_LOCKED(bch_cache)

STORE(__bch_cache)
{
	struct cache *ca = container_of(kobj, struct cache, kobj);
	struct cache_set *c = ca->set;

	sysfs_pd_controller_store(copy_gc, &ca->moving_gc_pd);

	if (attr == &sysfs_discard) {
		bool v = strtoul_or_return(buf);

		if (blk_queue_discard(bdev_get_queue(ca->bdev)))
			ca->discard = v;

		if (v != CACHE_DISCARD(&ca->sb)) {
			SET_CACHE_DISCARD(&ca->sb, v);
			bcache_write_super(c);
		}
	}

	if (attr == &sysfs_cache_replacement_policy) {
		ssize_t v = bch_read_string_list(buf, cache_replacement_policies);

		if (v < 0)
			return v;

		if ((unsigned) v != CACHE_REPLACEMENT(&ca->sb)) {
			mutex_lock(&c->bucket_lock);
			SET_CACHE_REPLACEMENT(&ca->sb, v);
			mutex_unlock(&c->bucket_lock);

			bcache_write_super(c);
		}
	}

	if (attr == &sysfs_tier) {
		unsigned long v = strtoul_or_return(buf);

		if (v >= CACHE_TIERS)
			return -EINVAL;

		if (v != CACHE_TIER(&ca->sb)) {
			unsigned i;
			struct cache_tier *tier;

			mutex_lock(&c->bucket_lock);
			tier = &c->cache_by_alloc[CACHE_TIER(&ca->sb)];

			for (i = 0; i < tier->nr_devices; i++)
				if (tier->devices[i] == ca)
					goto found;

			/* Not found */
			WARN(1, "cache device not found in tier\n");
			return -EINVAL;
found:
			memmove(&tier->devices[i],
				&tier->devices[i + 1],
				sizeof(ca) * (tier->nr_devices - i - 1));

			tier = &c->cache_by_alloc[v];
			tier->devices[tier->nr_devices++] = ca;

			mutex_unlock(&c->bucket_lock);

			SET_CACHE_TIER(&ca->sb, v);
			bcache_write_super(c);
		}
	}

	if (attr == &sysfs_clear_stats) {
		atomic_long_set(&ca->sectors_written, 0);
		atomic_long_set(&ca->btree_sectors_written, 0);
		atomic_long_set(&ca->meta_sectors_written, 0);
		atomic_set(&ca->io_count, 0);
		atomic_set(&ca->io_errors, 0);
	}

	return size;
}
STORE_LOCKED(bch_cache)

static struct attribute *bch_cache_files[] = {
	&sysfs_bucket_size,
	&sysfs_block_size,
	&sysfs_nbuckets,
	&sysfs_priority_stats,
	&sysfs_reserve_stats,
	&sysfs_dirty_data,
	&sysfs_dirty_buckets,
	&sysfs_cached_data,
	&sysfs_cached_buckets,
	&sysfs_meta_buckets,
	&sysfs_alloc_buckets,
	&sysfs_discard,
	&sysfs_written,
	&sysfs_btree_written,
	&sysfs_metadata_written,
	&sysfs_io_errors,
	&sysfs_clear_stats,
	&sysfs_cache_replacement_policy,
	&sysfs_tier,
	sysfs_pd_controller_files(copy_gc),
	NULL
};
KTYPE(bch_cache);
