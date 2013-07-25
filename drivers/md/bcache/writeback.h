#ifndef _BCACHE_WRITEBACK_H
#define _BCACHE_WRITEBACK_H

static inline uint64_t bcache_dev_sectors_dirty(struct bcache_device *d)
{
	uint64_t i, ret = 0;

	for (i = 0; i < d->nr_stripes; i++)
		ret += atomic_read(d->stripe_sectors_dirty + i);

	return ret;
}

static inline void bch_writeback_queue(struct cached_dev *dc)
{
	wake_up_process(dc->writeback_thread);
}

static inline void bch_writeback_add(struct cached_dev *dc)
{
	if (!atomic_read(&dc->has_dirty) &&
	    !atomic_xchg(&dc->has_dirty, 1)) {
		atomic_inc(&dc->count);

		if (BDEV_STATE(&dc->sb) != BDEV_STATE_DIRTY) {
			SET_BDEV_STATE(&dc->sb, BDEV_STATE_DIRTY);
			/* XXX: should do this synchronously */
			bch_write_bdev_super(dc, NULL);
		}

		bch_writeback_queue(dc);
	}
}

void bcache_dev_sectors_dirty_add(struct cache_set *, unsigned, uint64_t, int);

void bch_sectors_dirty_init(struct cached_dev *dc);
int bch_cached_dev_writeback_init(struct cached_dev *);

#endif
