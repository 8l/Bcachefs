#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

void bch_cache_io_error_work(struct work_struct *);
void bch_count_io_errors(struct cache *, int, const char *);
void bch_bbio_count_io_errors(struct bbio *, int, const char *);
void bch_bbio_endio(struct bbio *, int, const char *);
void bch_bbio_free(struct bio *, struct cache_set *);
struct bio *bch_bbio_alloc(struct cache_set *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_bbio_prep(struct bbio *, struct cache *);
void bch_submit_bbio(struct bbio *, struct cache *, const struct bkey_i *,
		     const struct bch_extent_ptr *, bool);
void bch_submit_bbio_replicas(struct bio *, struct cache_set *,
			      const struct bkey_i *, unsigned, bool);

int bch_discard(struct cache_set *, struct bpos, struct bpos, u64);

void __cache_promote(struct cache_set *, struct bbio *,
		     struct bkey_s_c, struct bkey_s_c, unsigned);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey_s_c);

void bch_read_race_work(struct work_struct *);
void bch_wake_delayed_writes(unsigned long data);

extern struct workqueue_struct *bcache_io_wq;

struct bch_versions_result {
	int error;
	u64 size;		/* In bch_version_records */
	u64 found;		/* In bch_version_records */
	u64 * __user user_found;
	struct bch_version_record * __user buf;
};

int bch_read_with_versions(struct cache_set *,
			   struct bio *,
			   u64 inode,
			   struct bch_versions_result *versions);

static inline u64 sector_bytes(u64 sectors)
{
	return sectors << BCH_SECTOR_SHIFT;
}

void bch_read_versioned_ioctl_endio(struct bio *, int);

#endif /* _BCACHE_IO_H */
