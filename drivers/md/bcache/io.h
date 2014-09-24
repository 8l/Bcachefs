#ifndef _BCACHE_IO_H
#define _BCACHE_IO_H

void bch_count_io_errors(struct cache *, int, const char *);
void bch_bbio_count_io_errors(struct bbio *, int, const char *);
void bch_bbio_endio(struct bbio *, int, const char *);
void bch_bbio_free(struct bio *, struct cache_set *);
struct bio *bch_bbio_alloc(struct cache_set *);

void bch_generic_make_request(struct bio *, struct cache_set *);
void bch_bio_submit_work(struct work_struct *);
void bch_bbio_prep(struct bbio *, struct cache *);
void bch_submit_bbio(struct bbio *, struct cache *, struct bkey *,
		     unsigned, bool);
void bch_submit_bbio_replicas(struct bio *, struct cache_set *,
			      struct bkey *, unsigned, bool);

void __cache_promote(struct cache_set *, struct bbio *, struct bkey *);
bool cache_promote(struct cache_set *, struct bbio *, struct bkey *, unsigned);

void bch_read_race_work(struct work_struct *work);

extern struct workqueue_struct *bcache_io_wq;

#endif /* _BCACHE_IO_H */
