
#include "bcache.h"
#include "bset.h"
#include "debug.h"

/* Bios with headers */

void bch_bbio_free(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	mempool_free(b, c->bio_meta);
}

struct bio *bch_bbio_alloc(struct cache_set *c)
{
	struct bbio *b = mempool_alloc(c->bio_meta, GFP_NOIO);
	struct bio *bio = &b->bio;

	bio_init(bio);
	bio->bi_flags		|= BIO_POOL_NONE << BIO_POOL_OFFSET;
	bio->bi_max_vecs	 = bucket_pages(c);
	bio->bi_io_vec		 = bio->bi_inline_vecs;

	return bio;
}

struct bio *__bch_bio_split_get(struct bio *bio, int len, struct bio_set *bs)
{
	struct bio *ret = bio_split(bio, len, GFP_NOIO, bs);

	if (ret && ret != bio) {
		closure_get(ret->bi_private);
		ret->bi_rw &= ~REQ_UNPLUG;
	}

	return ret;
}

void __bch_submit_bbio(struct bio *bio, struct cache_set *c)
{
	struct bbio *b = container_of(bio, struct bbio, bio);

	bio->bi_sector	= PTR_OFFSET(&b->key, 0);
	bio->bi_bdev	= PTR_CACHE(c, &b->key, 0)->bdev;

	b->submit_time_us = local_clock_us();
	generic_make_request(bio);
}

void bch_submit_bbio(struct bio *bio, struct cache_set *c,
		     struct bkey *k, unsigned ptr)
{
	struct bbio *b = container_of(bio, struct bbio, bio);
	bch_bkey_copy_single_ptr(&b->key, k, ptr);
	__bch_submit_bbio(bio, c);
}

/* IO errors */

void bch_count_io_errors(struct cache *c, int error, const char *m)
{
	/*
	 * The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */

	if (c->set->error_decay) {
		unsigned count = atomic_inc_return(&c->io_count);

		while (count > c->set->error_decay) {
			unsigned errors;
			unsigned old = count;
			unsigned new = count - c->set->error_decay;

			/*
			 * First we subtract refresh from count; each time we
			 * succesfully do so, we rescale the errors once:
			 */

			count = atomic_cmpxchg(&c->io_count, old, new);

			if (count == old) {
				count = new;

				errors = atomic_read(&c->io_errors);
				do {
					old = errors;
					new = ((uint64_t) errors * 127) / 128;
					errors = atomic_cmpxchg(&c->io_errors,
								old, new);
				} while (old != errors);
			}
		}
	}

	if (error) {
		char buf[BDEVNAME_SIZE];
		unsigned errors = atomic_add_return(1 << IO_ERROR_SHIFT,
						    &c->io_errors);
		errors >>= IO_ERROR_SHIFT;

		if (errors < c->set->error_limit)
			err_printk("%s: IO error on %s, recovering\n",
				   bdevname(c->bdev, buf), m);
		else
			bch_cache_set_error(c->set, "%s: too many IO errors %s",
					    bdevname(c->bdev, buf), m);
	}
}

void bch_bbio_endio(struct cache_set *c, struct bio *bio,
		    int error, const char *m)
{
	struct closure *cl = bio->bi_private;
	struct bbio *b = container_of(bio, struct bbio, bio);
	struct cache *ca = PTR_CACHE(c, &b->key, 0);

	unsigned threshold = bio->bi_rw & REQ_WRITE
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold) {
		unsigned t = local_clock_us();

		int us = t - b->submit_time_us;
		int congested = atomic_read(&c->congested);

		if (us > (int) threshold) {
			int ms = us / 1024;
			c->congested_last_us = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	bch_count_io_errors(ca, error, m);
	bio_put(bio);
	closure_put(cl);
}
