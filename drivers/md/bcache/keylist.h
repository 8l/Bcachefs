#ifndef _BCACHE_KEYLIST_H
#define _BCACHE_KEYLIST_H

#include "keylist_types.h"

/* include/linux/bcache-kernel.h declares plain keylist macros and externs */

void bch_scan_keylist_init(struct scan_keylist *kl,
			   unsigned max_size);

void bch_scan_keylist_reset(struct scan_keylist *kl);

/* The keylist is dynamically adjusted. This just clamps the maxima */

static inline unsigned bch_scan_keylist_size(struct scan_keylist *kl)
{
	return (kl->max_size);
}

void bch_scan_keylist_resize(struct scan_keylist *kl,
			     unsigned max_size);

void bch_scan_keylist_destroy(struct scan_keylist *kl);

/*
 * IMPORTANT: The caller of bch_scan_keylist_next or
 * bch_scan_keylist_next_rescan needs to copy any
 * non-null return value before calling either again!
 * These functions return a pointer into the internal structure.
 * Furthermore, they need to call bch_scan_keylist_advance after
 * copying the structure.
 */

struct bkey *bch_scan_keylist_next(struct scan_keylist *);

struct bkey *bch_scan_keylist_next_rescan(struct cache_set *c,
					  struct scan_keylist *kl,
					  struct bkey *end,
					  scan_keylist_pred_fn *pred);

static inline void bch_scan_keylist_advance(struct scan_keylist *kl)
{
	bch_keylist_pop_front(&kl->list);
	return;
}

void bch_mark_scan_keylist_keys(struct cache_set *, struct scan_keylist *);

#endif /* _BCACHE_KEYLIST_H */
