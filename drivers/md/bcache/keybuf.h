#ifndef _BCACHE_KEYBUF_H
#define _BCACHE_KEYBUF_H

#include "keybuf_types.h"

typedef bool (keybuf_pred_fn)(struct keybuf *, struct bkey_s_c);

void bch_keybuf_init(struct keybuf *, unsigned size, unsigned in_flight);
void bch_refill_keybuf(struct cache_set *, struct keybuf *,
		       struct bpos, keybuf_pred_fn *);
void bch_keybuf_recalc_oldest_gens(struct cache_set *, struct keybuf *);
bool bch_keybuf_check_overlapping(struct keybuf *, struct bpos, struct bpos);
void bch_keybuf_put(struct keybuf *, struct keybuf_key *);
struct keybuf_key *bch_keybuf_next(struct keybuf *);

static inline unsigned bch_keybuf_size(struct keybuf *kb)
{
	return kb->reserve;
}

void bch_keybuf_resize(struct keybuf *, unsigned);

static inline unsigned bch_keybuf_ios(struct keybuf *kb)
{
	return kb->max_in_flight;
}

void bch_keybuf_resize_ios(struct keybuf *, unsigned);

void bch_keybuf_free(struct keybuf *);
bool bch_keybuf_full(struct keybuf *);

#endif /* _BCACHE_KEYBUF_H */
