#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

extern const struct btree_keys_ops bch_btree_keys_ops;
extern const struct btree_keys_ops bch_generic_keys_ops;
extern const struct btree_keys_ops bch_extent_keys_ops;

struct bkey;
struct cache_set;

void bch_extent_to_text(char *, size_t, const struct bkey *);
bool __bch_btree_ptr_invalid(struct cache_set *, const struct bkey *);

static inline unsigned bch_extent_ptrs(const struct bkey *k)
{
	return bch_val_u64s(k);
}

static inline void bch_set_extent_ptrs(struct bkey *k, unsigned i)
{
	bch_set_val_u64s(k, i);
}

#endif /* _BCACHE_EXTENTS_H */
