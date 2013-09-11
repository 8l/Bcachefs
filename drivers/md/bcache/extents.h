#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

extern const struct btree_keys_ops btree_keys_ops;
extern const struct btree_keys_ops generic_keys_ops;
extern const struct btree_keys_ops extent_keys_ops;

struct bkey;
struct cache_set;

void bch_bkey_to_text(char *buf, size_t size, const struct bkey *k);
bool __bch_btree_ptr_invalid(struct cache_set *c, const struct bkey *k);

#endif /* _BCACHE_EXTENTS_H */
