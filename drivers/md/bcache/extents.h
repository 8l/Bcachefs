#ifndef _BCACHE_EXTENTS_H
#define _BCACHE_EXTENTS_H

struct bkey;
struct btree_keys;
struct btree_iter;
struct btree_iter_set;
struct cache_set;

bool bch_key_sort_cmp(struct btree_iter_set, struct btree_iter_set);

bool __bch_btree_ptr_invalid(struct cache_set *, const struct bkey *);
bool bch_btree_ptr_invalid(struct btree_keys *, const struct bkey *);
bool bch_btree_ptr_bad(struct btree_keys *, const struct bkey *);

bool bch_extent_sort_cmp(struct btree_iter_set, struct btree_iter_set);
void bch_extent_sort_fixup(struct btree_iter *);
bool bch_extent_invalid(struct btree_keys *, const struct bkey *);
bool bch_extent_bad(struct btree_keys *, const struct bkey *);
bool bch_extent_merge(struct btree_keys *, struct bkey *, struct bkey *);

#endif /* _BCACHE_EXTENTS_H */
