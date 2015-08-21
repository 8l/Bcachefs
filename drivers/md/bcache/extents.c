/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Code for managing the extent btree and dynamically updating the writeback
 * dirty sector count.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"
#include "gc.h"
#include "inode.h"
#include "journal.h"
#include "super.h"
#include "writeback.h"

#include <trace/events/bcache.h>

#define bkey_extent_p(_f, _k)	val_to_extent(bkeyp_val(_f, _k))

static inline unsigned bkeyp_extent_ptrs(const struct bkey_format *f,
					 const struct bkey_packed *k)
{
	return bkeyp_val_u64s(f, k);
}

static void sort_key_next(struct btree_node_iter *iter,
			  struct btree_keys *b,
			  struct btree_node_iter_set *i)
{
	i->k += __btree_node_offset_to_key(b, i->k)->u64s;

	if (i->k == i->end)
		*i = iter->data[--iter->used];
}

/*
 * Returns true if l > r - unless l == r, in which case returns true if l is
 * older than r.
 *
 * Necessary for btree_sort_fixup() - if there are multiple keys that compare
 * equal in different sets, we have to process them newest to oldest.
 */
#define key_sort_cmp(l, r)						\
({									\
	int _c = bkey_cmp_packed(&b->format,				\
				 __btree_node_offset_to_key(b, (l).k),	\
				 __btree_node_offset_to_key(b, (r).k));	\
									\
	_c ? _c > 0 : (l).k > (r).k;					\
})

static inline bool should_drop_next_key(struct btree_node_iter *iter,
					struct btree_keys *b)
{
	const struct bkey_format *f = &b->format;
	struct btree_node_iter_set *l = iter->data, *r = iter->data + 1;

	if (bkey_deleted(__btree_node_offset_to_key(b, l->k)))
		return true;

	if (iter->used < 2)
		return false;

	if (iter->used > 2 &&
	    key_sort_cmp(r[0], r[1]))
		r++;

	/*
	 * key_sort_cmp() ensures that when keys compare equal the older key
	 * comes first; so if l->k compares equal to r->k then l->k is older and
	 * should be dropped.
	 */
	return !bkey_cmp_packed(f,
				__btree_node_offset_to_key(b, l->k),
				__btree_node_offset_to_key(b, r->k));
}

void bch_key_sort_fix_overlapping(struct btree_keys *b,
				  struct bset *bset,
				  struct btree_node_iter *iter)
{
	struct bkey_packed *out = bset->start;

	b->nr_packed_keys	= 0;
	b->nr_unpacked_keys	= 0;

	heap_resort(iter, key_sort_cmp);

	while (!bch_btree_node_iter_end(iter)) {
		if (!should_drop_next_key(iter, b)) {
			struct bkey_packed *k =
				__btree_node_offset_to_key(b, iter->data->k);

			if (bkey_packed(k))
				b->nr_packed_keys++;
			else
				b->nr_unpacked_keys++;

			/* XXX: need better bkey_copy */
			memcpy(out, k, bkey_bytes(k));
			out = bkey_next(out);
		}

		sort_key_next(iter, b, iter->data);
		heap_sift(iter, 0, key_sort_cmp);
	}

	bset->u64s = (u64 *) out - bset->_data;
	b->nr_live_u64s = bset->u64s;

	pr_debug("sorted %i keys", bset->u64s);
}

/* This returns true if insert should be inserted, false otherwise */

bool bch_insert_fixup_key(struct btree *b, struct bkey_i *insert,
			  struct btree_node_iter *iter,
			  struct bch_replace_info *replace,
			  struct bpos *done,
			  struct journal_res *res)
{
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	int c;

	BUG_ON(replace);

	while ((k = bch_btree_node_iter_peek_all(iter, &b->keys)) &&
	       (c = bkey_cmp_packed(f, k, &insert->k)) <= 0) {
		if (!c && !bkey_deleted(k)) {
			k->type = KEY_TYPE_DELETED;
			btree_keys_account_key_drop(&b->keys, k);
		}

		bch_btree_node_iter_next_all(iter, &b->keys);
	}

	bch_btree_insert_and_journal(b, iter, insert, res);
	return true;
}

/* Common among btree and extent ptrs */

bool bch_extent_has_device(struct bkey_s_c_extent e, unsigned dev)
{
	const struct bch_extent_ptr *ptr;

	extent_for_each_ptr(e, ptr)
		if (PTR_DEV(ptr) == dev)
			return true;

	return false;
}

static bool should_drop_ptr(const struct cache_set *c,
			    const struct bch_extent *e,
			    const struct bch_extent_ptr *ptr,
			    unsigned nr_ptrs)
{
	unsigned dev;
	struct cache *ca;
	struct cache_member *mi;

	dev = PTR_DEV(ptr);
	if (dev == PTR_LOST_DEV)
		return false;

	if (dev >= c->sb.nr_in_set)
		return true;

	mi = rcu_dereference(c->members)->m;

	if (bch_is_zero(mi[dev].uuid.b, sizeof(uuid_le)))
		return true;

	if (__bch_extent_ptr_is_dirty(c, e, ptr, nr_ptrs))
		return false;

	return (ca = PTR_CACHE(c, ptr)) && ptr_stale(ca, ptr);
}

unsigned bch_extent_nr_ptrs_after_normalize(const struct btree *b,
					    const struct bkey_packed *k)
{
	const struct bkey_format *f = &b->keys.format;
	const struct bch_extent *e;
	unsigned ret = 0, ptr;

	switch (k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_COOKIE:
		return 0;

	case KEY_TYPE_DISCARD:
		return bkey_unpack_key(f, k).version ? BKEY_U64s : 0;

	case KEY_TYPE_ERROR:
		return bkeyp_key_u64s(f, k);

	case BCH_EXTENT:
		e = bkey_p_c_extent_val(f, k);

		rcu_read_lock();
		for (ptr = 0; ptr < bkeyp_extent_ptrs(f, k); ptr++)
			if (!should_drop_ptr(b->c, e, &e->ptr[ptr],
					     bkeyp_extent_ptrs(f, k)))
				ret++;
		rcu_read_unlock();

		if (ret)
			ret += bkeyp_key_u64s(f, k);

		return ret;
	default:
		BUG();
	}
}

void bch_extent_drop_stale(struct cache_set *c, struct bkey_s k)
{
	struct bkey_s_extent e = bkey_s_to_extent(k);
	struct bch_extent_ptr *ptr;

	rcu_read_lock();

	extent_for_each_ptr_backwards(e, ptr)
		if (should_drop_ptr(c, extent_s_to_s_c(e).v,
				    ptr, bch_extent_ptrs(e)))
			bch_extent_drop_ptr(e, ptr - e.v->ptr);

	rcu_read_unlock();
}

static bool bch_ptr_normalize(struct btree_keys *bk, struct bkey_s k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return bch_extent_normalize(b->c, k);
}

/*
 * Common among btree pointers and normal data extents
 */
static bool __ptr_invalid(const struct cache_set *c, struct bkey_s_c k)
{
	struct bkey_s_c_extent e;
	const struct bch_extent_ptr *ptr;
	struct cache_member *mi;
	bool ret = true;

	if (k.k->u64s < BKEY_U64s)
		return true;

	switch (k.k->type) {
	case BCH_EXTENT:
		e = bkey_s_c_to_extent(k);

		if (bch_extent_ptrs(e) > BKEY_EXTENT_PTRS_MAX)
			return true;

		mi = cache_member_info_get(c)->m;

		extent_for_each_ptr(e, ptr) {
			u64 offset = PTR_OFFSET(ptr);
			unsigned dev = PTR_DEV(ptr);
			struct cache_member *m = mi + dev;

			if (dev > c->sb.nr_in_set) {
				if (dev != PTR_LOST_DEV)
					goto invalid;

				continue;
			}

			if ((offset + e.k->size >
			     m->bucket_size * m->nbuckets) ||
			    (offset <
			     m->bucket_size * m->first_bucket) ||
			    ((offset & (m->bucket_size - 1)) + e.k->size >
			     m->bucket_size))
				goto invalid;
		}

		ret = false;
invalid:
		cache_member_info_put();
		break;
	default:
		return true;
	}

	return ret;
}

/*
 * Should match __extent_invalid() - returns the reason an extent is invalid
 */
static const char *bch_ptr_status(const struct cache_set *c,
				  struct cache_member *mi,
				  struct bkey_s_c_extent e)
{
	const struct bch_extent_ptr *ptr;

	if (!bch_extent_ptrs(e))
		return "invalid: no pointers";

	if (bch_extent_ptrs(e) > BKEY_EXTENT_PTRS_MAX)
		return "invalid: too many pointers";

	extent_for_each_ptr(e, ptr) {
		u64 offset = PTR_OFFSET(ptr);
		unsigned dev = PTR_DEV(ptr);
		struct cache_member *m = mi + dev;
		struct cache *ca;

		if (dev > c->sb.nr_in_set) {
			if (dev != PTR_LOST_DEV)
				return "pointer to invalid device";

			continue;
		}

		if (offset + e.k->size > m->bucket_size * m->nbuckets)
			return "invalid: offset past end of device";

		if (offset < m->bucket_size * m->first_bucket)
			return "invalid: offset before first bucket";

		if ((offset & (m->bucket_size - 1)) +
		    e.k->size > m->bucket_size)
			return "invalid: spans multiple buckets";

		if ((ca = PTR_CACHE(c, ptr)) &&
		    ptr_stale(ca, ptr))
			return "stale";
	}

	if (!e.k->size)
		return "zeroed key";
	return "";
}

static void bch_extent_to_text(const struct btree *b, char *buf,
			       size_t size, struct bkey_s_c k)
{
	struct cache_set *c = b->c;
	struct bkey_s_c_extent e;
	char *out = buf, *end = buf + size;
	const struct bch_extent_ptr *ptr;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	switch (k.k->type) {
	case BCH_EXTENT:
		e = bkey_s_c_to_extent(k);

		extent_for_each_ptr(e, ptr) {
			if (ptr != e.v->ptr)
				p(", ");

			p("%llu:%llu gen %llu", PTR_DEV(ptr),
			  PTR_OFFSET(ptr), PTR_GEN(ptr));
		}

		if (EXTENT_CACHED(e.v))
			p(" cached");
#if 0
		if (KEY_CSUM(k))
			p(" cs%llu %llx", KEY_CSUM(k), k->val[1]);
#endif

		p(" %s", bch_ptr_status(c, cache_member_info_get(c)->m, e));
		cache_member_info_put();
	}
#undef p
}

/* Btree ptrs */

static bool bch_btree_ptr_invalid(const struct cache_set *c, struct bkey_s_c k)
{
	return bkey_extent_cached(k) ||
		k.k->size ||
		__ptr_invalid(c, k);
}

static void btree_ptr_debugcheck(struct btree *b, struct bkey_s_c k)
{
	struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
	const struct bch_extent_ptr *ptr;
	struct cache_set *c = b->c;
	unsigned seq;
	const char *err;
	char buf[160];
	struct bucket *g;
	struct cache *ca;
	bool bad;

	if (EXTENT_CACHED(e.v)) {
		btree_bug(b, "btree ptr marked as cached");
		return;
	}

	rcu_read_lock();

	extent_for_each_online_device(c, e, ptr, ca) {
		g = PTR_BUCKET(ca, ptr);

		err = "stale";
		if (ptr_stale(ca, ptr))
			goto err;

		do {
			seq = read_seqbegin(&c->gc_cur_lock);
			bad = (!__gc_will_visit_node(c, b) &&
			       !g->mark.is_metadata);
		} while (read_seqretry(&c->gc_cur_lock, seq));

		err = "inconsistent";
		if (bad)
			goto err;
	}

	rcu_read_unlock();

	return;
err:
	bch_bkey_val_to_text(b, buf, sizeof(buf), k);
	btree_bug(b, "%s btree pointer %s: bucket %zi prio %i "
		  "gen %i last_gc %i mark %08x",
		  err, buf, PTR_BUCKET_NR(ca, ptr),
		  g->read_prio, PTR_BUCKET_GEN(ca, ptr),
		  g->oldest_gen, g->mark.counter);
	rcu_read_unlock();
}

struct cache *bch_btree_pick_ptr(struct cache_set *c,
				 const struct btree *b,
				 const struct bch_extent_ptr **ptr)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);
	struct cache *ca;

	rcu_read_lock();

	extent_for_each_online_device(c, e, *ptr, ca) {
		if (ptr_stale(ca, *ptr)) {
			bch_cache_error(ca,
				"stale btree node pointer at btree %u level %u/%u bucket %zu",
				b->btree_id, b->level, btree_node_root(b)
				? btree_node_root(b)->level : -1,
				PTR_BUCKET_NR(ca, *ptr));
			continue;
		}

		percpu_ref_get(&ca->ref);
		rcu_read_unlock();
		return ca;
	}

	rcu_read_unlock();

	return NULL;
}

const struct btree_keys_ops bch_btree_interior_node_ops = {
};

const struct bkey_ops bch_bkey_btree_ops = {
	.key_invalid	= bch_btree_ptr_invalid,
	.key_debugcheck	= btree_ptr_debugcheck,
	.val_to_text	= bch_extent_to_text,
};

/* Extents */

void bch_bkey_copy_single_ptr(struct bkey_i *dst,
			      struct bkey_s_c _src,
			      unsigned i)
{
	struct bkey_s_c_extent srce = bkey_s_c_to_extent(_src);
	struct bkey_i_extent *dste;

	BUG_ON(i > bch_extent_ptrs(srce));

	/* Only copy the header, key, and one pointer. */
	dst->k = *srce.k;
	dste = bkey_i_to_extent(dst);

	dste->v.ptr[0] = srce.v->ptr[i];

	bch_set_extent_ptrs(extent_i_to_s(dste), 1);
#if 0
	/* We didn't copy the checksum so clear that bit. */
	SET_KEY_CSUM(dst, 0);
#endif
}

bool __bch_cut_front(struct bpos where, struct bkey_s k)
{
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	unsigned len = 0;

	BUG_ON(bkey_cmp(where, k.k->p) > 0);

	if (bkey_cmp(where, bkey_start_pos(k.k)) <= 0)
		return false;

	if (bkey_cmp(where, k.k->p) < 0)
		len = k.k->p.offset - where.offset;
	else
		k.k->p = where;

	/*
	 * Don't readjust offset if the key size is now 0, because that could
	 * cause offset to point to the next bucket:
	 */
	if (len)
		switch (k.k->type) {
		case BCH_EXTENT:
			e = bkey_s_to_extent(k);

			extent_for_each_ptr(e, ptr)
				SET_PTR_OFFSET(ptr, PTR_OFFSET(ptr) +
					       e.k->size - len);
			break;
		default:
			break;
		}

	BUG_ON(len > k.k->size);
	k.k->size = len;

	if (!len)
		__set_bkey_deleted(k.k);

	return true;
}

bool bch_cut_front(struct bpos where, struct bkey_i *k)
{
	return __bch_cut_front(where, bkey_i_to_s(k));
}

bool bch_cut_back(struct bpos where, struct bkey *k)
{
	unsigned len = 0;

	BUG_ON(bkey_cmp(where, bkey_start_pos(k)) < 0);

	if (bkey_cmp(where, k->p) >= 0)
		return false;

	BUG_ON(where.inode != k->p.inode);

	if (bkey_cmp(where, bkey_start_pos(k)) > 0)
		len = where.offset - bkey_start_offset(k);

	k->p = where;

	BUG_ON(len > k->size);
	k->size = len;

	if (!len)
		__set_bkey_deleted(k);

	return true;
}

/*
 * Returns a key corresponding to the start of @k split at @where, @k will be
 * the second half of the split
 */
#define bch_key_split(_where, _k)				\
({								\
	BKEY_PADDED(k) __tmp;					\
								\
	bkey_copy(&__tmp.k, _k);				\
	bch_cut_back(_where, &__tmp.k.k);			\
	bch_cut_front(_where, _k);				\
	&__tmp.k;						\
})

/**
 * bch_key_resize - adjust size of @k
 *
 * bkey_start_offset(k) will be preserved, modifies where the extent ends
 */
void bch_key_resize(struct bkey *k,
		    unsigned new_size)
{
	k->p.offset -= k->size;
	k->p.offset += new_size;
	k->size = new_size;
}

/*
 * In extent_sort_fix_overlapping(), insert_fixup_extent(),
 * extent_merge_inline() - we're modifying keys in place that are packed. To do
 * that we have to unpack the key, modify the unpacked key - then this
 * copies/repacks the unpacked to the original as necessary.
 */
static void extent_save(struct bkey_packed *dst, struct bkey *src,
			const struct bkey_format *f)
{
	struct bkey_i *dst_unpacked;

	if ((dst_unpacked = packed_to_bkey(dst)))
		dst_unpacked->k = *src;
	else
		BUG_ON(!bkey_pack_key(dst, src, f));
}

/*
 * Returns true if l > r - unless l == r, in which case returns true if l is
 * older than r.
 *
 * Necessary for sort_fix_overlapping() - if there are multiple keys that
 * compare equal in different sets, we have to process them newest to oldest.
 */
#define extent_sort_cmp(l, r)						\
({									\
	const struct bkey_format *_f = &b->format;			\
	struct bkey _ul = bkey_unpack_key(_f,				\
				__btree_node_offset_to_key(b, (l).k));	\
	struct bkey _ur = bkey_unpack_key(_f,				\
				__btree_node_offset_to_key(b, (r).k));	\
									\
	int _c = bkey_cmp(bkey_start_pos(&_ul), bkey_start_pos(&_ur));	\
	_c ? _c > 0 : (l).k < (r).k;					\
})

static inline void extent_sort_sift(struct btree_node_iter *iter,
				    struct btree_keys *b, size_t i)
{
	heap_sift(iter, i, extent_sort_cmp);
}

static inline void extent_sort_next(struct btree_node_iter *iter,
				    struct btree_keys *b,
				    struct btree_node_iter_set *i)
{
	sort_key_next(iter, b, i);
	heap_sift(iter, i - iter->data, extent_sort_cmp);
}

static struct bkey_packed *extent_sort_append(struct btree_keys *b,
					      struct bkey_packed *out,
					      struct bkey_packed **prev,
					      struct bkey_packed *k)
{
	if (bkey_deleted(k))
		return out;

	if (bkey_packed(k))
		b->nr_packed_keys++;
	else
		b->nr_unpacked_keys++;

	/* XXX: need better bkey_copy */
	memcpy(out, k, bkey_bytes(k));

	/*
	 * prev/out are packed, try_merge() works on unpacked keys... may make
	 * this work again later, but the main btree_mergesort() handles
	 * unpacking/merging/repacking
	 */
#if 0
	if (*prev && bch_bkey_try_merge(b, *prev, out))
		return out;
#endif

	*prev = out;
	return bkey_next(out);
}

void bch_extent_sort_fix_overlapping(struct btree_keys *b,
				     struct bset *bset,
				     struct btree_node_iter *iter)
{
	struct bkey_format *f = &b->format;
	struct btree_node_iter_set *_l = iter->data, *_r;
	struct bkey_packed *prev = NULL, *out = bset->start, *lk, *rk;
	struct bkey_tup l, r;

	b->nr_packed_keys	= 0;
	b->nr_unpacked_keys	= 0;

	heap_resort(iter, extent_sort_cmp);

	while (!bch_btree_node_iter_end(iter)) {
		lk = __btree_node_offset_to_key(b, _l->k);

		if (iter->used == 1) {
			out = extent_sort_append(b, out, &prev, lk);
			extent_sort_next(iter, b, _l);
			continue;
		}

		_r = iter->data + 1;
		if (iter->used > 2 &&
		    extent_sort_cmp(_r[0], _r[1]))
			_r++;

		rk = __btree_node_offset_to_key(b, _r->k);

		bkey_disassemble(&l, f, lk);
		bkey_disassemble(&r, f, rk);

		/* If current key and next key don't overlap, just append */
		if (bkey_cmp(l.k.p, bkey_start_pos(&r.k)) <= 0) {
			out = extent_sort_append(b, out, &prev, lk);
			extent_sort_next(iter, b, _l);
			continue;
		}

		/* Skip 0 size keys */
		if (!r.k.size) {
			extent_sort_next(iter, b, _r);
			continue;
		}

		/*
		 * overlap: keep the newer key and trim the older key so they
		 * don't overlap. comparing pointers tells us which one is
		 * newer, since the bsets are appended one after the other.
		 */

		/* can't happen because of comparison func */
		BUG_ON(_l->k < _r->k &&
		       !bkey_cmp(bkey_start_pos(&l.k), bkey_start_pos(&r.k)));

		if (_l->k > _r->k) {
			/* l wins, trim r */
			if (bkey_cmp(l.k.p, r.k.p) >= 0) {
				sort_key_next(iter, b, _r);
			} else {
				__bch_cut_front(l.k.p, bkey_tup_to_s(&r));
				extent_save(rk, &r.k, f);
			}

			extent_sort_sift(iter, b, _r - iter->data);
		} else if (bkey_cmp(l.k.p, r.k.p) > 0) {
			BKEY_PADDED(k) tmp;

			/*
			 * r wins, but it overlaps in the middle of l - split l:
			 */
			bkey_reassemble(&tmp.k, bkey_tup_to_s_c(&l));
			bch_cut_back(bkey_start_pos(&r.k), &tmp.k.k);

			__bch_cut_front(r.k.p, bkey_tup_to_s(&l));
			extent_save(lk, &l.k, f);

			extent_sort_sift(iter, b, 0);

			out = extent_sort_append(b, out, &prev,
						 bkey_to_packed(&tmp.k));
		} else {
			bch_cut_back(bkey_start_pos(&r.k), &l.k);
			extent_save(lk, &l.k, f);
		}
	}

	bset->u64s = (u64 *) out - bset->_data;
	b->nr_live_u64s = bset->u64s;

	pr_debug("sorted %i keys", bset->u64s);
}

int __bch_add_sectors(struct cache_set *c, struct btree *b,
		      struct bkey_s_c_extent e, u64 offset,
		      int sectors, bool fail_if_stale)
{
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca) {
		bool stale, dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		trace_bcache_add_sectors(ca, e.k, ptr, offset,
					 sectors, dirty);

		/*
		 * Two ways a dirty pointer could be stale here:
		 *
		 * - A bkey_cmpxchg() operation could be trying to replace a key
		 *   that no longer exists. The new key, which can have some of
		 *   the same pointers as the old key, gets added here before
		 *   checking if the cmpxchg operation succeeds or not to avoid
		 *   another race.
		 *
		 *   If that's the case, we just bail out of the cmpxchg
		 *   operation early - a dirty pointer can only be stale if the
		 *   actual dirty pointer in the btree was overwritten.
		 *
		 *   And in that case we _have_ to bail out here instead of
		 *   letting bkey_cmpxchg() fail and undoing the accounting we
		 *   did here with subtract_sectors() (like we do otherwise),
		 *   because buckets going stale out from under us changes which
		 *   pointers we count as dirty.
		 *
		 * - Journal replay
		 *
		 *   A dirty pointer could be stale in journal replay if we
		 *   haven't finished journal replay - if it's going to get
		 *   overwritten again later in replay.
		 *
		 *   In that case, we don't want to fail the insert (just for
		 *   mental health) - but, since extent_normalize() drops stale
		 *   pointers, we need to count replicas in a way that's
		 *   invariant under normalize.
		 *
		 *   Fuck me, I hate my life.
		 */
		stale = bch_mark_data_bucket(c, ca, b, ptr, sectors, dirty);
		if (stale && dirty && fail_if_stale)
			goto stale;
	}
	rcu_read_unlock();

	return 0;
stale:
	while (--ptr >= e.v->ptr)
		if ((ca = PTR_CACHE(c, ptr)))
			bch_mark_data_bucket(c, ca, b, ptr, -sectors,
				bch_extent_ptr_is_dirty(c, e, ptr));
	rcu_read_unlock();

	return -1;
}

static int bch_add_sectors(struct btree *b, struct bkey_s_c k,
			   u64 offset, int sectors, bool fail_if_stale)
{
	if (sectors && k.k->type == BCH_EXTENT) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		int ret;

		ret = __bch_add_sectors(b->c, b, e, offset,
					sectors, fail_if_stale);
		if (ret)
			return ret;

		if (!EXTENT_CACHED(e.v))
			bcache_dev_sectors_dirty_add(b->c, e.k->p.inode,
						     offset, sectors);
	}

	return 0;
}

static void bch_subtract_sectors(struct btree *b, struct bkey_s_c k,
				 u64 offset, int sectors)
{
	bch_add_sectors(b, k, offset, -sectors, false);
}

/* These wrappers subtract exactly the sectors that we're removing from @k */
static void bch_cut_subtract_back(struct btree *b, struct bpos where,
				  struct bkey_s k)
{
	bch_subtract_sectors(b, bkey_s_to_s_c(k), where.offset,
			     k.k->p.offset - where.offset);
	bch_cut_back(where, k.k);
}

static void bch_cut_subtract_front(struct btree *b, struct bpos where,
				   struct bkey_s k)
{
	bch_subtract_sectors(b, bkey_s_to_s_c(k), bkey_start_offset(k.k),
			     where.offset - bkey_start_offset(k.k));
	__bch_cut_front(where, k);
}

static void bch_drop_subtract(struct btree *b, struct bkey_s k)
{
	if (k.k->size)
		bch_subtract_sectors(b, bkey_s_to_s_c(k),
				     bkey_start_offset(k.k), k.k->size);
	k.k->size = 0;
	__set_bkey_deleted(k.k);
}

/*
 * Note: If this returns true because only some pointers matched,
 * we can lose some caching that had happened in the interim.
 * Because cache promotion only promotes the part of the extent
 * actually read, and not the whole extent, and due to the key
 * splitting done in bch_extent_insert_fixup, preserving such
 * caching is difficult.
 */
static bool bkey_cmpxchg_cmp(struct bkey_s_c l, struct bkey_s_c r)
{
	struct bkey_s_c_extent le, re;
	s64 offset;
	unsigned i;

	BUG_ON(!l.k->size || !r.k->size);

	if (l.k->type != r.k->type ||
	    l.k->version != r.k->version)
		return false;

	switch (l.k->type) {
	case KEY_TYPE_COOKIE:
		return !memcmp(bkey_s_c_to_cookie(l).v,
			       bkey_s_c_to_cookie(r).v,
			       sizeof(struct bch_cookie));

	case BCH_EXTENT:
		le = bkey_s_c_to_extent(l);
		re = bkey_s_c_to_extent(r);

		/*
		 * bkey_cmpxchg() handles partial matches - when either l or r
		 * has been trimmed - so we need just to handle l or r not
		 * starting at the same place when checking for a match here.
		 *
		 * If the starts of the keys are different, we just apply that
		 * offset to the device pointer offsets when checking those -
		 * matching how bch_cut_front() adjusts device pointer offsets
		 * when adjusting the start of a key:
		 */
		offset = bkey_start_offset(l.k) - bkey_start_offset(r.k);

		if (bch_extent_ptrs(le) == bch_extent_ptrs(re)) {
			for (i = 0; i < bch_extent_ptrs(le); i++)
				if (le.v->ptr[i]._val !=
				    re.v->ptr[i]._val +
				    (offset << PTR_OFFSET_OFFSET))
					goto try_partial;

			return true;
		}

try_partial:
#if (0)
		unsigned j;

		/*
		 * Maybe we just raced with copygc or tiering replacing one of
		 * the pointers: it should suffice to find _any_ matching
		 * pointer:
		 */
		for (i = 0; i < bch_extent_ptrs(l); i++)
			for (j = 0; j < bch_extent_ptrs(r); j++)
				if (le->v.ptr[i]._val !=
				    re->v.ptr[i]._val +
				    (offset << PTR_OFFSET_OFFSET))
					return true;
#endif
		return false;
	default:
		return false;
	}

}

/*
 * Returns true on success, false on failure (and false means @new no longer
 * overlaps with @k)
 *
 * If returned true, we may have inserted up to one key in @b.
 * If returned false, we may have inserted up to two keys in @b.
 *
 * On return, there is room in @res for at least one more key of the same size
 * as @new.
 */
static bool bkey_cmpxchg(struct btree *b,
			 struct btree_node_iter *iter,
			 struct bkey_s_c k,
			 struct bch_replace_info *replace,
			 struct bkey_i *new,
			 struct bpos *done,
			 bool *inserted,
			 struct journal_res *res)
{
	bool ret;
	struct bkey_i *old = &replace->key;

	/* must have something to compare against */
	BUG_ON(!bkey_val_u64s(&old->k));
	BUG_ON(b->level);

	/* new must be a subset of old */
	BUG_ON(bkey_cmp(new->k.p, old->k.p) > 0 ||
	       bkey_cmp(bkey_start_pos(&new->k),
			bkey_start_pos(&old->k)) < 0);

	/* if an exact match was requested, those are simple: */
	if (replace->replace_exact) {
		ret = bkey_val_bytes(k.k) == bkey_val_bytes(&old->k) &&
			!memcmp(k.k, &old->k, sizeof(*k.k)) &&
			!memcmp(k.v, &old->v, bkey_val_bytes(k.k));

		if (ret)
			replace->successes += 1;
		else
			replace->failures += 1;

		*done = new->k.p;
		return ret;
	}

	/*
	 * first, check if there was a hole - part of the new key that we
	 * haven't checked against any existing key
	 */
	if (bkey_cmp(bkey_start_pos(k.k), *done) > 0) {
		/* insert previous partial match: */
		if (bkey_cmp(*done, bkey_start_pos(&new->k)) > 0) {
			replace->successes += 1;

			/*
			 * [ prev key ]
			 *                 [ k        ]
			 *         [**|   new      ]
			 *            ^
			 *            |
			 *            +-- done
			 *
			 * The [**] are already known to match, so insert them.
			 */
			bch_btree_insert_and_journal(b, iter,
						     bch_key_split(*done, new),
						     res);
			*inserted = true;
		}

		bch_cut_subtract_front(b, bkey_start_pos(k.k),
				       bkey_i_to_s(new));
		/* advance @done from the end of prev key to the start of @k */
		*done = bkey_start_pos(k.k);
	}

	ret = bkey_cmpxchg_cmp(k, bkey_i_to_s_c(old));
	if (!ret) {
		/* failed: */
		replace->failures += 1;

		if (bkey_cmp(*done, bkey_start_pos(&new->k)) > 0) {
			/*
			 * [ prev key ]
			 *             [ k        ]
			 *    [*******| new              ]
			 *            ^
			 *            |
			 *            +-- done
			 *
			 * The [**] are already known to match, so insert them.
			 */
			bch_btree_insert_and_journal(b, iter,
						     bch_key_split(*done, new),
						     res);
			*inserted = true;
		}

		/* update @new to be the part we haven't checked yet */
		if (bkey_cmp(k.k->p, new->k.p) > 0)
			bch_drop_subtract(b, bkey_i_to_s(new));
		else
			bch_cut_subtract_front(b, k.k->p, bkey_i_to_s(new));
	} else
		replace->successes += 1;

	/* advance @done past the part of @k overlapping @new */
	*done = bkey_cmp(k.k->p, new->k.p) < 0 ? k.k->p : new->k.p;
	return ret;
}

/* We are trying to insert a key with an older version than the existing one */
static void handle_existing_key_newer(struct btree *b,
				      struct btree_node_iter *iter,
				      struct bkey_i *insert,
				      const struct bkey *k,
				      bool *inserted,
				      struct journal_res *res)
{
	struct bkey_i *split;

	/* k is the key currently in the tree, 'insert' the new key */

	switch (bch_extent_overlap(k, &insert->k)) {
	case BCH_EXTENT_OVERLAP_FRONT:
		/* k and insert share the start, remove it from insert */
		bch_cut_subtract_front(b, k->p, bkey_i_to_s(insert));
		break;

	case BCH_EXTENT_OVERLAP_BACK:
		/* k and insert share the end, remove it from insert */
		bch_cut_subtract_back(b, bkey_start_pos(k),
				      bkey_i_to_s(insert));
		break;

	case BCH_EXTENT_OVERLAP_MIDDLE:
		/*
		 * We have an overlap where @k (newer version) splits
		 * @insert (older version) in three:
		 * - start only in insert
		 * - middle common section -- keep k
		 * - end only in insert
		 *
		 * Insert the start of @insert ourselves, then update
		 * @insert to to represent the end.
		 *
		 * Since we're splitting the insert key, we have to use
		 * bch_btree_insert_and_journal(), which adds a journal
		 * entry to @res.
		 */
		split = bch_key_split(bkey_start_pos(k), insert),
		bch_cut_subtract_front(b, k->p, bkey_i_to_s(insert));
		bch_btree_insert_and_journal(b, iter, split, res);
		*inserted = true;
		break;

	case BCH_EXTENT_OVERLAP_ALL:
		/* k completely covers insert -- drop insert */
		bch_drop_subtract(b, bkey_i_to_s(insert));
		break;
	}
}

/**
 * bch_extent_insert_fixup - insert a new extent and deal with overlaps
 *
 * this may result in not actually doing the insert, or inserting some subset
 * of the insert key. For cmpxchg operations this is where that logic lives.
 *
 * All subsets of @insert that need to be inserted are inserted using
 * bch_btree_insert_and_journal(). If @b or @res fills up, this function
 * returns false, setting @done for the prefix of @insert that actually got
 * inserted.
 *
 * BSET INVARIANTS: this function is responsible for maintaining all the
 * invariants for bsets of extents in memory. things get really hairy with 0
 * size extents
 *
 * within one bset:
 *
 * bkey_start_pos(bkey_next(k)) >= k
 * or bkey_start_offset(bkey_next(k)) >= k->offset
 *
 * i.e. strict ordering, no overlapping extents.
 *
 * multiple bsets (i.e. full btree node):
 *
 * ∀ k, j
 *   k.size != 0 ∧ j.size != 0 →
 *     ¬ (k > bkey_start_pos(j) ∧ k < j)
 *
 * i.e. no two overlapping keys _of nonzero size_
 *
 * We can't realistically maintain this invariant for zero size keys because of
 * the key merging done in bch_btree_insert_key() - for two mergeable keys k, j
 * there may be another 0 size key between them in another bset, and it will
 * thus overlap with the merged key.
 *
 * This returns true if it inserted, false otherwise.
 * Note that it can return false due to failure or because there is no
 * room for the insertion -- the caller needs to split the btree node.
 *
 * In addition, the end of done indicates how much has been processed.
 * If the end of done is not the same as the end of insert, then
 * key insertion needs to continue/be retried.
 */
bool bch_insert_fixup_extent(struct btree *b, struct bkey_i *insert,
			     struct btree_node_iter *iter,
			     struct bch_replace_info *replace,
			     struct bpos *done,
			     struct journal_res *res)
{
	const struct bkey_format *f = &b->keys.format;
	struct bpos orig_insert = insert->k.p;
	struct bkey_packed *_k;
	struct bkey_tup tup;
	struct bkey_s k;
	BKEY_PADDED(k) split;
	bool inserted = false;

	BUG_ON(bkey_deleted(&insert->k));
	BUG_ON(!insert->k.size);

	/*
	 * The end of this key is the range processed so far.
	 *
	 * At the start, we add bucket sector counts for the entirely of the
	 * new insert, then we subtract sector counts for existing keys or
	 * parts of the new key as necessary.
	 *
	 * All sector counts up to @done are finalized.
	 */
	*done = bkey_start_pos(&insert->k);

	/*
	 * If this is a cmpxchg operation, @insert doesn't necessarily exist in
	 * the btree, and may have pointers not pinned by open buckets; thus
	 * some of the pointers might be stale because we raced with foreground
	 * writes.
	 *
	 * If that happens bkey_cmpxchg() is going to fail; bail out here
	 * instead of calling subtract_sectors() in the fail path to avoid
	 * various races (we definitely don't want to increment/decrement
	 * sectors_dirty on a bucket that's been reused, or worse have a bucket
	 * go stale between here and subtract_sectors()).
	 *
	 * But only bail out here for cmpxchg operations - in journal replay we
	 * can also insert keys with stale pointers, but for those we still need
	 * to proceed with the insertion.
	 */
	if (bch_add_sectors(b, bkey_i_to_s_c(insert),
			    bkey_start_offset(&insert->k),
			    insert->k.size, replace != NULL)) {
		/* We raced - a dirty pointer was stale */
		*done = insert->k.p;
		insert->k.size = 0;
		if (replace != NULL)
			replace->failures += 1;
		return false;
	}

	while (insert->k.size &&
	       (_k = bch_btree_node_iter_peek_overlapping(iter, &b->keys,
							  &insert->k))) {
		bool needs_split, res_full;

		bkey_disassemble(&tup, f, _k);

		k = bkey_tup_to_s(&tup);
		/*
		 * Before setting @done, we first check if we have space for
		 * the insert in the btree node and journal reservation.
		 *
		 * Each insert checks for room in the journal entry, but we
		 * check for room in the btree node up-front. In the worst
		 * case, bkey_cmpxchg() will insert two keys, and one
		 * iteration of this room will insert one key, so we need
		 * room for three keys.
		 */
		needs_split = (bch_btree_keys_u64s_remaining(b) <
			       BKEY_EXTENT_MAX_U64s * 3);
		res_full = journal_res_full(res, &insert->k);

		if (needs_split || res_full) {
			/*
			 * XXX: would be better to explicitly signal that we
			 * need to split
			 */
			bch_cut_subtract_back(b, *done, bkey_i_to_s(insert));
			goto out;
		}

		/*
		 * We might overlap with 0 size extents; we can't skip these
		 * because if they're in the set we're inserting to we have to
		 * adjust them so they don't overlap with the key we're
		 * inserting. But we don't want to check them for replace
		 * operations.
		 */
		if (!replace)
			*done = bkey_cmp(k.k->p, insert->k.p) < 0
				? k.k->p : insert->k.p;
		else if (k.k->size &&
			 !bkey_cmpxchg(b, iter, bkey_s_to_s_c(k), replace,
				       insert, done, &inserted, res))
			continue;

		if (k.k->size && insert->k.version &&
		    insert->k.version < k.k->version) {
			handle_existing_key_newer(b, iter, insert, k.k,
						  &inserted, res);
			continue;
		}

		/* k is the key currently in the tree, 'insert' the new key */

		switch (bch_extent_overlap(&insert->k, k.k)) {
		case BCH_EXTENT_OVERLAP_FRONT:
			/* insert and k share the start, invalidate in k */
			bch_cut_subtract_front(b, insert->k.p, k);
			extent_save(_k, k.k, f);
			break;

		case BCH_EXTENT_OVERLAP_BACK:
			/* insert and k share the end, invalidate in k */
			bch_cut_subtract_back(b, bkey_start_pos(&insert->k), k);
			extent_save(_k, k.k, f);

			/*
			 * As the auxiliary tree is indexed by the end of the
			 * key and we've just changed the end, update the
			 * auxiliary tree.
			 */
			bch_bset_fix_invalidated_key(&b->keys, _k);
			bch_btree_node_iter_advance(iter, &b->keys);
			break;

		case BCH_EXTENT_OVERLAP_ALL:
			/* The insert key completely covers k, invalidate k */
			if (!bkey_deleted(_k))
				btree_keys_account_key_drop(&b->keys, _k);

			bch_drop_subtract(b, k);
			k.k->p = bkey_start_pos(&insert->k);
			extent_save(_k, k.k, f);

			bch_bset_fix_invalidated_key(&b->keys, _k);
			bch_btree_node_iter_advance(iter, &b->keys);
			break;

		case BCH_EXTENT_OVERLAP_MIDDLE:
			/*
			 * The insert key falls 'in the middle' of k
			 * The insert key splits k in 3:
			 * - start only in k, preserve
			 * - middle common section, invalidate in k
			 * - end only in k, preserve
			 *
			 * We update the old key to preserve the start,
			 * insert will be the new common section,
			 * we manually insert the end that we are preserving.
			 *
			 * modify k _before_ doing the insert (which will move
			 * what k points to)
			 */
			bkey_reassemble(&split.k, bkey_s_to_s_c(k));
			bch_cut_back(bkey_start_pos(&insert->k), &split.k.k);

			__bch_cut_front(bkey_start_pos(&insert->k), k);
			bch_cut_subtract_front(b, insert->k.p, k);
			extent_save(_k, k.k, f);

			bch_bset_insert(&b->keys, iter, &split.k);
			break;
		}
	}

	/* Was there a hole? */
	if (bkey_cmp(*done, insert->k.p) < 0) {
		/*
		 * Holes not allowed for cmpxchg operations, so chop off
		 * whatever we're not inserting (but done needs to reflect what
		 * we've processed, i.e. what insert was)
		 */
		if (replace != NULL)
			bch_cut_subtract_back(b, *done, bkey_i_to_s(insert));

		*done = orig_insert;
	}

out:
	if (insert->k.size) {
		bch_btree_insert_and_journal(b, iter, insert, res);
		inserted = true;
	}

	return inserted;
}

static bool bch_extent_invalid(const struct cache_set *c, struct bkey_s_c k)
{
	return (k.k->type == BCH_EXTENT &&
		!k.k->size) ||
		__ptr_invalid(c, k);
}

static void bch_extent_debugcheck(struct btree *b, struct bkey_s_c k)
{
	struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
	const struct bch_extent_ptr *ptr;
	struct cache_member_rcu *mi;
	struct cache_set *c = b->c;
	struct cache *ca;
	struct bucket *g;
	unsigned seq, stale;
	char buf[160];
	bool bad;
	unsigned ptrs_per_tier[CACHE_TIERS];
	unsigned i, dev, tier, replicas;

	memset(ptrs_per_tier, 0, sizeof(ptrs_per_tier));

	if (bch_extent_ptrs(e) < bch_extent_replicas_needed(c, e.v)) {
		bch_bkey_val_to_text(b, buf, sizeof(buf), k);
		cache_set_bug(c, "extent key bad (too few replicas): %s", buf);
		return;
	}

	mi = cache_member_info_get(c);

	extent_for_each_ptr(e, ptr) {
		bool dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		dev = PTR_DEV(ptr);

		/* Could be a special pointer such as PTR_CHECK_DEV */
		if (dev >= mi->nr_in_set) {
			if (dev != PTR_LOST_DEV)
				goto bad_device;

			continue;
		}

		tier = CACHE_TIER(&mi->m[dev]);
		ptrs_per_tier[tier]++;

		stale = 0;

		if ((ca = PTR_CACHE(c, ptr))) {
			g = PTR_BUCKET(ca, ptr);

			do {
				struct bucket_mark mark;

				seq = read_seqbegin(&c->gc_cur_lock);
				mark = READ_ONCE(g->mark);

				/* between mark and bucket gen */
				smp_rmb();

				stale = ptr_stale(ca, ptr);

				cache_set_bug_on(stale && dirty, c,
						 "stale dirty pointer");

				cache_set_bug_on(stale > 96, c,
						 "key too stale: %i",
						 stale);

				bad = (!stale &&
				       !__gc_will_visit_node(c, b) &&
				       (mark.is_metadata ||
					(!mark.dirty_sectors &&
					 !mark.owned_by_allocator &&
					 dirty)));
			} while (read_seqretry(&c->gc_cur_lock, seq));

			if (bad)
				goto bad_ptr;
		}
	}

	replicas = CACHE_SET_DATA_REPLICAS_WANT(&c->sb);
	for (i = 0; i < CACHE_TIERS; i++)
		if (ptrs_per_tier[i] > replicas) {
			bch_bkey_val_to_text(b, buf, sizeof(buf), k);
			cache_set_bug(c,
				      "extent key bad (too many tier %u replicas): %s",
				      i, buf);
			break;
		}

	cache_member_info_put();
	return;

bad_device:
	bch_bkey_val_to_text(b, buf, sizeof(buf), k);
	cache_set_bug(c, "extent pointer %u device missing: %s",
		      (unsigned) (ptr - e.v->ptr), buf);
	cache_member_info_put();
	return;

bad_ptr:
	bch_bkey_val_to_text(b, buf, sizeof(buf), k);
	cache_set_bug(c, "extent pointer %u bad gc mark: %s:\nbucket %zu prio %i "
		      "gen %i last_gc %i mark 0x%08x",
		      (unsigned) (ptr - e.v->ptr), buf, PTR_BUCKET_NR(ca, ptr),
		      g->read_prio, PTR_BUCKET_GEN(ca, ptr),
		      g->oldest_gen, g->mark.counter);
	cache_member_info_put();
	return;
}

static unsigned PTR_TIER(struct cache_member_rcu *mi,
			 const struct bch_extent *e,
			 unsigned ptr)
{
	unsigned dev = PTR_DEV(&e->ptr[ptr]);

	return dev < mi->nr_in_set ? CACHE_TIER(&mi->m[dev]) : UINT_MAX;
}

bool bch_extent_normalize(struct cache_set *c, struct bkey_s k)
{
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct cache_member_rcu *mi;
	unsigned i;
	bool swapped, have_data = false;
	bool cached;

	switch (k.k->type) {
	case KEY_TYPE_ERROR:
		return false;

	case KEY_TYPE_DELETED:
	case KEY_TYPE_COOKIE:
		return true;

	case KEY_TYPE_DISCARD:
		return !k.k->version;

	case BCH_EXTENT:
		e = bkey_s_to_extent(k);

		/*
		 * Preserve cached status since its stored in the
		 * first pointer
		 */
		cached = EXTENT_CACHED(e.v);

		bch_extent_drop_stale(c, k);

		mi = cache_member_info_get(c);

		/* Bubble sort pointers by tier, lowest (fastest) tier first */
		do {
			swapped = false;
			for (i = 0; i + 1 < bch_extent_ptrs(e); i++) {
				if (PTR_TIER(mi, e.v, i) >
				    PTR_TIER(mi, e.v, i + 1)) {
					swap(e.v->ptr[i], e.v->ptr[i + 1]);
					swapped = true;
				}
			}
		} while (swapped);

		cache_member_info_put();

		extent_for_each_ptr(e, ptr)
			if (PTR_DEV(ptr) != PTR_LOST_DEV)
				have_data = true;

		if (!have_data) {
			bch_set_extent_ptrs(e, 0);
			if (cached) {
				k.k->type = KEY_TYPE_DISCARD;
				if (!k.k->version)
					return true;
			} else {
				k.k->type = KEY_TYPE_ERROR;
			}
		} else {
			SET_EXTENT_CACHED(e.v, cached);
		}

		return false;
	default:
		BUG();
	}
}

/*
 * This picks a non-stale pointer, preferabbly from a device other than
 * avoid.  Avoid can be NULL, meaning pick any.  If there are no non-stale
 * pointers to other devices, it will still pick a pointer from avoid.
 * Note that it prefers lowered-numbered pointers to higher-numbered pointers
 * as the pointers are sorted by tier, hence preferring pointers to tier 0
 * rather than pointers to tier 1.
 */
struct cache *bch_extent_pick_ptr_avoiding(struct cache_set *c,
					   struct bkey_s_c k,
					   const struct bch_extent_ptr **ptr,
					   struct cache *avoid)
{
	struct bkey_s_c_extent e;
	const struct bch_extent_ptr *i;
	struct cache *ca, *picked = NULL;

	switch (k.k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_COOKIE:
		return NULL;

	case KEY_TYPE_ERROR:
		return ERR_PTR(-EIO);

	case BCH_EXTENT:
		/*
		 * Note: If DEV is PTR_LOST_DEV, PTR_CACHE returns NULL so if
		 * there are no other pointers, we'll return ERR_PTR(-EIO).
		 */
		e = bkey_s_c_to_extent(k);
		rcu_read_lock();

		extent_for_each_online_device(c, e, i, ca)
			if (!ptr_stale(ca, i)) {
				picked = ca;
				*ptr = i;
				if (ca != avoid)
					break;
			}

		if (picked != NULL) {
			percpu_ref_get(&picked->ref);
			rcu_read_unlock();
			return picked;
		}

		rcu_read_unlock();

		/* data missing that's not supposed to be? */
		return EXTENT_CACHED(e.v)
			? NULL
			: ERR_PTR(-EIO);

	default:
		BUG();
	}
}

#if 0
static uint64_t merge_chksums(struct bkey *l, struct bkey *r)
{
	return (l->val[bkeyp_extent_ptrs(l)] + r->val[bkeyp_extent_ptrs(r)]) &
		~((uint64_t)1 << 63);
}
#endif

static enum merge_result bch_extent_merge(struct btree_keys *bk,
					  struct bkey_i *l, struct bkey_i *r)
{
	struct btree *b = container_of(bk, struct btree, keys);
	struct bkey_s_extent el, er;
	struct cache *ca;
	unsigned i;

	if (key_merging_disabled(b->c))
		return BCH_MERGE_NOMERGE;

	/*
	 * Generic header checks
	 * Assumes left and right are in order
	 * Left and right must be exactly aligned
	 */

	if (l->k.u64s		!= r->k.u64s ||
	    l->k.type		!= r->k.type ||
	    l->k.version	!= r->k.version ||
	    bkey_cmp(l->k.p, bkey_start_pos(&r->k)))
		return BCH_MERGE_NOMERGE;

	switch (l->k.type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		/* These types are mergeable, and no val to check */
		break;

	case BCH_EXTENT:
		el = bkey_i_to_s_extent(l);
		er = bkey_i_to_s_extent(r);

		for (i = 0; i < bch_extent_ptrs(el); i++) {
			/*
			 * compare all the pointer fields at once, adding the
			 * size to the left pointer's offset:
			 */
			if (el.v->ptr[i]._val + PTR(0, el.k->size, 0)._val !=
			    er.v->ptr[i]._val)
				return BCH_MERGE_NOMERGE;

			/*
			 * we don't allow extent pointers to straddle buckets -
			 * if the device is offline, we don't know the bucket
			 * size so we can't check
			 */
			rcu_read_lock();
			if (!(ca = PTR_CACHE(b->c, &el.v->ptr[i])) ||
			    PTR_BUCKET_NR(ca, &el.v->ptr[i]) !=
			    PTR_BUCKET_NR(ca, &er.v->ptr[i])) {
				rcu_read_unlock();
				return BCH_MERGE_NOMERGE;
			}
			rcu_read_unlock();
		}

		break;
	default:
		return BCH_MERGE_NOMERGE;
	}

	/* Keys with no pointers aren't restricted to one bucket and could
	 * overflow KEY_SIZE
	 */
	if ((u64) l->k.size + r->k.size > KEY_SIZE_MAX) {
		bch_key_resize(&l->k, KEY_SIZE_MAX);
		bch_cut_front(l->k.p, r);
		return BCH_MERGE_PARTIAL;
	}
#if 0
	if (KEY_CSUM(l)) {
		if (KEY_CSUM(r))
			l->val[bch_extent_ptrs(l)] = merge_chksums(l, r);
		else
			SET_KEY_CSUM(l, 0);
	}
#endif
	bch_key_resize(&l->k, l->k.size + r->k.size);

	return BCH_MERGE_MERGE;
}

static bool extent_i_save(struct bkey_packed *dst, struct bkey_i *src,
			  const struct bkey_format *f)
{
	struct bkey_i *dst_unpacked;
	bool ret;

	BUG_ON(bkeyp_val_u64s(f, dst) != bkey_val_u64s(&src->k));

	if ((dst_unpacked = packed_to_bkey(dst))) {
		bkey_copy(dst_unpacked, src);
		ret = true;
	} else {
		ret = bkey_pack(dst, src, f);
	}

	return ret;
}

/*
 * When merging an extent that we're inserting into a btree node, the new merged
 * extent could overlap with an existing 0 size extent - if we don't fix that,
 * it'll break the btree node iterator so this code finds those 0 size extents
 * and shifts them out of the way.
 *
 * Also unpacks and repacks.
 */
static bool bch_extent_merge_inline(struct btree_keys *b,
				    struct btree_node_iter *iter,
				    struct bkey_packed *l,
				    struct bkey_packed *r)
{
	const struct bkey_format *f = &b->format;
	struct bset_tree *t;
	struct bkey_packed *k, *m;
	struct bkey uk;
	BKEY_PADDED(k) li;
	BKEY_PADDED(k) ri;
	struct bkey_i *mi;
	bool ret;

	if (l >= b->set->data->start &&
	    l < bset_bkey_last(bset_tree_last(b)->data)) {
		bkey_unpack(&li.k, f, l);
		bkey_copy(&ri.k, packed_to_bkey(r));
		m = l;
		mi = &li.k;
	} else if (r >= b->set->data->start &&
		   r < bset_bkey_last(bset_tree_last(b)->data)) {
		bkey_unpack(&ri.k, f, r);
		bkey_copy(&li.k, packed_to_bkey(l));
		m = r;
		mi = &ri.k;
	} else
		BUG();

	switch (bch_extent_merge(b, &li.k, &ri.k)) {
	case BCH_MERGE_NOMERGE:
		return false;
	case BCH_MERGE_PARTIAL:
		if (!extent_i_save(m, mi, f))
			return false;

		if (m == r)
			bkey_copy(packed_to_bkey(l), &li.k);
		else
			bkey_copy(packed_to_bkey(r), &ri.k);

		ret = false;
		break;
	case BCH_MERGE_MERGE:
		if (!extent_i_save(m, &li.k, f))
			return false;

		ret = true;
		break;
	}

	/*
	 * l is the output of bch_extent_merge(), m is the extent that was in
	 * the btree.
	 *
	 * Iterate over every bset that doesn't contain m, find the iterator's
	 * position and search from there for 0 size extents that overlap with
	 * m.
	 */
	for (t = b->set; t <= b->set + b->nsets; t++) {
		if (!t->data->u64s ||
		    (m >= t->data->start &&
		     m < bset_bkey_last(t->data)))
			continue;

		/*
		 * if we don't find this bset in the iterator we already got to
		 * the end of that bset, so start searching from the end.
		 */
		k = bch_btree_node_iter_bset_pos(iter, b, t->data) ?:
			bkey_prev(b, t, bset_bkey_last(t->data));

		if (m == l) {
			/*
			 * Back merge: 0 size extents will be before the key
			 * that was just inserted (and thus the iterator
			 * position) - walk backwards to find them
			 */
			for (;
			     k &&
			     (uk = bkey_unpack_key(f, k),
			      bkey_cmp(uk.p, bkey_start_pos(&li.k.k)) > 0);
			     k = bkey_prev(b, t, k)) {
				if (bkey_cmp(uk.p, li.k.k.p) >= 0)
					continue;

				BUG_ON(!bkey_deleted(k));

				uk.p = bkey_start_pos(&li.k.k);
				extent_save(k, &uk, f);

				bch_bset_fix_invalidated_key(b, k);
			}
		} else {
			/* Front merge - walk forwards */
			for (;
			     k != bset_bkey_last(t->data) &&
			     (uk = bkey_unpack_key(f, k),
			      bkey_cmp(uk.p, li.k.k.p) < 0);
			     k = bkey_next(k)) {
				if (bkey_cmp(uk.p,
					     bkey_start_pos(&li.k.k)) <= 0)
					continue;

				BUG_ON(!bkey_deleted(k));

				uk.p = li.k.k.p;
				extent_save(k, &uk, f);

				bch_bset_fix_invalidated_key(b, k);
			}
		}
	}

	bch_btree_node_iter_sort(iter, b);
	return true;
}

static const struct btree_keys_ops bch_extent_ops = {
	.key_normalize	= bch_ptr_normalize,
	.key_merge	= bch_extent_merge,
	.key_merge_inline = bch_extent_merge_inline,
	.is_extents	= true,
};

const struct bkey_ops bch_bkey_extent_ops = {
	.key_invalid	= bch_extent_invalid,
	.key_debugcheck	= bch_extent_debugcheck,
	.val_to_text	= bch_extent_to_text,
	.is_extents	= true,
};

const struct btree_keys_ops *bch_btree_ops[] = {
	[BTREE_ID_EXTENTS]	= &bch_extent_ops,
	[BTREE_ID_INODES]	= &bch_inode_ops,
};
