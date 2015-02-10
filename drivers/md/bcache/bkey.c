
#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/kernel.h>

#include "bkey.h"
#include "bset.h"
#include "util.h"

const struct bkey_format bch_bkey_format_current = BKEY_FORMAT_CURRENT;

int bch_bkey_to_text(char *buf, size_t size, const struct bkey *k)
{
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("u64s %u type %u %llu:%llu snap %u len %u ver %u",
	  k->u64s, k->type, k->p.inode, k->p.offset,
	  k->p.snapshot, k->size, k->version);

	switch (k->type) {
	case KEY_TYPE_DELETED:
		p(" deleted");
		break;
	case KEY_TYPE_DISCARD:
		p(" discard");
		break;
	case KEY_TYPE_ERROR:
		p(" error");
		break;
	case KEY_TYPE_COOKIE:
		p(" cookie");
		break;
	}
#undef p

	return out - buf;
}

struct pack_state {
	const struct bkey_format	*format;
	unsigned			field;
	unsigned			shift;
	u64				*p;
};

__always_inline
static struct pack_state pack_state_init(const struct bkey_format *format,
					 const struct bkey_packed *k)
{
	return (struct pack_state) {
		.format	= format,
		.field	= 0,
		.shift	= 64 - high_bit_offset,
		.p	= (u64 *) high_word(format, k),
	};
}

__always_inline
static u64 get_inc_field(struct pack_state *state)
{
	unsigned bits = state->format->bits_per_field[state->field];
	u64 offset = state->format->field_offset[state->field];

	/* bits might be 0 - and if bits is 0, v will be 0 when we use mask */
	u64 v = 0, mask = ~((~0ULL << 1) << (bits - 1));

	state->field++;

	if (bits >= state->shift) {
		bits -= state->shift;
		v = *state->p << bits;

		state->p = next_word(state->p);
		state->shift = 64;
	}

	if (bits) {
		state->shift -= bits;
		v |= *state->p >> state->shift;
	}

	return (v & mask) + offset;
}

__always_inline
static bool set_inc_field(struct pack_state *state, u64 v)
{
	unsigned bits = state->format->bits_per_field[state->field];
	u64 offset = state->format->field_offset[state->field];

	state->field++;

	if (v < offset)
		return false;

	v -= offset;

	if (fls64(v) > bits)
		return false;

	if (bits >= state->shift) {
		bits -= state->shift;
		*state->p |= v >> bits;

		state->p = next_word(state->p);
		state->shift = 64;
	}

	if (bits) {
		state->shift -= bits;
		*state->p |= v << state->shift;
	}

	return true;
}

bool bch_bkey_format_transform(const struct bkey_format *out_f,
			       struct bkey_packed *out,
			       const struct bkey_format *in_f,
			       const struct bkey_packed *in)
{
	struct pack_state out_s = pack_state_init(out_f, out);
	struct pack_state in_s = pack_state_init(in_f, in);
	unsigned i;

	out->u64s	= out_f->key_u64s + in->u64s - in_f->key_u64s;
	out->type	= in->type;
	memset(&out->key_start, 0,
	       out_f->key_u64s * sizeof(u64) -
	       offsetof(struct bkey_packed, key_start));

	for (i = 0; i < out_s.format->nr_fields; i++)
		if (!set_inc_field(&out_s, get_inc_field(&in_s)))
			return false;

	return true;
}

void bkey_unpack(struct bkey_i *dst,
		 const struct bkey_format *format,
		 const struct bkey_packed *src)
{
	dst->k = bkey_unpack_key(format, src);

	memcpy(&dst->v,
	       bkeyp_val(format, src),
	       bkeyp_val_bytes(format, src));
}

bool bkey_pack(struct bkey_packed *out, const struct bkey_i *in,
	       const struct bkey_format *format)
{
	struct bkey_packed tmp;

	if (!bkey_pack_key(&tmp, &in->k, format))
		return false;

	memmove((u64 *) out + format->key_u64s,
		&in->v,
		bkey_val_bytes(&in->k));
	memcpy(out, &tmp,
	       format->key_u64s * sizeof(u64));

	return true;
}

bool bkey_pack_pos(struct bkey_packed *out, struct bpos in,
		   const struct bkey_format *format)
{
	struct pack_state state = pack_state_init(format, out);

	memset(out, 0, format->key_u64s * sizeof(u64));
	out->u64s	= format->key_u64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->type	= KEY_TYPE_DELETED;

	return (set_inc_field(&state, in.inode) &&
		set_inc_field(&state, in.offset) &&
		set_inc_field(&state, in.snapshot));
}

__always_inline
static bool set_inc_field_lossy(struct pack_state *state, u64 v)
{
	unsigned bits = state->format->bits_per_field[state->field];
	u64 offset = state->format->field_offset[state->field];

	state->field++;

	if (v < offset)
		return false;

	v -= offset;

	v <<= 64 - bits;
	v >>= 64 - bits;

	if (bits >= state->shift) {
		bits -= state->shift;
		*state->p |= v >> bits;

		state->p = next_word(state->p);
		state->shift = 64;
	}

	if (bits) {
		state->shift -= bits;
		*state->p |= v << state->shift;
	}

	return true;
}

/*
 * This is used in bset_search_tree(), where we need a packed pos in order to be
 * able to compare against the keys in the auxiliary search tree - and it's
 * legal to use a packed pos that isn't equivalent to the original pos,
 * _provided_ it compares <= to the original pos.
 */
bool bkey_pack_pos_lossy(struct bkey_packed *out, struct bpos in,
			 const struct bkey_format *format)
{
	struct pack_state state = pack_state_init(format, out);

	memset(out, 0, format->key_u64s * sizeof(u64));
	out->u64s	= format->key_u64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->type	= KEY_TYPE_DELETED;

	return (set_inc_field_lossy(&state, in.inode) &&
		set_inc_field_lossy(&state, in.offset) &&
		set_inc_field_lossy(&state, in.snapshot));
}

void bch_bkey_format_init(struct bkey_format_state *s)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++)
		s->field_min[i] = U64_MAX;

	for (i = 0; i < ARRAY_SIZE(s->field_max); i++)
		s->field_max[i] = 0;
}

static void __bkey_format_add(struct bkey_format_state *s,
			      unsigned field, u64 v)
{
	s->field_min[field] = min(s->field_min[field], v);
	s->field_max[field] = max(s->field_max[field], v);
}

/*
 * Changes @format so that @k can be successfully packed with @format
 */
void bch_bkey_format_add_key(struct bkey_format_state *s, struct bkey *k)
{
	unsigned field = 0;

	__bkey_format_add(s, field++, k->p.inode);
	__bkey_format_add(s, field++, k->p.offset);
	__bkey_format_add(s, field++, k->p.snapshot);
	__bkey_format_add(s, field++, k->size);
	__bkey_format_add(s, field++, k->version);
	EBUG_ON(field != BKEY_NR_FIELDS);
}

void bch_bkey_format_add_pos(struct bkey_format_state *s, struct bpos p)
{
	unsigned field = 0;

	__bkey_format_add(s, field++, p.inode);
	__bkey_format_add(s, field++, p.offset);
	__bkey_format_add(s, field++, p.snapshot);
}

struct bkey_format bch_bkey_format_done(struct bkey_format_state *s)
{
	unsigned i, bits = KEY_PACKED_BITS_START;
	struct bkey_format ret = {
		.nr_fields = BKEY_NR_FIELDS,
	};

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++) {
		ret.field_offset[i]	= min(s->field_min[i], s->field_max[i]);
		ret.bits_per_field[i]	= fls(s->field_max[i] -
					      ret.field_offset[i]);

		bits += ret.bits_per_field[i];
	}

	ret.key_u64s = DIV_ROUND_UP(bits, 64);

	return ret;
}

/* Most significant differing bit */
unsigned bkey_greatest_differing_bit(const struct bkey_format *format,
				     const struct bkey_packed *l_k,
				     const struct bkey_packed *r_k)
{
	const u64 *l = high_word(format, l_k);
	const u64 *r = high_word(format, r_k);
	unsigned nr_key_bits = bkey_format_key_bits(format);
	u64 l_v, r_v;

	/* for big endian, skip past header */
	nr_key_bits += high_bit_offset;
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (1) {
		if (nr_key_bits < 64) {
			l_v >>= 64 - nr_key_bits;
			r_v >>= 64 - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= 64;
		}

		if (l_v != r_v)
			return fls64(l_v ^ r_v) + nr_key_bits;

		if (!nr_key_bits)
			return 0;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
	}
}

static int __bkey_cmp_bits(unsigned nr_key_bits, const u64 *l, const u64 *r)
{
	u64 l_v, r_v;

	if (!nr_key_bits)
		return 0;

	/* for big endian, skip past header */
	nr_key_bits += high_bit_offset;
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (1) {
		if (nr_key_bits < 64) {
			l_v >>= 64 - nr_key_bits;
			r_v >>= 64 - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= 64;
		}

		if (l_v != r_v)
			return l_v < r_v ? -1 : 1;

		if (!nr_key_bits)
			return 0;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
	}
}

/*
 * Would like to use this if we can make __bkey_cmp_bits() fast enough, it'll be
 * a decent reduction in code size
 */
#if 0
int bkey_cmp(struct bpos l, struct bpos r)
{
	return __bkey_cmp_bits((sizeof(l->p.inode) +
				sizeof(l->p.offset) +
				sizeof(l->p.snapshot)) * 8,
			       __high_word(BKEY_U64s, l),
			       __high_word(BKEY_U64s, r));
}
#endif

int __bkey_cmp_packed(const struct bkey_format *f,
		      const struct bkey_packed *l,
		      const struct bkey_packed *r)
{
	int ret;

	EBUG_ON(!bkey_packed(l) || !bkey_packed(r));

	ret = __bkey_cmp_bits(bkey_format_key_bits(f),
			      high_word(f, l),
			      high_word(f, r));

	EBUG_ON(ret != bkey_cmp(bkey_unpack_key(f, l).p,
				bkey_unpack_key(f, r).p));
	return ret;
}

int __bkey_cmp_left_packed(const struct bkey_format *format,
			   const struct bkey_packed *l, struct bpos r)
{
	return bkey_cmp(__bkey_unpack_key(format, l).p, r);
}
