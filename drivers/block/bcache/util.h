
#ifndef _BCACHE_UTIL_H
#define _BCACHE_UTIL_H

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/llist.h>
#include <linux/ratelimit.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#ifndef USHRT_MAX
#define USHRT_MAX	((u16)(~0U))
#define SHRT_MAX	((s16)(USHRT_MAX>>1))
#endif

#ifndef REQ_WRITE

#define REQ_WRITE		WRITE
#define REQ_UNPLUG		(1U << BIO_RW_UNPLUG)
#define REQ_SYNC		((1U << BIO_RW_SYNCIO)|REQ_UNPLUG)
#define REQ_META		(1U << BIO_RW_META)
#define REQ_RAHEAD		(1U << BIO_RW_AHEAD)
#define REQ_FLUSH		(1U << BIO_RW_BARRIER)

#define console_lock()		acquire_console_sem()
#define console_unlock()	release_console_sem()

#define blkdev_put(...)		close_bdev_exclusive(__VA_ARGS__)
#define blkdev_get_by_path(...)	open_bdev_exclusive(__VA_ARGS__)

#else

#define REQ_UNPLUG		0U
#define BIO_RW_DISCARD		__REQ_DISCARD
#define current_is_writer(x)	true

#endif

extern struct workqueue_struct *system_wq;

#define PAGE_SECTORS		(PAGE_SIZE / 512)

struct closure;

#include <trace/events/bcache.h>

#ifdef CONFIG_BCACHE_EDEBUG

#define atomic_dec_bug(v)	BUG_ON(atomic_dec_return(v) < 0)
#define atomic_inc_bug(v, i)	BUG_ON(atomic_inc_return(v) <= i)

#else /* EDEBUG */

#define atomic_dec_bug(v)	atomic_dec(v)
#define atomic_inc_bug(v, i)	atomic_inc(v)

#endif

#define BITMASK(name, type, field, offset, size)		\
static inline uint64_t name(const type *k)			\
{ return (k->field >> offset) & ~(((uint64_t) ~0) << size); }	\
								\
static inline void SET_##name(type *k, uint64_t v)		\
{								\
	k->field &= ~(~((uint64_t) ~0 << size) << offset);	\
	k->field |= v << offset;				\
}

#define DECLARE_HEAP(type, name)					\
	struct {							\
		size_t size, used;					\
		type *data;						\
	} name

#define init_heap(heap, _size, gfp)					\
({									\
	size_t _bytes;							\
	(heap)->used = 0;						\
	(heap)->size = (_size);						\
	_bytes = (heap)->size * sizeof(*(heap)->data);			\
	(heap)->data = NULL;						\
	if (_bytes < KMALLOC_MAX_SIZE)					\
		(heap)->data = kmalloc(_bytes, (gfp));			\
	if ((!(heap)->data) && ((gfp) & GFP_KERNEL))			\
		(heap)->data = vmalloc(_bytes);				\
	(heap)->data;							\
})

#define free_heap(heap)							\
do {									\
	if (is_vmalloc_addr((heap)->data))				\
		vfree((heap)->data);					\
	else								\
		kfree((heap)->data);					\
	(heap)->data = NULL;						\
} while (0)

#define heap_swap(h, i, j)	swap((h)->data[i], (h)->data[j])

#define heap_sift(h, i, cmp)						\
do {									\
	size_t _r, _j = i;						\
									\
	for (; _j * 2 + 1 < (h)->used; _j = _r) {			\
		_r = _j * 2 + 1;					\
		if (_r + 1 < (h)->used &&				\
		    cmp((h)->data[_r], (h)->data[_r + 1]))		\
			_r++;						\
									\
		if (cmp((h)->data[_r], (h)->data[_j]))			\
			break;						\
		heap_swap(h, _r, _j);					\
	}								\
} while (0)

#define heap_sift_down(h, i, cmp)					\
do {									\
	while (i) {							\
		size_t p = (i - 1) / 2;					\
		if (cmp((h)->data[i], (h)->data[p]))			\
			break;						\
		heap_swap(h, i, p);					\
		i = p;							\
	}								\
} while (0)

#define heap_add(h, d, cmp)						\
({									\
	bool _r = !heap_full(h);					\
	if (_r) {							\
		size_t _i = (h)->used++;				\
		(h)->data[_i] = d;					\
									\
		heap_sift_down(h, _i, cmp);				\
		heap_sift(h, _i, cmp);					\
	}								\
	_r;								\
})

#define heap_pop(h, d, cmp)						\
({									\
	bool _r = (h)->used;						\
	if (_r) {							\
		(d) = (h)->data[0];					\
		(h)->used--;						\
		heap_swap(h, 0, (h)->used);				\
		heap_sift(h, 0, cmp);					\
	}								\
	_r;								\
})

#define heap_peek(h)	((h)->size ? (h)->data[0] : NULL)

#define heap_full(h)	((h)->used == (h)->size)

#define DECLARE_FIFO(type, name)					\
	struct {							\
		size_t front, back, size, mask;				\
		type *data;						\
	} name

#define fifo_for_each(c, fifo)						\
	for (size_t _i = (fifo)->front;					\
	     c = (fifo)->data[_i], _i != (fifo)->back;			\
	     _i = (_i + 1) & (fifo)->mask)

#define __init_fifo(fifo, gfp)						\
({									\
	size_t _allocated_size, _bytes;					\
	BUG_ON(!(fifo)->size);						\
									\
	_allocated_size = roundup_pow_of_two((fifo)->size + 1);		\
	_bytes = _allocated_size * sizeof(*(fifo)->data);		\
									\
	(fifo)->mask = _allocated_size - 1;				\
	(fifo)->front = (fifo)->back = 0;				\
	(fifo)->data = NULL;						\
									\
	if (_bytes < KMALLOC_MAX_SIZE)					\
		(fifo)->data = kmalloc(_bytes, (gfp));			\
	if ((!(fifo)->data) && ((gfp) & GFP_KERNEL))			\
		(fifo)->data = vmalloc(_bytes);				\
	(fifo)->data;							\
})

#define init_fifo_exact(fifo, _size, gfp)				\
({									\
	(fifo)->size = (_size);						\
	__init_fifo(fifo, gfp);						\
})

#define init_fifo(fifo, _size, gfp)					\
({									\
	(fifo)->size = (_size);						\
	if ((fifo)->size > 4)						\
		(fifo)->size = roundup_pow_of_two((fifo)->size) - 1;	\
	__init_fifo(fifo, gfp);						\
})

#define free_fifo(fifo)							\
do {									\
	if (is_vmalloc_addr((fifo)->data))				\
		vfree((fifo)->data);					\
	else								\
		kfree((fifo)->data);					\
	(fifo)->data = NULL;						\
} while (0)

#define fifo_used(fifo)		(((fifo)->back - (fifo)->front) & (fifo)->mask)
#define fifo_free(fifo)		((fifo)->size - fifo_used(fifo))

#define fifo_empty(fifo)	(!fifo_used(fifo))
#define fifo_full(fifo)		(!fifo_free(fifo))

#define fifo_front(fifo)	((fifo)->data[(fifo)->front])
#define fifo_back(fifo)							\
	((fifo)->data[((fifo)->back - 1) & (fifo)->mask])

#define fifo_idx(fifo, p)	(((p) - &fifo_front(fifo)) & (fifo)->mask)

#define fifo_push_back(fifo, i)						\
({									\
	bool _r = !fifo_full((fifo));					\
	if (_r) {							\
		(fifo)->data[(fifo)->back++] = (i);			\
		(fifo)->back &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_pop_front(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r) {							\
		(i) = (fifo)->data[(fifo)->front++];			\
		(fifo)->front &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_push_front(fifo, i)					\
({									\
	bool _r = !fifo_full((fifo));					\
	if (_r) {							\
		--(fifo)->front;					\
		(fifo)->front &= (fifo)->mask;				\
		(fifo)->data[(fifo)->front] = (i);			\
	}								\
	_r;								\
})

#define fifo_pop_back(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r) {							\
		--(fifo)->back;						\
		(fifo)->back &= (fifo)->mask;				\
		(i) = (fifo)->data[(fifo)->back]			\
	}								\
	_r;								\
})

#define fifo_push(fifo, i)	fifo_push_back(fifo, (i))
#define fifo_pop(fifo, i)	fifo_pop_front(fifo, (i))

#define fifo_swap(l, r)							\
do {									\
	swap((l)->front, (r)->front);					\
	swap((l)->back, (r)->back);					\
	swap((l)->size, (r)->size);					\
	swap((l)->mask, (r)->mask);					\
	swap((l)->data, (r)->data);					\
} while (0)

#define fifo_move(dest, src)						\
do {									\
	typeof(*((dest)->data)) _t;					\
	while (!fifo_full(dest) &&					\
	       fifo_pop(src, _t))					\
		fifo_push(dest, _t);					\
} while (0)

#define ANYSINT_MAX(t)						\
	((((t) 1 << (sizeof(t) * 8 - 2)) - (t) 1) * (t) 2 + (t) 1)

int strtoint_h(const char *, int *);
int strtouint_h(const char *, unsigned int *);
int strtoll_h(const char *, long long *);
int strtoull_h(const char *, unsigned long long *);

static inline int strtol_h(const char *cp, long *res)
{
#if BITS_PER_LONG == 32
	return strtoint_h(cp, (int *) res);
#else
	return strtoll_h(cp, (long long *) res);
#endif
}

static inline int strtoul_h(const char *cp, long *res)
{
#if BITS_PER_LONG == 32
	return strtouint_h(cp, (unsigned int *) res);
#else
	return strtoull_h(cp, (unsigned long long *) res);
#endif
}

#define strtoi_h(cp, res)						\
	(__builtin_types_compatible_p(typeof(*res), int)		\
	? strtoint_h(cp, (void *) res)					\
	:__builtin_types_compatible_p(typeof(*res), long)		\
	? strtol_h(cp, (void *) res)					\
	: __builtin_types_compatible_p(typeof(*res), long long)		\
	? strtoll_h(cp, (void *) res)					\
	: __builtin_types_compatible_p(typeof(*res), unsigned int)	\
	? strtouint_h(cp, (void *) res)					\
	: __builtin_types_compatible_p(typeof(*res), unsigned long)	\
	? strtoul_h(cp, (void *) res)					\
	: __builtin_types_compatible_p(typeof(*res), unsigned long long)\
	? strtoull_h(cp, (void *) res) : -EINVAL)

#define strtoul_safe(cp, var)						\
({									\
	unsigned long _v;						\
	int _r = strict_strtoul(cp, 10, &_v);				\
	if (!_r)							\
		var = _v;						\
	_r;								\
})

#define strtoul_safe_clamp(cp, var, min, max)				\
({									\
	unsigned long _v;						\
	int _r = strict_strtoul(cp, 10, &_v);				\
	if (!_r)							\
		var = clamp_t(typeof(var), _v, min, max);		\
	_r;								\
})

#define snprint(buf, size, var)						\
	snprintf(buf, size,						\
		__builtin_types_compatible_p(typeof(var), int)		\
		     ? "%i\n" :						\
		__builtin_types_compatible_p(typeof(var), unsigned)	\
		     ? "%u\n" :						\
		__builtin_types_compatible_p(typeof(var), long)		\
		     ? "%li\n" :					\
		__builtin_types_compatible_p(typeof(var), unsigned long)\
		     ? "%lu\n" :					\
		__builtin_types_compatible_p(typeof(var), int64_t)	\
		     ? "%lli\n" :					\
		__builtin_types_compatible_p(typeof(var), uint64_t)	\
		     ? "%llu\n" :					\
		__builtin_types_compatible_p(typeof(var), const char *)	\
		     ? "%s\n" : "%i\n", var)

ssize_t hprint(char *buf, int64_t v);

#define sysfs_attribute(_name, _mode)					\
	static struct attribute sysfs_##_name =				\
		{ .name = #_name, .mode = _mode }

#define write_attribute(n)	sysfs_attribute(n, S_IWUSR)
#define read_attribute(n)	sysfs_attribute(n, S_IRUGO)
#define rw_attribute(n)		sysfs_attribute(n, S_IRUGO|S_IWUSR)

#define sysfs_printf(file, fmt, ...)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		return snprintf(buf, PAGE_SIZE, fmt "\n", __VA_ARGS__);	\
} while (0)

#define sysfs_print(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		return snprint(buf, PAGE_SIZE, var);			\
} while (0)

#define sysfs_hprint(file, val)						\
do {									\
	if (attr == &sysfs_ ## file) {					\
		ssize_t ret = hprint(buf, val);				\
		strcat(buf, "\n");					\
		return ret + 1;						\
	}								\
} while (0)

#define var_printf(_var, fmt)	sysfs_printf(_var, fmt, var(_var))
#define var_print(_var)		sysfs_print(_var, var(_var))
#define var_hprint(_var)	sysfs_hprint(_var, var(_var))

#define sysfs_strtoul(file, var)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe(buf, var) ?: (ssize_t) size;	\
} while (0)

#define sysfs_strtoul_clamp(file, var, min, max)			\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe_clamp(buf, var, min, max)		\
			?: (ssize_t) size;				\
} while (0)

#define strtoul_or_return(cp)						\
({									\
	unsigned long _v;						\
	int _r = strict_strtoul(cp, 10, &_v);				\
	if (_r)								\
		return _r;						\
	_v;								\
})

#define strtoi_h_or_return(cp, v)					\
do {									\
	int _r = strtoi_h(cp, &v);					\
	if (_r)								\
		return _r;						\
} while (0)

#define sysfs_hatoi(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		strtoi_h_or_return(buf, var);				\
} while (0)

bool is_zero(const char *p, size_t n);
int parse_uuid(const char *s, char *uuid);

ssize_t sprint_string_list(char *buf, const char * const list[],
			   size_t selected);

ssize_t read_string_list(const char *buf, const char * const list[]);

struct time_stats {
	/*
	 * all fields are in nanoseconds, averages are ewmas stored left shifted
	 * by 8
	 */
	uint64_t	max_duration;
	uint64_t	average_duration;
	uint64_t	average_frequency;
	uint64_t	last;
};

void time_stats_update(struct time_stats *stats, uint64_t time);

static const uint64_t __time_ns		= 1;
static const uint64_t __time_us		= NSEC_PER_USEC;
static const uint64_t __time_ms		= NSEC_PER_MSEC;
static const uint64_t __time_sec	= NSEC_PER_SEC;

#define sysfs_print_time_stats(stats, name,				\
			       frequency_units,				\
			       duration_units)				\
do {									\
	sysfs_print(name ## _average_frequency_ ## frequency_units,	\
		    ((stats)->average_frequency >> 8) /			\
		     __time_ ## frequency_units);			\
	sysfs_print(name ## _average_duration_ ## duration_units,	\
		    ((stats)->average_duration >> 8) /			\
		    __time_ ## duration_units);				\
	sysfs_print(name ## _max_duration_ ## duration_units,		\
		    ((stats)->max_duration) /				\
		    __time_ ## duration_units);				\
	sysfs_print(name ## _last_ ## frequency_units,			\
		    !(stats)->last ? -1LL				\
		    : (int64_t) ((local_clock() - (stats)->last) /	\
				 __time_ ## frequency_units));		\
} while (0)

#define sysfs_time_stats_attribute(name,				\
				   frequency_units,			\
				   duration_units)			\
read_attribute(name ## _average_frequency_ ## frequency_units);		\
read_attribute(name ## _average_duration_ ## duration_units);		\
read_attribute(name ## _max_duration_ ## duration_units);		\
read_attribute(name ## _last_ ## frequency_units)

#define sysfs_time_stats_attribute_list(name,				\
					frequency_units,		\
					duration_units)			\
&sysfs_ ## name ## _average_frequency_ ## frequency_units,		\
&sysfs_ ## name ## _average_duration_ ## duration_units,		\
&sysfs_ ## name ## _max_duration_ ## duration_units,			\
&sysfs_ ## name ## _last_ ## frequency_units,

#define ewma_add(ewma, val, weight, factor)				\
({									\
	(ewma) *= (weight) - 1;						\
	(ewma) += (val) << factor;					\
	(ewma) /= (weight);						\
	(ewma) >> factor;						\
})

#define __DIV_SAFE(n, d, zero)						\
({									\
	typeof(n) _n = (n);						\
	typeof(d) _d = (d);						\
	_d ? _n / _d : zero;						\
})

#define DIV_SAFE(n, d)	__DIV_SAFE(n, d, 0)

#define container_of_or_null(ptr, type, member)				\
({									\
	typeof(ptr) _ptr = ptr;						\
	_ptr ? container_of(_ptr, type, member) : NULL;			\
})

#define RB_INSERT(root, new, member, cmp)				\
({									\
	__label__ dup;							\
	struct rb_node **n = &(root)->rb_node, *parent = NULL;		\
	typeof(new) this;						\
	int res, ret = -1;						\
									\
	while (*n) {							\
		parent = *n;						\
		this = container_of(*n, typeof(*(new)), member);	\
		res = cmp(new, this);					\
		if (!res)						\
			goto dup;					\
		n = res < 0						\
			? &(*n)->rb_left				\
			: &(*n)->rb_right;				\
	}								\
									\
	rb_link_node(&(new)->member, parent, n);			\
	rb_insert_color(&(new)->member, root);				\
	ret = 0;							\
dup:									\
	ret;								\
})

#define RB_SEARCH(root, search, member, cmp)				\
({									\
	struct rb_node *n = (root)->rb_node;				\
	typeof(&(search)) this, ret = NULL;				\
	int res;							\
									\
	while (n) {							\
		this = container_of(n, typeof(search), member);		\
		res = cmp(&(search), this);				\
		if (!res) {						\
			ret = this;					\
			break;						\
		}							\
		n = res < 0						\
			? n->rb_left					\
			: n->rb_right;					\
	}								\
	ret;								\
})

#define RB_GREATER(root, search, member, cmp)				\
({									\
	struct rb_node *n = (root)->rb_node;				\
	typeof(&(search)) this, ret = NULL;				\
	int res;							\
									\
	while (n) {							\
		this = container_of(n, typeof(search), member);		\
		res = cmp(&(search), this);				\
		if (res < 0) {						\
			ret = this;					\
			n = n->rb_left;					\
		} else							\
			n = n->rb_right;				\
	}								\
	ret;								\
})

#define RB_FIRST(root, type, member)					\
	container_of_or_null(rb_first(root), type, member)

#define RB_LAST(root, type, member)					\
	container_of_or_null(rb_last(root), type, member)

#define RB_NEXT(ptr, member)						\
	container_of_or_null(rb_next(&(ptr)->member), typeof(*ptr), member)

#define RB_PREV(ptr, member)						\
	container_of_or_null(rb_prev(&(ptr)->member), typeof(*ptr), member)

/* Does linear interpolation between powers of two */
static inline unsigned fract_exp_two(unsigned x, unsigned fract_bits)
{
	unsigned fract = x & ~(~0 << fract_bits);

	x >>= fract_bits;
	x   = 1 << x;
	x  += (x * fract) >> fract_bits;

	return x;
}

#define bio_end(bio)	((bio)->bi_sector + bio_sectors(bio))

void bio_reset(struct bio *bio);
void bio_map(struct bio *bio, void *base);

typedef struct bio *(bio_alloc_fn)(gfp_t, int);

struct bio *bio_split_front(struct bio *, int, bio_alloc_fn *,
			    gfp_t, struct bio_set *);

int bio_submit_split(struct bio *bio, atomic_t *i, struct bio_set *bs);
unsigned __bio_max_sectors(struct bio *bio, struct block_device *bdev,
			   sector_t sector);

int bio_alloc_pages(struct bio *bio, gfp_t gfp);

#define bio_alloc_pages(...)						\
	(dynamic_fault() ? -ENOMEM	: bio_alloc_pages(__VA_ARGS__))

static inline unsigned bio_max_sectors(struct bio *bio)
{
	return __bio_max_sectors(bio, bio->bi_bdev, bio->bi_sector);
}

static inline sector_t bdev_sectors(struct block_device *bdev)
{
	return bdev->bd_inode->i_size >> 9;
}

#ifdef CONFIG_BCACHE_LATENCY_DEBUG
extern unsigned latency_warn_ms;

#define latency_ms(j)		jiffies_to_msecs(jiffies - (j))

#define pr_latency(j, fmt, ...)						\
do {									\
	int _ms = latency_ms(j);					\
	if (j && latency_warn_ms && (_ms) > (int) latency_warn_ms)	\
		printk_ratelimited(KERN_DEBUG "bcache: %i ms latency "	\
			"called from %pf for " fmt "\n", _ms,		\
		       __builtin_return_address(0), ##__VA_ARGS__);	\
} while (0)

#define set_wait(f)	((f)->wait_time = jiffies)

#else
#define latency_ms(j)	(0)
#define pr_latency(...) do {} while (0)
#define set_wait(j)	do {} while (0)
#endif

#define closure_bio_submit(bio, c, bs)					\
	bio_submit_split(bio, &(c)->remaining, bs)

uint64_t crc64_update(uint64_t, const void *, size_t);
uint64_t crc64(const void *, size_t);

unsigned popcount_64(uint64_t);
unsigned popcount_32(uint32_t);

#endif /* _BCACHE_UTIL_H */
