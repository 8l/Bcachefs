
#ifndef _BCACHE_UTIL_H
#define _BCACHE_UTIL_H

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/ratelimit.h>
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

#define DEFINE_HEAP(type, name, s)					\
	struct {							\
		size_t size;						\
		const size_t used;					\
		type data[s];						\
	} name = { .used = 0, .size = s }

#define init_heap(h, s, gfp)						\
({									\
	(h)->used = 0;							\
	(h)->size = s;							\
	if ((h)->size * sizeof(*(h)->data) >= KMALLOC_MAX_SIZE)		\
		(h)->data = vmalloc((h)->size * sizeof(*(h)->data));	\
	else if ((h)->size > 0)						\
		(h)->data = kmalloc((h)->size * sizeof(*(h)->data), gfp);\
	(h)->data;							\
})

#define free_heap(h)							\
do {									\
	if ((h)->size * sizeof(*(h)->data) >= KMALLOC_MAX_SIZE)		\
		vfree((h)->data);					\
	else								\
		kfree((h)->data);					\
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
	size_t _bytes;							\
	BUG_ON(!(fifo)->size);						\
	(fifo)->front = (fifo)->back = 0;				\
	(fifo)->mask = roundup_pow_of_two((fifo)->size + 1);		\
	_bytes = (fifo)->mask * sizeof(*(fifo)->data);			\
	(fifo)->mask--;							\
	(fifo)->data = (_bytes >= KMALLOC_MAX_SIZE)			\
		? vmalloc(_bytes)					\
		: kmalloc(_bytes, gfp);					\
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
	(fifo)->mask++;							\
	if ((fifo)->mask * sizeof(*(fifo)->data) >= KMALLOC_MAX_SIZE)	\
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

#define fifo_push(fifo, i)						\
({									\
	bool _r = !fifo_full(fifo);					\
	if (_r) {							\
		(fifo)->data[(fifo)->back++] = i;			\
		(fifo)->back &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_pop(fifo, i)						\
({									\
	bool _r = !fifo_empty(fifo);					\
	if (_r) {							\
		i = (fifo)->data[(fifo)->front++];			\
		(fifo)->front &= (fifo)->mask;				\
	}								\
	_r;								\
})

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

int strtol_h(const char *, long *);
int strtoll_h(const char *, long long *);
int strtoul_h(const char *, unsigned long *);
int strtoull_h(const char *, unsigned long long *);

#define strtoi_h(cp, res)						\
	(__builtin_types_compatible_p(typeof(*res), long)		\
	? strtol_h(cp, (void *) res)					\
	: __builtin_types_compatible_p(typeof(*res), long long)		\
	? strtoll_h(cp, (void *) res)					\
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
bool is_zero(const char *p, size_t n);
int parse_uuid(const char *s, char *uuid);

ssize_t sprint_string_list(char *buf, const char * const list[],
			   size_t selected);

ssize_t read_string_list(const char *buf, const char * const list[]);

#define __DIV_SAFE(n, d, zero)						\
({									\
	typeof(n) _n = (n);						\
	typeof(d) _d = (d);						\
	_d ? _n / _d : zero;						\
})

#define DIV_SAFE(n, d)	__DIV_SAFE(n, d, 0)

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
	(root ? container_of(rb_first(root), type, member) : NULL)

#define RB_LAST(root, type, member)					\
	(root ? container_of(rb_last(root), type, member) : NULL)

#define RB_PREV(node, type, member)					\
	(rb_prev(node) ? container_of(rb_prev(node), type, member) : NULL)

#define RB_NEXT(node, type, member)					\
	(rb_next(node) ? container_of(rb_next(node), type, member) : NULL)

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

static inline unsigned bio_max_sectors(struct bio *bio)
{
	return __bio_max_sectors(bio, bio->bi_bdev, bio->bi_sector);
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

typedef void (closure_fn) (struct closure *);

typedef struct {
	struct closure *head;
} closure_list_t;

struct closure {
	union {
		struct {
			struct workqueue_struct *wq;
			struct task_struct	*task;
			struct closure		*next;
			closure_fn		*fn;
		};
		struct work_struct	work;
	};

	struct closure		*parent;

#define CLOSURE_REMAINING_MASK	(~(~0 << 24))
#define CLOSURE_GUARD_MASK					\
	((1 << 23)|(1 << 25)|(1 << 27)|(1 << 29)|(1 << 31))

#define	CLOSURE_BLOCKING	(1 << 24)
#define CLOSURE_STACK		(1 << 26)
#define	CLOSURE_WAITING		(1 << 28)
#define	CLOSURE_SLEEPING	(1 << 30)
	atomic_t		remaining;

#ifdef CONFIG_BCACHE_CLOSURE_DEBUG
	struct list_head	all;
	unsigned long		waiting_on;
#endif
#ifdef CONFIG_BCACHE_LATENCY_DEBUG
	unsigned long		wait_time;
#endif
};

void closure_put(struct closure *cl);
void closure_queue(struct closure *cl);
void closure_init(struct closure *cl, struct closure *parent);
void __closure_wake_up(closure_list_t *list);
bool closure_wait(closure_list_t *list, struct closure *cl);
void closure_sync(struct closure *cl);

#ifdef CONFIG_BCACHE_CLOSURE_DEBUG
extern struct list_head closures;
extern spinlock_t closure_lock;

static inline void closure_del(struct closure *cl)
{
	unsigned long flags;
	spin_lock_irqsave(&closure_lock, flags);
	list_del(&cl->all);
	spin_unlock_irqrestore(&closure_lock, flags);
}

#else
static inline void closure_del(struct closure *cl) {}
#endif

static inline void closure_init_stack(struct closure *cl)
{
	memset(cl, 0, sizeof(struct closure));
	atomic_set(&cl->remaining, 1|CLOSURE_BLOCKING|CLOSURE_STACK);
	set_wait(cl);
}

static inline void closure_get(struct closure *cl)
{
	atomic_inc_bug(&cl->remaining, 1);
}

static inline void __closure_end_sleep(struct closure *cl)
{
	__set_current_state(TASK_RUNNING);

	if (atomic_read(&cl->remaining) & CLOSURE_SLEEPING)
		atomic_sub(CLOSURE_SLEEPING, &cl->remaining);
}

static inline void __closure_start_sleep(struct closure *cl)
{
	cl->task = current;
	set_current_state(TASK_UNINTERRUPTIBLE);

	if (!(atomic_read(&cl->remaining) & CLOSURE_SLEEPING))
		atomic_add(CLOSURE_SLEEPING, &cl->remaining);
}

static inline bool closure_blocking(struct closure *cl)
{
	return atomic_read(&cl->remaining) & CLOSURE_BLOCKING;
}

static inline void set_closure_blocking(struct closure *cl)
{
	if (!closure_blocking(cl))
		atomic_add(CLOSURE_BLOCKING, &cl->remaining);
}

static inline void closure_wake_up(closure_list_t *list)
{
	smp_mb();
	__closure_wake_up(list);
}

/*
 * Wait on an event, synchronously or asynchronously - analagous to wait_event()
 * but for closures.
 *
 * The loop is oddly structured so as to avoid a race; we must check the
 * condition again after we've added ourself to the waitlist. We know if we were
 * already on the waitlist because closure_wait() returns false; thus, we only
 * schedule or break if closure_wait() returns false. If it returns true, we
 * just loop again - rechecking the condition.
 *
 * The __closure_wake_up() is necessary because we may race with the event
 * becoming true; i.e. we see event false -> wait -> recheck condition, but the
 * thread that made the event true may have called closure_wake_up() before we
 * added ourself to the wait list.
 */
#define __closure_wait_event(list, cl, condition, _block)		\
({									\
	__label__ out;							\
	bool block = _block;						\
	typeof(condition) ret;						\
									\
	while (!(ret = (condition))) {					\
		if (block)						\
			__closure_start_sleep(cl);			\
		if (!closure_wait(list, cl)) {				\
			if (!block)					\
				goto out;				\
			schedule();					\
		}							\
	}								\
	__closure_wake_up(list);					\
	if (block)							\
		__closure_end_sleep(cl);				\
out:									\
	ret;								\
})

#define closure_wait_event(list, cl, condition)				\
	__closure_wait_event(list, cl, condition, closure_blocking(cl))

#define closure_wait_event_async(list, cl, condition)			\
	__closure_wait_event(list, cl, condition, false)

static inline void set_closure_fn(struct closure *cl, closure_fn *fn,
				  struct workqueue_struct *wq)
{
	cl->fn = fn;
	cl->wq = wq;
	/* between atomic_dec() in closure_put() */
	smp_mb__before_atomic_dec();
}

#define return_f(_cl, _fn, _wq, ...)					\
do {									\
	BUG_ON(!(_cl) || object_is_on_stack(_cl));			\
	set_closure_fn(_cl, _fn, _wq);					\
	closure_put(_cl);						\
	return __VA_ARGS__;						\
} while (0)

#define closure_bio_submit(bio, c, bs)					\
	bio_submit_split(bio, &(c)->remaining, bs)

uint64_t crc64_update(uint64_t, const void *, size_t);
uint64_t crc64(const void *, size_t);

unsigned popcount_64(uint64_t);
unsigned popcount_32(uint32_t);

#endif /* _BCACHE_UTIL_H */
