#ifndef _LINUX_CLOSURE_H
#define _LINUX_CLOSURE_H

#include <linux/llist.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

/*
 * Closure is perhaps the most overused and abused term in computer science, but
 * since I've been unable to come up with anything better you're stuck with it
 * again.
 *
 * What are closures?
 *
 * They embed a refcount. The basic idea is they count "things that are in
 * progress" - in flight bios, some other thread that's doing something else -
 * anything you might want to wait on.
 *
 * The refcount may be manipulated with closure_get() and closure_put().
 * closure_put() is where many of the interesting things happen, when it causes
 * the refcount to go to 0.
 *
 * Closures can be used to wait on things both synchronously and asynchronously,
 * and synchronous and asynchronous use can be mixed without restriction. To
 * wait synchronously, use closure_sync() - you will sleep until your closure's
 * refcount hits 1.
 *
 * To wait asynchronously, use
 *   continue_at(cl, next_function, workqueue);
 *
 * passing it, as you might expect, the function to run when nothing is pending
 * and the workqueue to run that function out of.
 *
 * continue_at() also, critically, is a macro that returns the calling function.
 * There's good reason for this.
 *
 * To use safely closures asynchronously, they must always have a refcount while
 * they are running owned by the thread that is running them. Otherwise, suppose
 * you submit some bios and wish to have a function run when they all complete:
 *
 * foo_endio(struct bio *bio, int error)
 * {
 *	closure_put(cl);
 * }
 *
 * closure_init(cl);
 *
 * do_stuff();
 * closure_get(cl);
 * bio1->bi_endio = foo_endio;
 * bio_submit(bio1);
 *
 * do_more_stuff();
 * closure_get(cl);
 * bio2->bi_endio = foo_endio;
 * bio_submit(bio2);
 *
 * continue_at(cl, complete_some_read, system_wq);
 *
 * If closure's refcount started at 0, complete_some_read() could run before the
 * second bio was submitted - which is almost always not what you want! More
 * importantly, it wouldn't be possible to say whether the original thread or
 * complete_some_read()'s thread owned the closure - and whatever state it was
 * associated with!
 *
 * So, closure_init() initializes a closure's refcount to 1 - and when a
 * closure_fn is run, the refcount will be reset to 1 first.
 *
 * Then, the rule is - if you got the refcount with closure_get(), release it
 * with closure_put() (i.e, in a bio->bi_endio function). If you have a refcount
 * on a closure because you called closure_init() or you were run out of a
 * closure - _always_ use continue_at(). Doing so consistently will help
 * eliminate an entire class of particularly pernicious races.
 *
 * For a closure to wait on an arbitrary event, we need to introduce waitlists:
 *
 * struct closure_waitlist list;
 * closure_wait_event(list, cl, condition);
 * closure_wake_up(wait_list);
 *
 * These work analagously to wait_event() and wake_up() - except that instead of
 * operating on the current thread (for wait_event()) and lists of threads, they
 * operate on an explicit closure and lists of closures.
 *
 * Because it's a closure we can now wait either synchronously or
 * asynchronously. closure_wait_event() returns the current value of the
 * condition, and if it returned false continue_at() or closure_sync() can be
 * used to wait for it to become true.
 *
 * It's useful for waiting on things when you can't sleep in the context in
 * which you must check the condition (perhaps a spinlock held, or you might be
 * beneath generic_make_request() - in which case you can't sleep on IO).
 *
 * closure_wait_event() will wait either synchronously or asynchronously,
 * depending on whether the closure is in blocking mode or not. You can pick a
 * mode explicitly with closure_wait_event_sync() and
 * closure_wait_event_async(), which do just what you might expect.
 *
 * Lastly, you might have a wait list dedicated to a specific event, and have no
 * need for specifying the condition - you just want to wait until someone runs
 * closure_wake_up() on the appropriate wait list. In that case, just use
 * closure_wait(). It will return either true or false, depending on whether the
 * closure was already on a wait list or not - a closure can only be on one wait
 * list at a time.
 *
 * Parents:
 *
 * closure_init() takes two arguments - it takes the closure to initialize, and
 * a (possibly null) parent.
 *
 * If parent is non null, the new closure will have a refcount for its lifetime;
 * a closure is considered to be "finished" when its refcount hits 0 and the
 * function to run is null. Hence
 *
 * continue_at(cl, NULL, NULL);
 *
 * returns up the (spaghetti) stack of closures, precisely like normal return
 * returns up the C stack. continue_at() with non null fn is better thought of
 * as doing a tail call.
 *
 * All this implies that a closure should typically be embedded in a particular
 * struct (which its refcount will normally control the lifetime of), and that
 * struct can very much be thought of as a stack frame.
 */

struct closure;
typedef void (closure_fn) (struct closure *);

struct closure_waitlist {
	struct llist_head	list;
};

enum closure_state {
	/*
	 * CLOSURE_WAITING: Set iff the closure is on a waitlist. Must be set by
	 * the thread that owns the closure, and cleared by the thread that's
	 * waking up the closure.
	 *
	 * CLOSURE_SLEEPING: Must be set before a thread uses a closure to sleep
	 * - indicates that cl->task is valid and closure_put() may wake it up.
	 * Only set or cleared by the thread that owns the closure.
	 *
	 * The rest are for debugging and don't affect behaviour:
	 *
	 * CLOSURE_RUNNING: Set when a closure is running (i.e. by
	 * closure_init() and when closure_put() runs then next function), and
	 * must be cleared before remaining hits 0. Primarily to help guard
	 * against incorrect usage and accidentally transferring references.
	 * continue_at() and closure_return() clear it for you, if you're doing
	 * something unusual you can use closure_set_dead() which also helps
	 * annotate where references are being transferred.
	 *
	 * CLOSURE_STACK: Sanity check - remaining should never hit 0 on a
	 * closure with this flag set
	 */

	CLOSURE_BITS_START	= (1 << 25),
	CLOSURE_WAITING		= (1 << 25),
	CLOSURE_SLEEPING	= (1 << 27),
	CLOSURE_RUNNING		= (1 << 29),
	CLOSURE_STACK		= (1 << 31),
};

#define CLOSURE_GUARD_MASK					\
	((CLOSURE_WAITING|CLOSURE_SLEEPING|			\
	  CLOSURE_RUNNING|CLOSURE_STACK) << 1)

#define CLOSURE_REMAINING_MASK		(CLOSURE_BITS_START - 1)
#define CLOSURE_REMAINING_INITIALIZER	(1|CLOSURE_RUNNING)

struct closure {
	union {
		struct {
			struct workqueue_struct *wq;
			struct task_struct	*task;
			struct llist_node	list;
			closure_fn		*fn;
		};
		struct work_struct	work;
	};

	struct closure		*parent;

	atomic_t		remaining;

#ifdef CONFIG_DEBUG_CLOSURES
#define CLOSURE_MAGIC_DEAD	0xc054dead
#define CLOSURE_MAGIC_ALIVE	0xc054a11e

	unsigned		magic;
	struct list_head	all;
	unsigned long		ip;
	unsigned long		waiting_on;
#endif
};

void closure_sub(struct closure *cl, int v);
void closure_put(struct closure *cl);
void closure_queue(struct closure *cl);
void __closure_wake_up(struct closure_waitlist *list);
bool closure_wait(struct closure_waitlist *list, struct closure *cl);
void closure_sync(struct closure *cl);

#ifdef CONFIG_DEBUG_CLOSURES

void closure_debug_create(struct closure *cl);
void closure_debug_destroy(struct closure *cl);

#else

static inline void closure_debug_create(struct closure *cl) {}
static inline void closure_debug_destroy(struct closure *cl) {}

#endif

static inline void closure_set_ip(struct closure *cl)
{
#ifdef CONFIG_DEBUG_CLOSURES
	cl->ip = _THIS_IP_;
#endif
}

static inline void closure_set_ret_ip(struct closure *cl)
{
#ifdef CONFIG_DEBUG_CLOSURES
	cl->ip = _RET_IP_;
#endif
}

static inline void closure_get(struct closure *cl)
{
#ifdef CONFIG_DEBUG_CLOSURES
	BUG_ON((atomic_inc_return(&cl->remaining) &
		CLOSURE_REMAINING_MASK) <= 1);
#else
	atomic_inc(&cl->remaining);
#endif
}

static inline void closure_set_stopped(struct closure *cl)
{
	atomic_sub(CLOSURE_RUNNING, &cl->remaining);
}

static inline bool closure_is_stopped(struct closure *cl)
{
	return !(atomic_read(&cl->remaining) & CLOSURE_RUNNING);
}

static inline void __closure_init(struct closure *cl, struct closure *parent)
{
	cl->parent = parent;
	if (parent)
		closure_get(parent);

	closure_debug_create(cl);
	atomic_set(&cl->remaining, CLOSURE_REMAINING_INITIALIZER);

	closure_set_ip(cl);
}

/**
 * closure_init() - Initialize a closure, setting the refcount to 1
 * @cl:		closure to initialize
 * @parent:	parent of the new closure. cl will take a refcount on it for its
 *		lifetime; may be NULL.
 */
#define closure_init(cl, parent)				\
do {								\
	memset((cl), 0, sizeof(*(cl)));				\
	__closure_init(cl, parent);				\
} while (0)

static inline void closure_init_stack(struct closure *cl)
{
	memset(cl, 0, sizeof(struct closure));
	atomic_set(&cl->remaining, CLOSURE_REMAINING_INITIALIZER|CLOSURE_STACK);
}

static inline void __closure_end_sleep(struct closure *cl)
{
	__set_current_state(TASK_RUNNING);

	if (atomic_read(&cl->remaining) & CLOSURE_SLEEPING)
		atomic_sub(CLOSURE_SLEEPING, &cl->remaining);
}

static inline void __closure_start_sleep(struct closure *cl)
{
	closure_set_ip(cl);
	cl->task = current;
	set_current_state(TASK_UNINTERRUPTIBLE);

	if (!(atomic_read(&cl->remaining) & CLOSURE_SLEEPING))
		atomic_add(CLOSURE_SLEEPING, &cl->remaining);
}

/**
 * closure_wake_up() - wake up all closures on a wait list.
 */
static inline void closure_wake_up(struct closure_waitlist *list)
{
	smp_mb();
	__closure_wake_up(list);
}

/**
 * closure_wait_event() - Asynchronous wait_event()
 * @list:	the wait list to wait on
 * @cl:		the closure that is doing the waiting
 * @condition:	a C expression for the event to wait for
 *
 *
 * If the condition is currently false the @cl is put onto @list and returns.
 * @list owns a refcount on @cl; closure_sync() or continue_at() may be used
 * later to wait for another thread to wake up @list, which drops the refcount
 * on @cl.
 *
 * Returns the value of @condition; @cl will be on @list iff @condition was
 * false.
 *
 * closure_wake_up(@list) must be called after changing any variable that could
 * cause @condition to become true.
 */
#define closure_wait_event_async(list, cl, condition)			\
({									\
	typeof(condition) ret;						\
									\
	while (1) {							\
		ret = (condition);					\
		if (ret) {						\
			__closure_wake_up(list);			\
			break;						\
		}							\
									\
		if (!closure_wait(list, cl))				\
			break;						\
	}								\
									\
	ret;								\
})

/**
 * closure_wait_event_sync() - wait on a condition
 * @list:	the wait list to wait on
 * @cl:		the closure that is doing the waiting
 * @condition:	a C expression for the event to wait for
 *
 * Sleeps until @condition is true, exactly like wait_event()
 *
 * closure_wake_up(@list) must be called after changing any variable that could
 * cause @condition to become true.
 */
#define closure_wait_event_sync(list, cl, condition)			\
do {									\
	while (!(condition)) {						\
		__closure_start_sleep(cl);				\
									\
		if (!closure_wait(list, cl))				\
			schedule();					\
	}								\
									\
	__closure_wake_up(list);					\
	closure_sync(cl);						\
} while (0)

static inline void set_closure_fn(struct closure *cl, closure_fn *fn,
				  struct workqueue_struct *wq)
{
	BUG_ON(object_is_on_stack(cl));
	closure_set_ip(cl);
	cl->fn = fn;
	cl->wq = wq;
	/* between atomic_dec() in closure_put() */
	smp_mb__before_atomic_dec();
}

#define continue_at(_cl, _fn, _wq)					\
do {									\
	set_closure_fn(_cl, _fn, _wq);					\
	closure_sub(_cl, CLOSURE_RUNNING + 1);				\
	return;								\
} while (0)

#define closure_return(_cl)	continue_at((_cl), NULL, NULL)

#define continue_at_nobarrier(_cl, _fn, _wq)				\
do {									\
	set_closure_fn(_cl, _fn, _wq);					\
	closure_queue(cl);						\
	return;								\
} while (0)

static inline void closure_call(closure_fn fn, struct closure *cl,
				struct closure *parent)
{
	closure_init(cl, parent);
	fn(cl);
}

#endif /* _LINUX_CLOSURE_H */
