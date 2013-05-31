/*
 * Dynamic percpu refcounts:
 * (C) 2012 Google, Inc.
 * Author: Kent Overstreet <koverstreet@google.com>
 *
 * This implements a refcount with similar semantics to atomic_t - atomic_inc(),
 * atomic_dec_and_test() - but potentially percpu.
 *
 * There's one important difference between percpu refs and normal atomic_t
 * refcounts; you have to keep track of your initial refcount, and then when you
 * start shutting down you call percpu_ref_kill() _before_ dropping the initial
 * refcount.
 *
 * The refcount will have a range of 0 to ((1U << 31) - 1), i.e. one bit less
 * than an atomic_t - this is because of the way shutdown works, see
 * percpu_ref_kill()/PCPU_COUNT_BIAS.
 *
 * Before you call percpu_ref_kill(), percpu_ref_put() does not check for the
 * refcount hitting 0 - it can't, if it was in percpu mode. percpu_ref_kill()
 * puts the ref back in single atomic_t mode, collecting the per cpu refs and
 * issuing the appropriate barriers, and then marks the ref as shutting down so
 * that percpu_ref_put() will check for the ref hitting 0.  After it returns,
 * it's safe to drop the initial ref.
 *
 * BACKGROUND:
 *
 * Percpu refcounts are quite useful for performance, but if we blindly
 * converted all refcounts to percpu counters we'd waste quite a bit of memory.
 *
 * Think about all the refcounts embedded in kobjects, files, etc. most of which
 * aren't used much. These start out as simple atomic counters - a little bigger
 * than a bare atomic_t, 16 bytes instead of 4 - but if we exceed some arbitrary
 * number of gets in one second, we then switch to percpu counters.
 *
 * This heuristic isn't perfect because it'll fire if the refcount was only
 * being used on one cpu; ideally we'd be able to count the number of cache
 * misses on percpu_ref_get() or something similar, but that'd make the non
 * percpu path significantly heavier/more complex. We can count the number of
 * gets() without any extra atomic instructions on arches that support
 * atomic64_t - simply by changing the atomic_inc() to atomic_add_return().
 *
 * USAGE:
 *
 * See fs/aio.c for some example usage; it's used there for struct kioctx, which
 * is created when userspaces calls io_setup(), and destroyed when userspace
 * calls io_destroy() or the process exits.
 *
 * In the aio code, kill_ioctx() is called when we wish to destroy a kioctx; it
 * calls percpu_ref_kill(), then hlist_del_rcu() and sychronize_rcu() to remove
 * the kioctx from the proccess's list of kioctxs - after that, there can't be
 * any new users of the kioctx (from lookup_ioctx()) and it's then safe to drop
 * the initial ref with percpu_ref_put().
 *
 * Code that does a two stage shutdown like this often needs some kind of
 * explicit synchronization to ensure the initial refcount can only be dropped
 * once - percpu_ref_kill() does this for you, it returns true once and false if
 * someone else already called it. The aio code uses it this way, but it's not
 * necessary if the code has some other mechanism to synchronize teardown.
 * around.
 */

#ifndef _LINUX_PERCPU_REFCOUNT_H
#define _LINUX_PERCPU_REFCOUNT_H

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>

struct percpu_ref;
typedef void (percpu_ref_release)(struct percpu_ref *);

struct percpu_ref {
	atomic64_t		count;
	/*
	 * The low bit of the pointer indicates whether the ref is in percpu
	 * mode; if set, then get/put will manipulate the atomic_t (this is a
	 * hack because we need to keep the pointer around for
	 * percpu_ref_kill_rcu())
	 */
	unsigned __percpu	*pcpu_count;
	percpu_ref_release	*release;
	struct rcu_head		rcu;
};

void percpu_ref_init(struct percpu_ref *, percpu_ref_release *);
void percpu_ref_kill(struct percpu_ref *ref);
unsigned percpu_ref_count(struct percpu_ref *ref);
void __percpu_ref_get(struct percpu_ref *ref, unsigned __percpu *pcpu_count);

#define PCPU_STATUS_BITS	2
#define PCPU_STATUS_MASK	((1 << PCPU_STATUS_BITS) - 1)

#define PCPU_REF_PTR		0
#define PCPU_REF_NONE		1
#define PCPU_REF_DEAD		3

#define REF_STATUS(count)	(((unsigned long) count) & PCPU_STATUS_MASK)

#define PCPU_COUNT_BITS		50
#define PCPU_COUNT_MASK		((1LL << PCPU_COUNT_BITS) - 1)

/**
 * percpu_ref_dead - check if a dynamic percpu refcount is shutting down
 *
 * Returns true if percpu_ref_kill() has been called on @ref, false otherwise.
 */
int percpu_ref_dead(struct percpu_ref *ref)
{
	return REF_STATUS(ref->pcpu_count) == PCPU_REF_DEAD;
}

/**
 * percpu_ref_get - increment a percpu refcount
 *
 * Analagous to atomic_inc().
  */
static inline void percpu_ref_get(struct percpu_ref *ref)
{
	unsigned __percpu *pcpu_count;

	preempt_disable();

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	if (likely(REF_STATUS(pcpu_count) == PCPU_REF_PTR)) {
		/* for rcu - we're not using rcu_dereference() */
		smp_read_barrier_depends();
		__this_cpu_inc(*pcpu_count);
	} else {
		__percpu_ref_get(ref, pcpu_count);
	}

	preempt_enable();
}

/**
 * percpu_ref_tryget - increment a percpu refcount if not shutting down
 *
 * Roughly analagous to atomic_inc_not_zero().
 */
static inline int percpu_ref_tryget(struct percpu_ref *ref)
{
	int ret = 0;

	preempt_disable();

	if (likely(!percpu_ref_dead(ref))) {
		percpu_ref_get(ref);
		ret = 1;
	}

	preempt_enable();

	return ret;
}

/**
 * percpu_ref_put - decrement a percpu refcount
 *
 * Decrement the refcount, and if 0, call the release function (which was passed
 * to percpu_ref_init())
 */
static inline void percpu_ref_put(struct percpu_ref *ref)
{
	unsigned __percpu *pcpu_count;

	preempt_disable();

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	if (likely(REF_STATUS(pcpu_count) == PCPU_REF_PTR)) {
		/* for rcu - we're not using rcu_dereference() */
		smp_read_barrier_depends();
		__this_cpu_dec(*pcpu_count);
	} else {
		uint64_t v;

		v = atomic64_dec_return(&ref->count);
		v &= PCPU_COUNT_MASK;
		if (unlikely(!v))
			ref->release(ref);
	}

	preempt_enable();
}

#endif
