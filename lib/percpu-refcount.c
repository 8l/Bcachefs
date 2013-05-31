#define pr_fmt(fmt) "%s: " fmt "\n", __func__

#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/percpu-refcount.h>

/*
 * A percpu refcount can be in three different modes. The state is tracked in
 * the low two bits of percpu_ref->pcpu_count:
 *
 * PCPU_REF_NONE - the initial state, no percpu counters allocated.
 *
 * PCPU_REF_PTR - using percpu counters for the refcount.
 *
 * PCPU_REF_DEAD - we're shutting down, get and put should use the atomic
 * counter and put should check for the ref hitting 0.
 *
 * Initially, a percpu refcount is just a set of percpu counters. Initially, we
 * don't try to detect the ref hitting 0 - which means that get/put can just
 * increment or decrement the local counter. Note that the counter on a
 * particular cpu can (and will) wrap - this is fine, when we go to shutdown the
 * percpu counters will all sum to the correct value
 *
 * (More precisely: because moduler arithmatic is commutative the sum of all the
 * pcpu_count vars will be equal to what it would have been if all the gets and
 * puts were done to a single integer, even if some of the percpu integers
 * overflow or underflow).
 *
 * The real trick to implementing percpu refcounts is shutdown. We can't detect
 * the ref hitting 0 on every put - this would require global synchronization
 * and defeat the whole purpose of using percpu refs.
 *
 * What we do is require the user to keep track of the initial refcount; we know
 * the ref can't hit 0 before the user drops the initial ref, so as long as we
 * convert to non percpu mode before the initial ref is dropped everything
 * works.
 *
 * Dynamic bits:
 *
 * Converting to non percpu mode is done with some RCUish stuff in
 * percpu_ref_kill. Additionally, we need a bias value so that the atomic_t
 * can't hit 0 before we've added up all the percpu refs.
 *
 * In PCPU_REF_NONE mode, we need to count the number of times percpu_ref_get()
 * is called; this is done with the high bits of the raw atomic counter. We also
 * track the time, in jiffies, when the get count last wrapped - this is done
 * with the remaining bits of percpu_ref->percpu_count.
 *
 * So, when percpu_ref_get() is called it increments the get count and checks if
 * it wrapped; if it did, it checks if the last time it wrapped was less than
 * one second ago; if so, we want to allocate percpu counters.
 *
 * PCPU_COUNT_BITS determines the threshold where we convert to percpu: of the
 * raw 64 bit counter, we use PCPU_COUNT_BITS for the refcount, and the
 * remaining (high) bits to count the number of times percpu_ref_get() has been
 * called. It's currently (completely arbitrarily) 16384 times in one second.
 */

#define PCPU_COUNT_BIAS		(1U << 31)

/*
 * So that we don't have to call alloc_percu() from percpu_ref_get(), we use a
 * small pool and refill from a workqueue.
 */

#define PCPU_REF_ALLOC_NR	8

static unsigned __percpu *percpu_ref_pool[PCPU_REF_ALLOC_NR];
static unsigned percpu_ref_alloc_nr;
static DEFINE_SPINLOCK(percpu_ref_alloc_lock);

static void percpu_ref_alloc_refill(struct work_struct *work)
{
	spin_lock_irq(&percpu_ref_alloc_lock);

	while (percpu_ref_alloc_nr < PCPU_REF_ALLOC_NR) {
		unsigned __percpu *ref;

		spin_unlock_irq(&percpu_ref_alloc_lock);
		ref = alloc_percpu(unsigned);
		spin_lock_irq(&percpu_ref_alloc_lock);

		if (!ref)
			break;

		percpu_ref_pool[percpu_ref_alloc_nr++] = ref;
	}

	spin_unlock_irq(&percpu_ref_alloc_lock);
}

static DECLARE_WORK(percpu_ref_alloc_work, percpu_ref_alloc_refill);

static void percpu_ref_alloc(struct percpu_ref *ref, unsigned __percpu *pcpu_count)
{
	unsigned long flags, now = jiffies;
	static unsigned __percpu *new = NULL;

	now <<= PCPU_STATUS_BITS;
	now |= PCPU_REF_NONE;

	if (now - (unsigned long) pcpu_count <= HZ << PCPU_STATUS_BITS) {
		spin_lock_irqsave(&percpu_ref_alloc_lock, flags);

		if (percpu_ref_alloc_nr)
			new = percpu_ref_pool[--percpu_ref_alloc_nr];

		if (percpu_ref_alloc_nr < PCPU_REF_ALLOC_NR / 2)
			schedule_work(&percpu_ref_alloc_work);

		spin_unlock_irqrestore(&percpu_ref_alloc_lock, flags);

		if (!new)
			goto update_time;

		BUG_ON((unsigned long) new & PCPU_STATUS_MASK);

		if (cmpxchg(&ref->pcpu_count, pcpu_count, new) != pcpu_count)
			free_percpu(new);
	} else {
update_time:
		cmpxchg(&ref->pcpu_count, pcpu_count, (unsigned __percpu *) now);
	}
}

/* Slowpath, i.e. non percpu */
void __percpu_ref_get(struct percpu_ref *ref, unsigned __percpu *pcpu_count)
{
	uint64_t v;

	v = atomic64_add_return(1 + (1ULL << PCPU_COUNT_BITS),
				&ref->count);

	/*
	 * The high bits of the counter count the number of gets() that
	 * have occured; we check for overflow to call
	 * percpu_ref_alloc() every (1 << (64 - PCPU_COUNT_BITS))
	 * iterations.
	 */

	if (unlikely(!(v >> PCPU_COUNT_BITS) &&
		     REF_STATUS(pcpu_count) == PCPU_REF_NONE))
		percpu_ref_alloc(ref, pcpu_count);
}

unsigned percpu_ref_count(struct percpu_ref *ref)
{
	unsigned __percpu *pcpu_count;
	unsigned count = 0;
	int cpu;

	preempt_disable();

	count = atomic64_read(&ref->count) & PCPU_COUNT_MASK;

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	if (REF_STATUS(pcpu_count) == PCPU_REF_PTR) {
		/* for rcu - we're not using rcu_dereference() */
		smp_read_barrier_depends();

		for_each_possible_cpu(cpu)
			count += *per_cpu_ptr(pcpu_count, cpu);
	}

	preempt_enable();

	return count;
}

/**
 * percpu_ref_init - initialize a percpu refcount
 * @ref:	ref to initialize
 * @release:	function which will be called when refcount hits 0
 *
 * Initializes the refcount in single atomic counter mode with a refcount of 1;
 * analagous to atomic_set(ref, 1).
 *
 * Note that @release must not sleep - it may potentially be called from RCU
 * callback context by percpu_ref_kill().
 */
void percpu_ref_init(struct percpu_ref *ref, percpu_ref_release *release)
{
	unsigned long now = jiffies;

	atomic64_set(&ref->count, 1 + PCPU_COUNT_BIAS);

	now <<= PCPU_STATUS_BITS;
	now |= PCPU_REF_NONE;

	ref->pcpu_count = (unsigned __percpu *) now;
	ref->release = release;
}

static void percpu_ref_kill_rcu(struct rcu_head *rcu)
{
	struct percpu_ref *ref = container_of(rcu, struct percpu_ref, rcu);
	unsigned __percpu *pcpu_count;
	unsigned count = 0;
	int cpu;

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	/* Mask out PCPU_REF_DEAD */
	pcpu_count = (unsigned __percpu *)
		(((unsigned long) pcpu_count) & ~PCPU_STATUS_MASK);

	for_each_possible_cpu(cpu)
		count += *per_cpu_ptr(pcpu_count, cpu);

	free_percpu(pcpu_count);

	pr_debug("global %lli pcpu %i",
		 (int64_t) atomic64_read(&ref->count), (int) count);

	/*
	 * It's crucial that we sum the percpu counters _before_ adding the sum
	 * to &ref->count; since gets could be happening on one cpu while puts
	 * happen on another, adding a single cpu's count could cause
	 * @ref->count to hit 0 before we've got a consistent value - but the
	 * sum of all the counts will be consistent and correct.
	 *
	 * Subtracting the bias value then has to happen _after_ adding count to
	 * &ref->count; we need the bias value to prevent &ref->count from
	 * reaching 0 before we add the percpu counts. But doing it at the same
	 * time is equivalent and saves us atomic operations:
	 */

	atomic64_add((int) count - PCPU_COUNT_BIAS, &ref->count);

	/*
	 * Now we're in single atomic_t mode with a consistent refcount, so it's
	 * safe to drop our initial ref:
	 */
	percpu_ref_put(ref);
}

/**
 * percpu_ref_kill - safely drop initial ref
 *
 * Must be used to drop the initial ref on a percpu refcount; must be called
 * precisely once before shutdown.
 *
 * Puts @ref in non percpu mode, then does a call_rcu() before gathering up the
 * percpu counters and dropping the initial ref.
 */
void percpu_ref_kill(struct percpu_ref *ref)
{
	unsigned __percpu *pcpu_count, *old, *new;

	pcpu_count = ACCESS_ONCE(ref->pcpu_count);

	do {
		if (REF_STATUS(pcpu_count) == PCPU_REF_DEAD) {
			WARN(1, "percpu_ref_kill() called more than once!\n");
			return;
		}

		old = pcpu_count;
		new = (unsigned __percpu *)
			(((unsigned long) pcpu_count)|PCPU_REF_DEAD);

		pcpu_count = cmpxchg(&ref->pcpu_count, old, new);
	} while (pcpu_count != old);

	if (REF_STATUS(pcpu_count) == PCPU_REF_PTR) {
		call_rcu(&ref->rcu, percpu_ref_kill_rcu);
	} else {
		atomic64_sub(PCPU_COUNT_BIAS, &ref->count);
		percpu_ref_put(ref);
	}
}
