#define pr_fmt(fmt) "%s: " fmt "\n", __func__

#include <linux/kernel.h>
#include <linux/percpu-refcount.h>

/*
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
 * Converting to non percpu mode is done with some RCUish stuff in
 * percpu_ref_kill. Additionally, we need a bias value so that the atomic_t
 * can't hit 0 before we've added up all the percpu refs.
 */

#define PCPU_COUNT_BIAS		(1U << 31)

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
int percpu_ref_init(struct percpu_ref *ref, percpu_ref_release *release)
{
	atomic_set(&ref->count, 1 + PCPU_COUNT_BIAS);

	ref->pcpu_count = alloc_percpu(unsigned);
	if (!ref->pcpu_count)
		return -ENOMEM;

	ref->release = release;
	return 0;
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

	pr_debug("global %i pcpu %i", atomic_read(&ref->count), (int) count);

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

	atomic_add((int) count - PCPU_COUNT_BIAS, &ref->count);

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

	call_rcu(&ref->rcu, percpu_ref_kill_rcu);
}
