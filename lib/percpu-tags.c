/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 * Author: koverstreet@google.com (Kent Overstreet)
 *
 * Per cpu tag allocator.
 */

#include <asm/cmpxchg.h>
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/percpu-tags.h>

/*
 * Number of tags we move between the percpu freelist and the global freelist at
 * a time
 */
#define TAG_CPU_BATCH_MOVE	32U

/* Max size of percpu freelist, */
#define TAG_CPU_SIZE		(TAG_CPU_BATCH_MOVE * 2)

/*
 * When we're stealing tags from a remote cpu's freelist, we need to avoid
 * racing with alloc/free on that cpu - steal_tags() will set nr_free on their
 * freelist to TAG_CPU_STEALING while it copies tags away.
 */
#define TAG_CPU_STEALING	UINT_MAX

struct percpu_tag_cpu {
	unsigned			nr_free;
	unsigned			freelist[];
};

static inline void move_tags(unsigned *dst, unsigned *dst_nr,
			     unsigned *src, unsigned *src_nr,
			     unsigned nr)
{
	*src_nr -= nr;
	memcpy(dst + *dst_nr, src + *src_nr, sizeof(unsigned) * nr);
	*dst_nr += nr;
}

/*
 * Try to steal tags from a remote cpu's percpu freelist.
 *
 * We first check how many percpu freelists have tags - we don't steal tags
 * unless enough percpu freelists have tags on them that it's possible more than
 * half the total tags could be stuck on remote percpu freelists.
 *
 * Then we iterate through the cpus until we find some tags - we don't attempt
 * to find the "best" cpu to steal from, to keep cacheline bouncing to a
 * minimum.
 *
 * Returns true on success (our percpu freelist is no longer empty), false on
 * failure.
 */
static inline bool steal_tags(struct percpu_tag_pool *pool,
			      struct percpu_tag_cpu *tags)
{
	unsigned nr_free, cpus_have_tags, cpu = pool->cpu_last_stolen;
	struct percpu_tag_cpu *remote;

	for (cpus_have_tags = bitmap_weight(pool->cpus_have_tags, nr_cpu_ids);
	     cpus_have_tags * TAG_CPU_SIZE > pool->nr_tags / 2;
	     cpus_have_tags--) {
		cpu = find_next_bit(pool->cpus_have_tags, nr_cpu_ids, cpu);

		if (cpu == nr_cpu_ids)
			cpu = find_first_bit(pool->cpus_have_tags, nr_cpu_ids);

		if (cpu == nr_cpu_ids)
			BUG();

		pool->cpu_last_stolen = cpu;
		remote = per_cpu_ptr(pool->tag_cpu, cpu);

		if (remote == tags)
			continue;

		clear_bit(cpu, pool->cpus_have_tags);

		nr_free = xchg(&remote->nr_free, TAG_CPU_STEALING);

		if (nr_free) {
			memcpy(tags->freelist,
			       remote->freelist,
			       sizeof(unsigned) * nr_free);

			/*
			 * Setting remote->nr_free is effectively unlock - so
			 * barrier between it and the memcpy(), corresponding to
			 * barrier in percpu_tag_free()
			 */
			smp_mb();
			remote->nr_free = 0;

			tags->nr_free = nr_free;
			return true;
		} else {
			remote->nr_free = 0;
		}
	}

	return false;
}

static inline bool alloc_global_tags(struct percpu_tag_pool *pool,
				     struct percpu_tag_cpu *tags)
{
	int nr_free = bitmap_tree_find_set_bits(&pool->map,
						tags->freelist,
						TAG_CPU_BATCH_MOVE);

	if (nr_free <= 0)
		return false;

	tags->nr_free = nr_free;
	return true;
}

static inline unsigned alloc_local_tag(struct percpu_tag_pool *pool,
				       struct percpu_tag_cpu *tags)
{
	unsigned nr_free, old, new, tag;

	/*
	 * Try per cpu freelist
	 * Since we don't have global lock held, need to use cmpxchg()
	 * to guard against a different thread using steal_tags() on us:
	 */
	nr_free = tags->nr_free;

	do {
		if (unlikely(!nr_free || nr_free == TAG_CPU_STEALING))
			return TAG_FAIL;

		old = nr_free;
		new = old - 1;
		tag = tags->freelist[new];

		nr_free = cmpxchg(&tags->nr_free, old, new);
	} while (unlikely(nr_free != old));

	return tag;
}

/**
 * percpu_tag_alloc - allocate a tag
 * @pool: pool to allocate from
 * @gfp: gfp flags
 *
 * Returns a tag - an integer in the range [0..nr_tags) (passed to
 * tag_pool_init()), or otherwise TAG_FAIL on allocation failure.
 *
 * Safe to be called from interrupt context (assuming it isn't passed
 * __GFP_WAIT, of course).
 *
 * Will not fail if passed __GFP_WAIT.
 */
unsigned percpu_tag_alloc(struct percpu_tag_pool *pool, gfp_t gfp)
{
	DEFINE_WAIT(wait);
	struct percpu_tag_cpu *tags;
	unsigned long flags;
	unsigned tag, this_cpu;

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	tags = per_cpu_ptr(pool->tag_cpu, this_cpu);

	/* Fastpath */
	tag = alloc_local_tag(pool, tags);
	if (likely(tag != TAG_FAIL)) {
		local_irq_restore(flags);
		return tag;
	}

	while (1) {
		spin_lock(&pool->lock);

		/*
		 * prepare_to_wait() must come before steal_tags(), in case
		 * percpu_tag_free() on another cpu flips a bit in
		 * cpus_have_tags
		 */
		prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);

		/*
		 * alloc_global_tags(), steal_tags() return true iff we now have
		 * tags on our percpu freelist
		 */
		if (tags->nr_free ||
		    alloc_global_tags(pool, tags) ||
		    steal_tags(pool, tags)) {
			/* Global lock held, don't need cmpxchg */
			tag = tags->freelist[--tags->nr_free];
			if (tags->nr_free)
				set_bit(this_cpu, pool->cpus_have_tags);
		}

		spin_unlock(&pool->lock);
		local_irq_restore(flags);

		if (tag != TAG_FAIL || !(gfp & __GFP_WAIT))
			break;

		schedule();

		local_irq_save(flags);
		this_cpu = smp_processor_id();
		tags = per_cpu_ptr(pool->tag_cpu, this_cpu);
	}

	finish_wait(&pool->wait, &wait);
	return tag;
}
EXPORT_SYMBOL_GPL(percpu_tag_alloc);

/**
 * percpu_tag_free - free a tag
 * @pool: pool @tag was allocated from
 * @tag: a tag previously allocated with percpu_tag_alloc()
 *
 * Safe to be called from interrupt context.
 */
void percpu_tag_free(struct percpu_tag_pool *pool, unsigned tag)
{
	struct percpu_tag_cpu *tags;
	unsigned long flags;
	unsigned nr_free, old, new, this_cpu;

	BUG_ON(tag >= pool->nr_tags);

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	tags = per_cpu_ptr(pool->tag_cpu, this_cpu);

	/*
	 * Need to guard against racing with steal_tags() on another cpu - we
	 * can manage with just cmpxchg because we can only race with tags being
	 * pulled off our freelist, not other threads pushing tags back onto our
	 * freelist
	 */
	nr_free = tags->nr_free;

	do {
		while (unlikely(nr_free == TAG_CPU_STEALING)) {
			cpu_relax();
			nr_free = tags->nr_free;
		}

		smp_mb();

		old = nr_free;
		new = old + 1;
		tags->freelist[old] = tag;

		nr_free = cmpxchg(&tags->nr_free, old, new);
	} while (unlikely(nr_free != old));

	if (!nr_free) {
		set_bit(this_cpu, pool->cpus_have_tags);
		wake_up(&pool->wait);
	}

	if (new == TAG_CPU_SIZE) {
		spin_lock(&pool->lock);

		while (tags->nr_free > TAG_CPU_SIZE - TAG_CPU_BATCH_MOVE)
			bitmap_tree_clear_bit(&pool->map,
					      tags->freelist[--tags->nr_free]);

		wake_up(&pool->wait);
		spin_unlock(&pool->lock);
	}

	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(percpu_tag_free);

/**
 * percpu_tag_pool_free - release a tag pool's resources
 * @pool: pool to free
 *
 * Frees the resources allocated by percpu_tag_pool_init().
 */
void percpu_tag_pool_free(struct percpu_tag_pool *pool)
{
	free_percpu(pool->tag_cpu);
	kfree(pool->cpus_have_tags);
	bitmap_tree_free(&pool->map);
}
EXPORT_SYMBOL_GPL(percpu_tag_pool_free);

/**
 * percpu_tag_pool_init - initialize a percpu tag pool
 * @pool: pool to initialize
 * @nr_tags: number of tags that will be available for allocation
 *
 * Initializes @pool so that it can be used to allocate tags - integers in the
 * range [0, nr_tags). Typically, they'll be used by driver code to refer to a
 * preallocated array of tag structures.
 *
 * Allocation is percpu, but sharding is limited by nr_tags - for best
 * performance, the workload should not span more cpus than nr_tags / 128.
 */
int percpu_tag_pool_init(struct percpu_tag_pool *pool, unsigned long nr_tags)
{
	memset(pool, 0, sizeof(*pool));

	spin_lock_init(&pool->lock);
	init_waitqueue_head(&pool->wait);
	pool->nr_tags = nr_tags;

	/* Guard against overflow */
	if (nr_tags > TAG_MAX) {
		pr_err("tags.c: nr_tags too large\n");
		return -EINVAL;
	}

	if (bitmap_tree_init(&pool->map, nr_tags))
		return -ENOMEM;

	pool->cpus_have_tags = kzalloc(BITS_TO_LONGS(nr_cpu_ids) *
				       sizeof(unsigned long), GFP_KERNEL);
	if (!pool->cpus_have_tags)
		goto err;

	pool->tag_cpu = __alloc_percpu(sizeof(struct percpu_tag_cpu) +
				       TAG_CPU_SIZE * sizeof(unsigned),
				       sizeof(unsigned));
	if (!pool->tag_cpu)
		goto err;

	return 0;
err:
	percpu_tag_pool_free(pool);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(percpu_tag_pool_init);
