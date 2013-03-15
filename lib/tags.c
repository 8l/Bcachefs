/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 * Author: koverstreet@google.com (Kent Overstreet)
 *
 * Per cpu tag allocator.
 */

#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/tags.h>

struct tag_cpu_freelist {
	unsigned			nr_free;
	unsigned			free[];
};

struct tag_waiter {
	struct list_head		list;
	struct task_struct		*task;
};

static inline void move_tags(unsigned *dst, unsigned *dst_nr,
			     unsigned *src, unsigned *src_nr,
			     unsigned nr)
{
	*src_nr -= nr;
	memcpy(dst + *dst_nr, src + *src_nr, sizeof(unsigned) * nr);
	*dst_nr += nr;
}

unsigned tag_alloc(struct tag_pool *pool, bool wait)
{
	struct tag_cpu_freelist *tags;
	unsigned long flags;
	unsigned ret;
retry:
	preempt_disable();
	local_irq_save(flags);
	tags = this_cpu_ptr(pool->tag_cpu);

	while (!tags->nr_free) {
		spin_lock(&pool->lock);

		if (pool->nr_free)
			move_tags(tags->free, &tags->nr_free,
				  pool->free, &pool->nr_free,
				  min(pool->nr_free, pool->watermark));
		else if (wait) {
			struct tag_waiter wait = { .task = current };

			__set_current_state(TASK_UNINTERRUPTIBLE);
			list_add(&wait.list, &pool->wait);

			spin_unlock(&pool->lock);
			local_irq_restore(flags);
			preempt_enable();

			schedule();
			__set_current_state(TASK_RUNNING);

			if (!list_empty_careful(&wait.list)) {
				spin_lock_irqsave(&pool->lock, flags);
				list_del_init(&wait.list);
				spin_unlock_irqrestore(&pool->lock, flags);
			}

			goto retry;
		} else
			goto fail;

		spin_unlock(&pool->lock);
	}

	ret = tags->free[--tags->nr_free];

	local_irq_restore(flags);
	preempt_enable();

	return ret;
fail:
	local_irq_restore(flags);
	preempt_enable();
	return 0;
}
EXPORT_SYMBOL_GPL(tag_alloc);

void tag_free(struct tag_pool *pool, unsigned tag)
{
	struct tag_cpu_freelist *tags;
	unsigned long flags;

	preempt_disable();
	local_irq_save(flags);
	tags = this_cpu_ptr(pool->tag_cpu);

	tags->free[tags->nr_free++] = tag;

	if (tags->nr_free == pool->watermark * 2) {
		spin_lock(&pool->lock);

		move_tags(pool->free, &pool->nr_free,
			  tags->free, &tags->nr_free,
			  pool->watermark);

		while (!list_empty(&pool->wait)) {
			struct tag_waiter *wait;
			wait = list_first_entry(&pool->wait,
						struct tag_waiter, list);
			list_del_init(&wait->list);
			wake_up_process(wait->task);
		}

		spin_unlock(&pool->lock);
	}

	local_irq_restore(flags);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(tag_free);

void tag_pool_free(struct tag_pool *pool)
{
	free_percpu(pool->tag_cpu);

	free_pages((unsigned long) pool->free,
		   get_order(pool->nr_tags * sizeof(unsigned)));
}
EXPORT_SYMBOL_GPL(tag_pool_free);

int tag_pool_init(struct tag_pool *pool, unsigned long nr_tags)
{
	unsigned i, order;

	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->wait);
	pool->nr_tags = nr_tags;

	/* Guard against overflow */
	if (nr_tags > UINT_MAX)
		return -ENOMEM;

	order = get_order(nr_tags * sizeof(unsigned));
	pool->free = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!pool->free)
		return -ENOMEM;

	for (i = 1; i < nr_tags; i++)
		pool->free[pool->nr_free++] = i;

	/* nr_possible_cpus would be more correct */
	pool->watermark = nr_tags / (num_possible_cpus() * 4);

	pool->watermark = min(pool->watermark, 128);

	if (pool->watermark > 64)
		pool->watermark = round_down(pool->watermark, 32);

	pool->tag_cpu = __alloc_percpu(sizeof(struct tag_cpu_freelist) +
				       pool->watermark * 2 * sizeof(unsigned),
				       sizeof(unsigned));
	if (!pool->tag_cpu)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL_GPL(tag_pool_init);
