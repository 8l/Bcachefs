/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 * Author: koverstreet@google.com (Kent Overstreet)
 *
 * Per cpu tag allocator. Allocates small integers - up to nr_tags passed to
 * percpu_tag_pool_init() - for use with say driver tag structures for talking
 * to a device.
 *
 * It works by caching tags on percpu freelists, and then tags are
 * allocated/freed from the global freelist in batches.
 *
 * Note that it will in general be impossible to allocate all nr_tags tags,
 * since some tags will be stranded on other cpu's freelists: but we guarantee
 * that nr_tags / 2 can always be allocated.
 *
 * This is done by keeping track of which cpus have tags on their percpu
 * freelists in a bitmap, and then on allocation failure if too many cpus have
 * tags on their freelists - i.e. if cpus_have_tags * TAG_CPU_SIZE (64) >
 * nr_tags / 2 - then we steal one remote cpu's freelist (effectively picked at
 * random).
 *
 * This means that if a workload spans a huge number of cpus - in relation to
 * the number of tags that can be allocated - performance will suffer somewhat;
 * but as long as the workload is bounded to a reasonable number of cpus the
 * percpu-ness of the allocator will not be affected.
 */

#ifndef _LINUX_TAGS_H
#define _LINUX_TAGS_H

#include <linux/bitmap-tree.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>

struct percpu_tag_cpu;

struct percpu_tag_pool {
	/*
	 * number of tags available to be allocated, as passed to
	 * percpu_tag_pool_init()
	 */
	unsigned			nr_tags;

	struct percpu_tag_cpu __percpu	*tag_cpu;

	/*
	 * Bitmap of cpus that (may) have tags on their percpu freelists:
	 * steal_tags() uses this to decide when to steal tags, and which cpus
	 * to try stealing from.
	 *
	 * It's ok for a freelist to be empty when its bit is set - steal_tags()
	 * will just keep looking - but the bitmap _must_ be set whenever a
	 * percpu freelist does have tags.
	 */
	unsigned long			*cpus_have_tags;

	struct {
		spinlock_t		lock;
		/*
		 * When we go to steal tags from another cpu (see steal_tags()),
		 * we want to pick a cpu at random. Cycling through them every
		 * time we steal is a bit easier and more or less equivalent:
		 */
		unsigned		cpu_last_stolen;

		/* For sleeping on allocation failure */
		wait_queue_head_t	wait;

		/* Global freelist */
		struct bitmap_tree	map;
	} ____cacheline_aligned_in_smp;
};

unsigned percpu_tag_alloc(struct percpu_tag_pool *pool, gfp_t gfp);
void percpu_tag_free(struct percpu_tag_pool *pool, unsigned tag);

void percpu_tag_pool_free(struct percpu_tag_pool *pool);
int percpu_tag_pool_init(struct percpu_tag_pool *pool, unsigned long nr_tags);

enum {
	/*
	 * TAG_FAIL is returned on allocation failure, TAG_MAX is the max
	 * nr_tags you can pass to percpu_tag_pool_init()
	 */
	TAG_FAIL	= -1U,
	TAG_MAX		= TAG_FAIL - 1,
};

#endif
