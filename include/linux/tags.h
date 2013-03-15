/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 * Author: koverstreet@google.com (Kent Overstreet)
 *
 * Per cpu tag allocator.
 */

#ifndef _LINUX_TAGS_H
#define _LINUX_TAGS_H

#include <linux/list.h>
#include <linux/spinlock.h>

struct tag_cpu_freelist;

struct tag_pool {
	unsigned			watermark;
	unsigned			nr_tags;

	struct tag_cpu_freelist		*tag_cpu;

	struct {
		/* Global freelist */
		unsigned		nr_free;
		unsigned		*free;
		spinlock_t		lock;
		struct list_head	wait;
	} ____cacheline_aligned;
};

unsigned tag_alloc(struct tag_pool *pool, bool wait);
void tag_free(struct tag_pool *pool, unsigned tag);

void tag_pool_free(struct tag_pool *pool);
int tag_pool_init(struct tag_pool *pool, unsigned long nr_tags);


#endif
