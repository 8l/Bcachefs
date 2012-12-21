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
	uint16_t			watermark;
	uint16_t			nr_tags;

	struct tag_cpu_freelist		*tag_cpu;

	struct {
		/* Global freelist */
		uint16_t		nr_free;
		uint16_t		*free;
		spinlock_t		lock;
		struct list_head	wait;
	} ____cacheline_aligned;
};

uint16_t tag_alloc(struct tag_pool *pool, bool wait);
void tag_free(struct tag_pool *pool, uint16_t tag);

void tag_pool_free(struct tag_pool *pool);
int tag_pool_init(struct tag_pool *pool, uint16_t nr_tags);


#endif
