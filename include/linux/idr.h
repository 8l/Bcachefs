/*
 * include/linux/idr.h
 * 
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *	Distributed under the GNU GPL license version 2.
 *
 * Small id to pointer translation service avoiding fixed sized
 * tables.
 */

#ifndef __IDR_H__
#define __IDR_H__

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>

/* IDA */

struct ida {
	spinlock_t		lock;

	/*
	 * cur_id and allocated_ids are for ida_alloc_cyclic. For cyclic
	 * allocations we search for new ids to allocate starting from the last
	 * id allocated - cur_id is the next id to try allocating.
	 *
	 * But we also don't want the allocated ids to be arbitrarily sparse -
	 * the memory usage for the bitmap could be arbitrarily bad, and if
	 * they're used as keys in a radix tree the memory overhead of the radix
	 * tree could be quite bad as well. So we use allocated_ids to decide
	 * when to restart cur_id from 0, and bound how sparse the bitmap can
	 * be.
	 */
	unsigned		cur_id;
	unsigned		allocated_ids;

	/* size of ida->tree */
	unsigned		nodes;

	/*
	 * Index of first leaf node in ida->tree; equal to the number of non
	 * leaf nodes, ida->nodes - ida->first_leaf == number of leaf nodes
	 */
	unsigned		first_leaf;
	unsigned		sections;

	unsigned long		**tree;
	unsigned long		*inline_section;
	unsigned long		inline_node;
};

#define IDA_INIT(name)						\
{								\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),	\
	.nodes		= 1,					\
	.first_leaf	= 0,					\
	.sections	= 1,					\
	.tree		= &name.inline_section,			\
	.inline_section	= &name.inline_node,			\
}
#define DEFINE_IDA(name)	struct ida name = IDA_INIT(name)

void ida_remove(struct ida *ida, unsigned id);
int ida_alloc_range(struct ida *ida, unsigned int start,
		  unsigned int end, gfp_t gfp);
int ida_alloc_cyclic(struct ida *ida, unsigned start, unsigned end, gfp_t gfp);
void ida_destroy(struct ida *ida);
int ida_init_prealloc(struct ida *ida, unsigned prealloc);

/**
 * ida_alloc_range - allocate a new id.
 * @ida: the (initialized) ida.
 * @gfp_mask: memory allocation flags
 *
 * Allocates an id in the range [0, INT_MAX]. Returns -ENOSPC if no ids are
 * available, or -ENOMEM on memory allocation failure.
 *
 * Returns the smallest available id
 *
 * Use ida_remove() to get rid of an id.
 */
static inline int ida_alloc(struct ida *ida, gfp_t gfp_mask)
{
	return ida_alloc_range(ida, 0, 0, gfp_mask);
}

/**
 * ida_init - initialize ida handle
 * @ida:	ida handle
 *
 * This function is use to set up the handle (@ida) that you will pass
 * to the rest of the functions.
 */
static inline void ida_init(struct ida *ida)
{
	ida_init_prealloc(ida, 0);
}

/* Percpu IDA/tag allocator */

struct percpu_ida_cpu;

struct percpu_ida {
	/*
	 * number of tags available to be allocated, as passed to
	 * percpu_ida_init()
	 */
	unsigned			nr_tags;

	struct percpu_ida_cpu __percpu	*tag_cpu;

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
		/*
		 * When we go to steal tags from another cpu (see steal_tags()),
		 * we want to pick a cpu at random. Cycling through them every
		 * time we steal is a bit easier and more or less equivalent:
		 */
		unsigned		cpu_last_stolen;

		/* For sleeping on allocation failure */
		wait_queue_head_t	wait;

		/* Global freelist */
		struct ida		ida;
	} ____cacheline_aligned_in_smp;
};

int percpu_ida_alloc(struct percpu_ida *pool, gfp_t gfp);
void percpu_ida_free(struct percpu_ida *pool, unsigned tag);

void percpu_ida_destroy(struct percpu_ida *pool);
int percpu_ida_init(struct percpu_ida *pool, unsigned long nr_tags);

/* IDR */

/*
 * We want shallower trees and thus more bits covered at each layer.  8
 * bits gives us large enough first layer for most use cases and maximum
 * tree depth of 4.  Each idr_layer is slightly larger than 2k on 64bit and
 * 1k on 32bit.
 */
#define IDR_BITS 8
#define IDR_SIZE (1 << IDR_BITS)
#define IDR_MASK ((1 << IDR_BITS)-1)

struct idr_layer {
	int			prefix;	/* the ID prefix of this idr_layer */
	DECLARE_BITMAP(bitmap, IDR_SIZE); /* A zero bit means "space here" */
	struct idr_layer __rcu	*ary[1<<IDR_BITS];
	int			count;	/* When zero, we can release it */
	int			layer;	/* distance from leaf */
	struct rcu_head		rcu_head;
};

struct idr {
	struct idr_layer __rcu	*hint;	/* the last layer allocated from */
	struct idr_layer __rcu	*top;
	struct idr_layer	*id_free;
	int			layers;	/* only valid w/o concurrent changes */
	int			id_free_cnt;
	int			cur;	/* current pos for cyclic allocation */
	spinlock_t		lock;
};

#define IDR_INIT(name)							\
{									\
	.lock			= __SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)

/**
 * DOC: idr sync
 * idr synchronization (stolen from radix-tree.h)
 *
 * idr_find() is able to be called locklessly, using RCU. The caller must
 * ensure calls to this function are made within rcu_read_lock() regions.
 * Other readers (lock-free or otherwise) and modifications may be running
 * concurrently.
 *
 * It is still required that the caller manage the synchronization and
 * lifetimes of the items. So if RCU lock-free lookups are used, typically
 * this would mean that the items have their own locks, or are amenable to
 * lock-free access; and that the items are freed by RCU (or only freed after
 * having been deleted from the idr tree *and* a synchronize_rcu() grace
 * period).
 */

/*
 * This is what we export.
 */

void *idr_find_slowpath(struct idr *idp, int id);
void idr_preload(gfp_t gfp_mask);
int idr_alloc(struct idr *idp, void *ptr, int start, int end, gfp_t gfp_mask);
int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask);
int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data);
void *idr_find_next(struct idr *idp, int *nextid);
void *idr_replace(struct idr *idp, void *ptr, int id);
void idr_remove(struct idr *idp, int id);
void idr_free(struct idr *idp, int id);
void idr_destroy(struct idr *idp);
void idr_init(struct idr *idp);

/**
 * idr_preload_end - end preload section started with idr_preload()
 *
 * Each idr_preload() should be matched with an invocation of this
 * function.  See idr_preload() for details.
 */
static inline void idr_preload_end(void)
{
	preempt_enable();
}

/**
 * idr_find - return pointer for given id
 * @idr: idr handle
 * @id: lookup key
 *
 * Return the pointer given the id it has been registered with.  A %NULL
 * return indicates that @id is not valid or you passed %NULL in
 * idr_get_new().
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 */
static inline void *idr_find(struct idr *idr, int id)
{
	struct idr_layer *hint = rcu_dereference_raw(idr->hint);

	if (hint && (id & ~IDR_MASK) == hint->prefix)
		return rcu_dereference_raw(hint->ary[id & IDR_MASK]);

	return idr_find_slowpath(idr, id);
}

/**
 * idr_for_each_entry - iterate over an idr's elements of a given type
 * @idp:     idr handle
 * @entry:   the type * to use as cursor
 * @id:      id entry's key
 *
 * @entry and @id do not need to be initialized before the loop, and
 * after normal terminatinon @entry is left with the value NULL.  This
 * is convenient for a "not found" value.
 */
#define idr_for_each_entry(idp, entry, id)			\
	for (id = 0; ((entry) = idr_find_next(idp, &(id))) != NULL; ++id)

void __init idr_init_cache(void);

#endif /* __IDR_H__ */
