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

#include <linux/init.h>
#include <linux/bitmap-tree.h>
#include <linux/bitops.h>
#include <linux/gfp.h>
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

/* IDA */

struct ida {
	struct bitmap_tree	map;
};

#define IDA_INIT(name)						\
{								\
	.map	= BITMAP_TREE_INIT(name.map),			\
}
#define DEFINE_IDA(name)	struct ida name = IDA_INIT(name)

void ida_remove(struct ida *ida, unsigned id);

void ida_destroy(struct ida *ida);
void ida_init(struct ida *ida);

int ida_get_range(struct ida *ida, unsigned int start,
		  unsigned int end, gfp_t gfp_mask);

static inline int ida_get(struct ida *ida, gfp_t gfp_mask)
{
	return ida_get_range(ida, 0, 0, gfp_mask);
}

/* IDR */

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

struct idr;

void *idr_find_next(struct idr *idr, int *nextid);
int idr_for_each(struct idr *idr,
		 int (*fn)(int id, void *p, void *data), void *data);
void *idr_replace(struct idr *idr, void *ptr, unsigned id);
void idr_remove(struct idr *idr, unsigned id);
int idr_alloc_range(struct idr *idr, void *ptr, unsigned start,
		    unsigned end, gfp_t gfp);
int idr_alloc_cyclic(struct idr *idr, void *ptr, unsigned start,
		     unsigned end, gfp_t gfp_mask);
void idr_destroy(struct idr *idr);
void idr_init(struct idr *idr);

/**
 * idr_for_each_entry - iterate over an idr's elements of a given type
 * @idr:     idr handle
 * @entry:   the type * to use as cursor
 * @id:      id entry's key
 *
 * @entry and @id do not need to be initialized before the loop, and
 * after normal terminatinon @entry is left with the value NULL.  This
 * is convenient for a "not found" value.
 */
#define idr_for_each_entry(idr, entry, id)			\
	for (id = 0; ((entry) = idr_find_next(idr, &(id))) != NULL; ++id)

static inline int idr_alloc(struct idr *idr, void *ptr, gfp_t gfp)
{
	return idr_alloc_range(idr, ptr, 0, 0, gfp);
}

#if 0
#define IDR_FIRST_LAYER_SIZE	(1 << 7)
#define IDR_LAYERS		14

struct idr {
	struct ida	ida;
	void __rcu	**layers[IDR_LAYERS];
};

static inline unsigned __idr_layer_from_id(unsigned *id)
{
	unsigned i, size = IDR_FIRST_LAYER_SIZE;

	for (i = 0; *id >= size; i++) {
		*id -= size;
		size *= 2;
	}

	return i;
}

/**
 * idr_find - return pointer for given id
 * @idr: idr handle
 * @id: lookup key
 *
 * Return the pointer given the id it has been registered with.  A %NULL
 * return indicates that @id is not valid or you passed %NULL in
 * idr_alloc().
 */
static inline void *idr_find(struct idr *idr, unsigned id)
{
	unsigned layer;
	void *ptr = NULL;

	rcu_read_lock();
	layer = __idr_layer_from_id(&id);

	if (layer < IDR_LAYERS && idr->layers[layer])
		ptr = rcu_dereference(rcu_dereference(idr->layers[layer])[id]);

	rcu_read_unlock();

	return ptr;
}
#endif

struct idr {
	struct ida		ida;
	unsigned		cur;
	struct radix_tree_root	ptrs;
};

#define IDR_INIT(name)							\
{									\
	.ida			= IDA_INIT(name.ida),			\
	.ptrs			= RADIX_TREE_INIT(GFP_NOWAIT),		\
}
#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)

/**
 * idr_find - return pointer for given id
 * @idr: idr handle
 * @id: lookup key
 *
 * Return the pointer given the id it has been registered with.  A %NULL
 * return indicates that @id is not valid or you passed %NULL in
 * idr_alloc().
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 */
static inline void *idr_find(struct idr *idr, unsigned id)
{
	void *ret;

	rcu_read_lock();
	ret = radix_tree_lookup(&idr->ptrs, id);
	rcu_read_unlock();

	return ret;
}

/**
 * idr_preload_end - end preload section started with idr_preload()
 *
 * Each idr_preload() should be matched with an invocation of this
 * function.  See idr_preload() for details.
 */
static inline void idr_preload_end(void)
{
	radix_tree_preload_end();
}

/**
 * idr_preload - preload for idr_alloc_range()
 * @gfp: allocation mask to use for preloading
 *
 * Preload per-cpu layer buffer for idr_alloc_range().  Can only be used from
 * process context and each idr_preload() invocation should be matched with
 * idr_preload_end().  Note that preemption is disabled while preloaded.
 *
 * The first idr_alloc_range() in the preloaded section can be treated as if it
 * were invoked with @gfp_mask used for preloading.  This allows using more
 * permissive allocation masks for idrs protected by spinlocks.
 *
 * For example, if idr_alloc_range() below fails, the failure can be treated as
 * if idr_alloc_range() were called with GFP_KERNEL rather than GFP_NOWAIT.
 *
 *	idr_preload(GFP_KERNEL);
 *	spin_lock(lock);
 *
 *	id = idr_alloc_range(idr, ptr, start, end, GFP_NOWAIT);
 *
 *	spin_unlock(lock);
 *	idr_preload_end();
 *	if (id < 0)
 *		error;
 */
static inline void idr_preload(gfp_t gfp)
{
	might_sleep_if(gfp & __GFP_WAIT);

	/* Well this is horrible, but idr_preload doesn't return errors */
	if (radix_tree_preload(gfp))
		preempt_disable();
}

#endif /* __IDR_H__ */
