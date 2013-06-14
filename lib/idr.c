/*
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *	Distributed under the GNU GPL license version 2.
 *
 * Modified by George Anzinger to reuse immediately and to use
 * find bit instructions.  Also removed _irq on spinlocks.
 *
 * Modified by Nadia Derbey to make it RCU safe.
 *
 * Small id to pointer translation service.
 *
 * It uses a radix tree like structure as a sparse array indexed
 * by the id to obtain the pointer.  The bitmap makes allocating
 * a new id quick.
 *
 * You call it to allocate an id (an int) an associate with that id a
 * pointer or what ever, we treat it as a (void *).  You can pass this
 * id to a user for him to pass back at a later time.  You then pass
 * that id to this code and it returns your pointer.

 * You can release ids at any time. When all ids are released, most of
 * the memory is returned (we keep MAX_IDR_FREE) in a local pool so we
 * don't need to go to the memory "store" during an id allocate, just
 * so you don't need to be too concerned about locking and conflicts
 * with the slab allocator.
 */

#ifndef TEST                        // to test in user space...
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/export.h>
#endif
#include <linux/err.h>
#include <linux/string.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>

/* IDA */

/**
 * DOC: IDA description
 * IDA - IDR based ID allocator
 *
 * This is id allocator without id -> pointer translation.  Memory
 * usage is much lower than full blown idr because each id only
 * occupies a bit.  ida uses a custom leaf node which contains
 * IDA_BITMAP_BITS slots.
 *
 * 2007-04-25  written by Tejun Heo <htejun@gmail.com>
 */

/**
 * ida_remove - remove an allocated id.
 * @ida: the (initialized) ida.
 * @id: the id returned by ida_get_range.
 */
void ida_remove(struct ida *ida, unsigned int id)
{
	BUG_ON(id > INT_MAX);
	bitmap_tree_clear_bit(&ida->map, id);
}
EXPORT_SYMBOL(ida_remove);

/**
 * ida_get_range - get a new id.
 * @ida: the (initialized) ida.
 * @start: the minimum id (inclusive, < 0x8000000)
 * @end: the maximum id (exclusive, < 0x8000000 or 0)
 * @gfp_mask: memory allocation flags
 *
 * Allocates an id in the range start <= id < end, or returns -ENOSPC.
 * On memory allocation failure, returns -ENOMEM.
 *
 * Use ida_remove() to get rid of an id.
 */
int ida_get_range(struct ida *ida, unsigned int start,
		  unsigned int end, gfp_t gfp)
{
	unsigned id;
	int ret = bitmap_tree_find_set_bits_from(&ida->map, &id, 1,
						 start, end ?: INT_MAX, gfp);
	if (ret < 0)
		return ret;

	return id;
}
EXPORT_SYMBOL(ida_get_range);

/**
 * ida_destroy - release all cached layers within an ida tree
 * @ida:		ida handle
 */
void ida_destroy(struct ida *ida)
{
	bitmap_tree_destroy(&ida->map);
}
EXPORT_SYMBOL(ida_destroy);

/**
 * ida_init - initialize ida handle
 * @ida:	ida handle
 *
 * This function is use to set up the handle (@ida) that you will pass
 * to the rest of the functions.
 */
void ida_init(struct ida *ida)
{
	bitmap_tree_init(&ida->map, 0);

}
EXPORT_SYMBOL(ida_init);

/* IDR */

/**
 * idr_find_next - lookup next object of id to given id.
 * @idp: idr handle
 * @nextidp:  pointer to lookup key
 *
 * Returns pointer to registered object with id, which is next number to
 * given id. After being looked up, *@nextidp will be updated for the next
 * iteration.
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 */
void *idr_find_next(struct idr *idr, int *nextidp)
{
	void **slot;
	struct radix_tree_iter iter;

	radix_tree_for_each_slot(slot, &idr->ptrs, &iter, *nextidp) {
		*nextidp = iter.index;
		return radix_tree_deref_slot(slot);
	}

	return NULL;
}
EXPORT_SYMBOL(idr_find_next);

/**
 * idr_for_each - iterate through all stored pointers
 * @idp: idr handle
 * @fn: function to be called for each pointer
 * @data: data passed back to callback function
 *
 * Iterate over the pointers registered with the given idr.  The
 * callback function will be called for each pointer currently
 * registered, passing the id, the pointer and the data pointer passed
 * to this function.  It is not safe to modify the idr tree while in
 * the callback, so functions such as idr_remove are not allowed.
 *
 * We check the return of @fn each time. If it returns anything other
 * than %0, we break out and return that value.
 *
 * The caller must serialize idr_for_each() vs idr_remove().
 */
int idr_for_each(struct idr *idr,
		 int (*fn)(int id, void *p, void *data), void *data)
{
	void *p;
	unsigned id;
	int error = 0;

	idr_for_each_entry(idr, p, id) {
		error = fn(id, (void *)p, data);
		if (error)
			break;
	}

	return error;
}
EXPORT_SYMBOL(idr_for_each);

/**
 * idr_replace - replace pointer for given id
 * @idp: idr handle
 * @ptr: pointer you want associated with the id
 * @id: lookup key
 *
 * Replace the pointer registered with an id and return the old value.
 * A %-ENOENT return indicates that @id was not found.
 * A %-EINVAL return indicates that @id was not within valid constraints.
 *
 * The caller must serialize with writers.
 */
void *idr_replace(struct idr *idr, void *ptr, unsigned id)
{
	void **slot, *old = ERR_PTR(-ENOENT);

	rcu_read_lock();

	slot = radix_tree_lookup_slot(&idr->ptrs, id);

	if (slot) {
		old = radix_tree_deref_slot(slot);
		if (old)
			radix_tree_replace_slot(slot, ptr);
	}

	rcu_read_unlock();

	return old;
}
EXPORT_SYMBOL(idr_replace);

/**
 * idr_remove - remove the given id and free its slot
 * @idp: idr handle
 * @id: unique key
 */
void idr_remove(struct idr *idr, unsigned id)
{
	radix_tree_delete(&idr->ptrs, id);
	ida_remove(&idr->ida, id);
}
EXPORT_SYMBOL(idr_remove);

/**
 * idr_alloc_range - allocate new idr entry
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp: memory allocation flags
 *
 * Allocate an id in [start, end) and associate it with @ptr.  If no ID is
 * available in the specified range, returns -ENOSPC.  On memory allocation
 * failure, returns -ENOMEM.
 *
 * Note that @end is treated as max when <= 0.  This is to always allow
 * using @start + N as @end as long as N is inside integer range.
 *
 * The user is responsible for exclusively synchronizing all operations
 * which may modify @idr.  However, read-only accesses such as idr_find()
 * or iteration can be performed under RCU read lock provided the user
 * destroys @ptr in RCU-safe way after removal from idr.
 */
int idr_alloc_range(struct idr *idr, void *ptr, unsigned start,
		    unsigned end, gfp_t gfp)
{
	int id, ret;

	might_sleep_if(gfp & __GFP_WAIT);

	id = ida_get_range(&idr->ida, start, end, gfp);
	if (unlikely(id < 0))
		return id;

	ret = radix_tree_preload(gfp);
	if (ret) {
		ida_remove(&idr->ida, id);
		return ret;
	}

	radix_tree_insert(&idr->ptrs, ret, ptr);
	radix_tree_preload_end();

	return ret;
}
EXPORT_SYMBOL_GPL(idr_alloc_range);

/**
 * idr_alloc_cyclic - allocate new idr entry in a cyclical fashion
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp_mask: memory allocation flags
 *
 * Essentially the same as idr_alloc_range, but prefers to allocate progressively
 * higher ids if it can. If the "cur" counter wraps, then it will start again
 * at the "start" end of the range and allocate one that has already been used.
 */
int idr_alloc_cyclic(struct idr *idr, void *ptr, unsigned start,
		     unsigned end, gfp_t gfp_mask)
{
	int id;

	id = idr_alloc_range(idr, ptr, max(start, idr->cur), end, gfp_mask);
	if (id == -ENOSPC)
		id = idr_alloc_range(idr, ptr, start, end, gfp_mask);

	if (likely(id >= 0))
		idr->cur = id + 1;
	return id;
}
EXPORT_SYMBOL(idr_alloc_cyclic);

/**
 * idr_destroy - release all cached layers within an idr tree
 * @idp: idr handle
 *
 * Free all id mappings and all idp_layers.  After this function, @idp is
 * completely unused and can be freed / recycled.  The caller is
 * responsible for ensuring that no one else accesses @idp during or after
 * idr_destroy().
 *
 * A typical clean-up sequence for objects stored in an idr tree will use
 * idr_for_each() to free all objects, if necessay, then idr_destroy() to
 * free up the id mappings and cached idr_layers.
 */
void idr_destroy(struct idr *idr)
{
	void *p;
	unsigned id;

	idr_for_each_entry(idr, p, id)
		idr_remove(idr, id);

	ida_destroy(&idr->ida);
}
EXPORT_SYMBOL(idr_destroy);

/**
 * idr_init - initialize sparse idr handle
 * @idp:	idr handle
 *
 * This function is use to set up the handle (@idp) that you will pass
 * to the rest of the functions.
 */
void idr_init(struct idr *idr)
{
	ida_init(&idr->ida);
	INIT_RADIX_TREE(&idr->ptrs, GFP_NOWAIT);
}
EXPORT_SYMBOL(idr_init);
