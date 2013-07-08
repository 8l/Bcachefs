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
 * IDA completely rewritten by Kent Overstreet <koverstreet@google.com>
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

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/hardirq.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>

static void kgfree(void *ptr, size_t size)
{
	if (size < PAGE_SIZE)
		kfree(ptr);
	else
		free_pages((unsigned long) ptr, get_order(size));
}

static void *kgalloc(size_t size, gfp_t gfp)
{
	return size < PAGE_SIZE
		? kmalloc(size, gfp)
		: (void *) __get_free_pages(gfp, get_order(size));
}

/**
 * DOC: IDA description
 * IDA - ID (small integer) allocator
 *
 * This works much like using a simple bitmap to allocate indices - ida_alloc()
 * is equivalent to find_first_zero_bit() then __set_bit(), and ida_remove() is
 * equivalent to __clear_bit(). But it's much more efficient than a large
 * bitmap, and resizes itself as needed.
 *
 * It's implemented as a tree of bitmaps: a node in the tree is a single
 * unsigned long. The leaf nodes of the tree are segments of the entire bitmap -
 * a cleared bit indicates a free id, and a set bit indicates an allocated one.
 * Bits in the parent nodes indicate whether or not there are free bits in the
 * corresponding child node - when all the bits in a parent node are set, none
 * of its children have bits free.
 *
 * The splay factor of the tree (IDA_TREE_ARY) == BITS_PER_LONG - parent nodes
 * have 32 or 64 children.
 *
 * The tree itself is implemented with an array instead of pointers - exactly
 * like the textbook implementation of D-ary heaps. The root of the bitmap tree
 * is at ida->tree[0]. The children of node i are at i * IDA_TREE_ARY + 1 + j,
 * where j is in the range [0, 63], and the parent of node i is at (i - 1) /
 * IDA_TREE_ARY.
 *
 * This conveniently means that our leaf nodes are all contiguous in memory -
 * the bit for id i is bit id % BITS_PER_LONG in ida->tree[ida->first_leaf + i /
 * BITS_PER_LONG].
 *
 * Note that the number of ids we can allocate is limited by the amount of
 * memory we can contiguously allocate. The amount of memory used for the bitmap
 * tree is only slightly more than a flat bitmap would use - about 1 / TREE_ARY
 * * (sizeof flat bitmap).
 *
 * So for 1 mb of memory (and allocating more than that should be fine with
 * CONFIG_COMPACTION) you get slightly under 8 million IDs.
 */

#define IDA_TREE_ARY		BITS_PER_LONG
#define IDA_ALLOC_ORDER_MAX	4
#define IDA_SECTION_SIZE	(PAGE_SIZE << IDA_ALLOC_ORDER_MAX)
#define IDA_NODES_PER_SECTION	(IDA_SECTION_SIZE / sizeof(unsigned long))

static inline unsigned long *ida_index_to_node(struct ida *ida, unsigned node)
{
	return ida->tree[node / IDA_NODES_PER_SECTION] +
		node % IDA_NODES_PER_SECTION;
}

/*
 * For a given number of nodes, calculate how many are going to be parent nodes
 * (equal to ida->first_leaf) and by extension how my will be leaves.
 */
static unsigned first_leaf_from_nodes(unsigned nodes)
{
	unsigned ret = 0;

	while (ret * IDA_TREE_ARY + 1 < nodes)
		ret = ret * IDA_TREE_ARY + 1;

	return ret;
}

static void __ida_remove(struct ida *ida, unsigned int id)
{
	unsigned i = ida->first_leaf + id / BITS_PER_LONG;
	unsigned bit = id % BITS_PER_LONG;

	if (WARN(i >= ida->nodes,
		 "Tried to free an id outside the range of allocated ids\n"))
		return;

	--ida->allocated_ids;

	while (1) {
		unsigned long *node = ida_index_to_node(ida, i), old = *node;

		WARN(!test_bit(bit, node),
		     "Tried to free an id that was already free\n");
		__clear_bit(bit, node);

		if (~old || !i)
			break;

		/*
		 * If this node's bits were all 1s before we cleared this bit,
		 * we need to clear this node's bit in the parent node - and so
		 * on up to the root.
		 */

		bit = (i - 1) % IDA_TREE_ARY;
		i = (i - 1) / IDA_TREE_ARY;
	}
}

/**
 * ida_remove - remove an allocated id.
 * @ida: the (initialized) ida.
 * @id: the id returned by ida_alloc_range.
 */
void ida_remove(struct ida *ida, unsigned int id)
{
	unsigned long flags;
	spin_lock_irqsave(&ida->lock, flags);
	__ida_remove(ida, id);
	spin_unlock_irqrestore(&ida->lock, flags);
}
EXPORT_SYMBOL(ida_remove);

static void ida_increase_depth(struct ida *ida, unsigned new_nodes,
			       unsigned new_first_leaf)
{
	unsigned old_leaves = ida->nodes - ida->first_leaf;
	unsigned src = ida->nodes;
	unsigned dst = new_first_leaf + old_leaves;
	unsigned n, i, bit;
	unsigned long *node;

	/* Shift leaves up to new position */
	while (src != ida->first_leaf) {
		i = min((src - 1) % IDA_NODES_PER_SECTION + 1,
			(dst - 1) % IDA_NODES_PER_SECTION + 1);

		i = min(i, src - ida->first_leaf);

		src -= i;
		dst -= i;

		memmove(ida_index_to_node(ida, dst),
			ida_index_to_node(ida, src),
			i * sizeof(unsigned long));
	}

	/* Zero out parent nodes */
	for (n = 0; n < new_first_leaf; n += i) {
		i = min_t(unsigned, new_first_leaf - n,
			  IDA_NODES_PER_SECTION);

		memset(ida_index_to_node(ida, n),
		       0, i * sizeof(unsigned long));
	}

	/* Reconstruct parent nodes */
	for (n = new_first_leaf; n < new_first_leaf + old_leaves; n++) {
		i = n;
		node = ida_index_to_node(ida, i);

		while (!~*node && i) {
			bit = (i - 1) % IDA_TREE_ARY;
			i = (i - 1) / IDA_TREE_ARY;

			node = ida_index_to_node(ida, i);
			__set_bit(bit, node);
		}
	}
}

/*
 * Attempt to double the size of the tree. We have to drop ida->lock to allocate
 * memory, so we might race with another allocation that also tries to resize.
 * So if the tree's not the size it originally was when we retake ida->lock,
 * just return 0 - but the caller needs to recheck for the tree being full in
 * case we _really_ raced badly.
 */
static int __ida_resize(struct ida *ida, gfp_t gfp, unsigned long *flags)
	__releases(&ida->lock)
	__acquires(&ida->lock)
{
	unsigned long *tree, **sections;
	unsigned cur_nodes, new_nodes, new_first_leaf, cur_sections;
again:
	cur_nodes = ida->nodes;

	new_nodes = roundup_pow_of_two(ida->nodes + 1) <= IDA_NODES_PER_SECTION
		? roundup_pow_of_two(ida->nodes + 1)
		: ida->nodes + IDA_NODES_PER_SECTION;

	new_first_leaf = first_leaf_from_nodes(new_nodes);

	sections = NULL;
	cur_sections = ida->sections;

	BUG_ON(ida->nodes > IDA_NODES_PER_SECTION &&
	       ida->nodes % IDA_NODES_PER_SECTION);

	spin_unlock_irqrestore(&ida->lock, *flags);

	if (ida->nodes >= IDA_NODES_PER_SECTION &&
	    is_power_of_2(cur_sections)) {
		sections = kgalloc(cur_sections * 2 * sizeof(unsigned long *),
				   __GFP_ZERO|gfp);
		if (!sections)
			goto err;
	}

	tree = kgalloc(min_t(size_t, new_nodes * sizeof(unsigned long),
			     IDA_SECTION_SIZE), __GFP_ZERO|gfp);
	if (!tree)
		goto err;

	spin_lock_irqsave(&ida->lock, *flags);

	if (cur_nodes != ida->nodes || cur_sections != ida->sections) {
		kgfree(sections, cur_sections * 2 * sizeof(unsigned long *));
		kgfree(tree, min_t(size_t, new_nodes * sizeof(unsigned long),
				   IDA_SECTION_SIZE));
		return 0;
	}

	if (sections) {
		memcpy(sections, ida->tree,
		       ida->sections  * sizeof(unsigned long *));

		if (ida->tree != &ida->inline_section)
			kgfree(ida->tree,
			       ida->sections * sizeof(unsigned long *));

		ida->tree = sections;
	}

	if (ida->nodes < IDA_NODES_PER_SECTION) {
		memcpy(tree, ida_index_to_node(ida, 0),
		       ida->nodes * sizeof(unsigned long));

		if (ida->tree[0] != &ida->inline_node)
			kgfree(ida->tree[0],
			       ida->nodes * sizeof(unsigned long));

		ida->tree[0] = tree;
	} else {
		ida->tree[ida->sections++] = tree;

		new_nodes = ida->sections * IDA_NODES_PER_SECTION;
		new_first_leaf = first_leaf_from_nodes(new_nodes);

		if (new_nodes - new_first_leaf < ida->nodes - ida->first_leaf)
			goto again;
	}

	if (new_first_leaf != ida->first_leaf)
		ida_increase_depth(ida, new_nodes, new_first_leaf);

	ida->nodes	= new_nodes;
	ida->first_leaf	= new_first_leaf;

	return 0;
err:
	kgfree(sections, cur_sections * 2 * sizeof(unsigned long));
	spin_lock_irqsave(&ida->lock, *flags);
	return -ENOMEM;
}

/*
 * Ganged allocation - amortize locking and tree traversal for when we've got
 * another allocator (i.e. a percpu version) acting as a frontend to this code
 */
static int __ida_alloc_range_multiple(struct ida *ida, unsigned *ids,
				      unsigned nr_ids, unsigned min_id,
				      unsigned max_id, gfp_t gfp,
				      unsigned long *flags)
	__releases(&ida->lock)
	__acquires(&ida->lock)
{
	unsigned i = 0, bit, bit_offset, id, ids_found = 0;
	unsigned long *node = ida_index_to_node(ida, i);
	int err = 0;

	if (!max_id || max_id > (unsigned) INT_MAX + 1)
		max_id = (unsigned) INT_MAX + 1;

	if (min_id >= max_id)
		return -ENOSPC;

	while (ids_found < nr_ids) {
		/*
		 * If all bits are set in the root, no bits free and we need to
		 * resize.
		 */
		while (!~*node) {
resize:
			if (ida->nodes - ida->first_leaf >=
			    BITS_TO_LONGS(max_id)) {
				err = -ENOSPC;
				goto err;
			}

			err = __ida_resize(ida, gfp, flags);
			if (err)
				goto err;

			i = 0;
			node = ida_index_to_node(ida, i);
		}

		if (min_id) {
			/*
			 * If we're starting from a specific index, skip to that
			 * leaf node and start looking there:
			 */
			bit_offset = min_id % BITS_PER_LONG;
			i = ida->first_leaf + min_id / BITS_PER_LONG;

			if (i >= ida->nodes)
				goto resize;

			while (1) {
				node = ida_index_to_node(ida, i);
				bit = ffz(*node >> bit_offset) + bit_offset;

				/*
				 * We might have had to go back up the tree
				 * before we found a free bit - so skip down to
				 * where we recurse down the tree.
				 */
				if (~*node && bit < BITS_PER_LONG)
					goto found;

				if (!i)
					goto resize;

				/*
				 * Ok, no bits available in this node - go up a
				 * level. But we have to update bit_offset so we
				 * start searching in the parent _after_ the
				 * node we're currently at
				 */
				bit_offset = (i - 1) % IDA_TREE_ARY + 1;
				i = (i - 1) / IDA_TREE_ARY;
			}
		}

		/*
		 * Recurse down the tree looking for a free bit. We already
		 * checked to make sure there _were_ free bits, but we might end
		 * up at a leaf node we haven't allocated yet.
		 */
		while (1) {
			bit = ffz(*node);
found:
			/*
			 * Found a bit - if we're at a leaf node, great! We're
			 * done:
			 */
			if (i >= ida->first_leaf)
				break;

			i = i * IDA_TREE_ARY + 1 + bit;
			node = ida_index_to_node(ida, i);

			/*
			 * Recurse. But if we'd recurse to a node that hasn't
			 * been allocated yet, resize:
			 */

			if (i >= ida->nodes)
				goto resize;

			BUG_ON(!~*node);
		}

		/*
		 * Our leaves are contiguous, so we can calculate the id we
		 * allocated from the node we're at and the bit we found within
		 * that node:
		 */
		id = (i - ida->first_leaf) * BITS_PER_LONG + bit;
		BUG_ON(id < min_id);

		if (id >= max_id) {
			err = -ENOSPC;
			goto err;
		}

		ids[ids_found++] = id;
		ida->allocated_ids++;

		/*
		 * Mark the id as allocated. If all the bits are now set in this
		 * node, set this node's bit in the parent node - and so on up
		 * to the root:
		 */
		while (1) {
			__set_bit(bit, node);

			if (~*node || !i)
				break;

			bit = (i - 1) % IDA_TREE_ARY;
			i = (i - 1) / IDA_TREE_ARY;

			node = ida_index_to_node(ida, i);
		}
	}
err:
	return ids_found ? ids_found : err;
}

/**
 * ida_alloc_range - allocate a new id.
 * @ida: the (initialized) ida.
 * @start: the minimum id (inclusive, <= INT_MAX)
 * @end: the maximum id (exclusive, <= INT_MAX + 1 or 0 for unlimited)
 * @gfp: memory allocation flags
 *
 * Allocates an id in the range [start, end). Returns -ENOSPC if no ids are
 * available, or -ENOMEM on memory allocation failure.
 *
 * Returns the smallest free id >= start.
 *
 * Use ida_remove() to get rid of an id.
 */
int ida_alloc_range(struct ida *ida, unsigned int start,
		    unsigned int end, gfp_t gfp)
{
	int ret;
	unsigned id;
	unsigned long flags;

	spin_lock_irqsave(&ida->lock, flags);
	ret = __ida_alloc_range_multiple(ida, &id, 1, start, end, gfp, &flags);
	spin_unlock_irqrestore(&ida->lock, flags);

	return ret == 1 ? id : ret;
}
EXPORT_SYMBOL(ida_alloc_range);

static int __ida_alloc_cyclic(struct ida *ida, unsigned start, unsigned end,
			      gfp_t gfp, unsigned long *flags)
	__releases(&ida->lock)
	__acquires(&ida->lock)
{
	int ret;
	unsigned id;

	ret = __ida_alloc_range_multiple(ida, &id, 1,
					 max(start, ida->cur_id),
					 end, gfp, flags);

	if (ret < 0)
		ret = __ida_alloc_range_multiple(ida, &id, 1, start,
						 end, gfp, flags);
	if (ret == 1) {
		ida->cur_id = id + 1;
		if ((ida->cur_id - start) / 2 > max(1024U, ida->allocated_ids))
			ida->cur_id = 0;

		return id;
	}

	return ret;
}

/**
 * ida_alloc_cyclic - allocate new ids cyclically
 * @ida: the (initialized) ida.
 * @start: the minimum id (inclusive, <= INT_MAX)
 * @end: the maximum id (exclusive, <= INT_MAX + 1 or 0 for unlimited)
 * @gfp: memory allocation flags
 *
 * Allocates an id in the range start <= id < end, or returns -ENOSPC.
 * On memory allocation failure, returns -ENOMEM.
 *
 * Instead of returning the smallest free id, start searching from the position
 * where the last id was allocated - i.e. it won't reuse freed ids right away.
 *
 * To avoid the allocated id space (and internal bitmap) becoming arbitrarily
 * sparse, it can wrap before reaching the maximum id - if less than half of our
 * current id space is allocated, it resets cur_id to 0
 *
 * But we don't want to wrap when the id space is small, so we use the maximum
 * of (1024, allocated_ids) - see __ida_alloc_cyclic().
 *
 * Use ida_remove() to get rid of an id.
 */
int ida_alloc_cyclic(struct ida *ida, unsigned start, unsigned end, gfp_t gfp)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&ida->lock, flags);
	ret = __ida_alloc_cyclic(ida, start, end, gfp, &flags);
	spin_unlock_irqrestore(&ida->lock, flags);

	return ret;
}
EXPORT_SYMBOL(ida_alloc_cyclic);

/**
 * ida_destroy - release all cached layers within an ida tree
 * @ida:		ida handle
 */
void ida_destroy(struct ida *ida)
{
	unsigned i;

	if (ida->tree[0] &&
	    ida->tree[0] != &ida->inline_node)
		kgfree(ida->tree[0], min(ida->nodes * sizeof(unsigned long),
					 IDA_SECTION_SIZE));

	for (i = 1; i < ida->sections; i++)
		kgfree(ida->tree[i], IDA_SECTION_SIZE);

	if (ida->tree &&
	    ida->tree != &ida->inline_section)
		kgfree(ida->tree, roundup_pow_of_two(ida->sections) *
		       sizeof(unsigned long *));
}
EXPORT_SYMBOL(ida_destroy);

/**
 * ida_init_prealloc - initialize ida handle
 * @ida:	ida handle
 * @prealloc:	number of ids to preallocate memory for
 *
 * Initialize an ida, and preallocate enough memory that ida_alloc() will never
 * return -ENOMEM if passed max_id <= prealloc.
 */
int ida_init_prealloc(struct ida *ida, unsigned prealloc)
{
	unsigned leaves = BITS_TO_LONGS(prealloc);

	memset(ida, 0, sizeof(*ida));

	spin_lock_init(&ida->lock);

	ida->nodes		= 1;
	ida->first_leaf		= 0;
	ida->sections		= 1;
	ida->inline_section	= &ida->inline_node;
	ida->tree		= &ida->inline_section;

	if (leaves > ida->nodes - ida->first_leaf) {
		unsigned i;

		while (leaves > ida->nodes - ida->first_leaf) {
			if (ida->nodes < IDA_NODES_PER_SECTION)
				ida->nodes *= 2;
			else
				ida->nodes += IDA_NODES_PER_SECTION;

			ida->first_leaf = first_leaf_from_nodes(ida->nodes);
		}

		if (ida->nodes > IDA_NODES_PER_SECTION) {
			ida->sections = ida->nodes / IDA_NODES_PER_SECTION;
			ida->tree = kgalloc(roundup_pow_of_two(ida->sections) *
					    sizeof(unsigned long *),
					    __GFP_ZERO|GFP_KERNEL);
			if (!ida->tree)
				return -ENOMEM;

			for (i = 0; i < ida->sections; i++) {
				ida->tree[i] = kgalloc(IDA_SECTION_SIZE,
						       __GFP_ZERO|GFP_KERNEL);
				if (!ida->tree[i])
					goto err;
			}
		} else {
			ida->tree[0] =
				kgalloc(ida->nodes * sizeof(unsigned long),
					__GFP_ZERO|GFP_KERNEL);
			if (!ida->tree)
				return -ENOMEM;
		}
	}

	return 0;
err:
	ida_destroy(ida);
	return -ENOMEM;

}
EXPORT_SYMBOL(ida_init_prealloc);

/* Percpu IDA */

/*
 * Number of tags we move between the percpu freelist and the global freelist at
 * a time
 */
#define IDA_PCPU_BATCH_MOVE	32U

/* Max size of percpu freelist, */
#define IDA_PCPU_SIZE		((IDA_PCPU_BATCH_MOVE * 3) / 2)

struct percpu_ida_cpu {
	spinlock_t			lock;
	unsigned			nr_free;
	unsigned			freelist[];
};

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
 */
static inline void steal_tags(struct percpu_ida *pool,
			      struct percpu_ida_cpu *tags)
{
	unsigned cpus_have_tags, cpu = pool->cpu_last_stolen;
	struct percpu_ida_cpu *remote;

	for (cpus_have_tags = bitmap_weight(pool->cpus_have_tags, nr_cpu_ids);
	     cpus_have_tags * IDA_PCPU_SIZE > pool->nr_tags / 2;
	     cpus_have_tags--) {
		cpu = find_next_bit(pool->cpus_have_tags, nr_cpu_ids, cpu);

		if (cpu == nr_cpu_ids)
			cpu = find_first_bit(pool->cpus_have_tags, nr_cpu_ids);

		if (cpu == nr_cpu_ids)
			BUG();

		pool->cpu_last_stolen = cpu;
		remote = per_cpu_ptr(pool->tag_cpu, cpu);

		clear_bit(cpu, pool->cpus_have_tags);

		if (remote == tags)
			continue;

		spin_lock(&remote->lock);

		if (remote->nr_free) {
			memcpy(tags->freelist,
			       remote->freelist,
			       sizeof(unsigned) * remote->nr_free);

			tags->nr_free = remote->nr_free;
			remote->nr_free = 0;
		}

		spin_unlock(&remote->lock);

		if (tags->nr_free)
			break;
	}
}

static inline void alloc_global_tags(struct percpu_ida *pool,
				     struct percpu_ida_cpu *tags)
{
	int nr_free = __ida_alloc_range_multiple(&pool->ida, tags->freelist,
						 IDA_PCPU_BATCH_MOVE, 0,
						 pool->nr_tags, GFP_NOWAIT,
						 NULL);
	if (nr_free > 0)
		tags->nr_free = nr_free;
}

static inline unsigned alloc_local_tag(struct percpu_ida *pool,
				       struct percpu_ida_cpu *tags)
{
	int tag = -ENOSPC;

	spin_lock(&tags->lock);
	if (tags->nr_free)
		tag = tags->freelist[--tags->nr_free];
	spin_unlock(&tags->lock);

	return tag;
}

/**
 * percpu_ida_alloc - allocate a tag
 * @pool: pool to allocate from
 * @gfp: gfp flags
 *
 * Returns a tag - an integer in the range [0..nr_tags) (passed to
 * tag_pool_init()), or otherwise -ENOSPC on allocation failure.
 *
 * Safe to be called from interrupt context (assuming it isn't passed
 * __GFP_WAIT, of course).
 *
 * Will not fail if passed __GFP_WAIT.
 */
int percpu_ida_alloc(struct percpu_ida *pool, gfp_t gfp)
{
	DEFINE_WAIT(wait);
	struct percpu_ida_cpu *tags;
	unsigned long flags;
	unsigned this_cpu;
	int tag;

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	tags = per_cpu_ptr(pool->tag_cpu, this_cpu);

	/* Fastpath */
	tag = alloc_local_tag(pool, tags);
	if (likely(tag >= 0)) {
		local_irq_restore(flags);
		return tag;
	}

	while (1) {
		spin_lock(&pool->ida.lock);

		/*
		 * prepare_to_wait() must come before steal_tags(), in case
		 * percpu_ida_free() on another cpu flips a bit in
		 * cpus_have_tags
		 *
		 * global lock held and irqs disabled, don't need percpu lock
		 */
		prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);

		if (!tags->nr_free)
			alloc_global_tags(pool, tags);
		if (!tags->nr_free)
			steal_tags(pool, tags);

		if (tags->nr_free) {
			tag = tags->freelist[--tags->nr_free];
			if (tags->nr_free)
				set_bit(this_cpu, pool->cpus_have_tags);
		}

		spin_unlock(&pool->ida.lock);
		local_irq_restore(flags);

		if (tag >= 0 || !(gfp & __GFP_WAIT))
			break;

		schedule();

		local_irq_save(flags);
		this_cpu = smp_processor_id();
		tags = per_cpu_ptr(pool->tag_cpu, this_cpu);
	}

	finish_wait(&pool->wait, &wait);
	return tag;
}
EXPORT_SYMBOL_GPL(percpu_ida_alloc);

/**
 * percpu_ida_free - free a tag
 * @pool: pool @tag was allocated from
 * @tag: a tag previously allocated with percpu_ida_alloc()
 *
 * Safe to be called from interrupt context.
 */
void percpu_ida_free(struct percpu_ida *pool, unsigned tag)
{
	struct percpu_ida_cpu *tags;
	unsigned long flags;
	unsigned nr_free, this_cpu;

	BUG_ON(tag >= pool->nr_tags);

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	tags = per_cpu_ptr(pool->tag_cpu, this_cpu);

	spin_lock(&tags->lock);
	tags->freelist[tags->nr_free++] = tag;

	nr_free = tags->nr_free;
	spin_unlock(&tags->lock);

	if (nr_free == 1) {
		set_bit(this_cpu, pool->cpus_have_tags);
		wake_up(&pool->wait);
	}

	if (nr_free == IDA_PCPU_SIZE) {
		spin_lock(&pool->ida.lock);

		/*
		 * Global lock held and irqs disabled, don't need percpu
		 * lock
		 */
		while (tags->nr_free > IDA_PCPU_SIZE - IDA_PCPU_BATCH_MOVE)
			__ida_remove(&pool->ida,
				     tags->freelist[--tags->nr_free]);

		wake_up(&pool->wait);
		spin_unlock(&pool->ida.lock);
	}

	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(percpu_ida_free);

/**
 * percpu_ida_destroy - release a tag pool's resources
 * @pool: pool to free
 *
 * Frees the resources allocated by percpu_ida_init().
 */
void percpu_ida_destroy(struct percpu_ida *pool)
{
	free_percpu(pool->tag_cpu);
	kfree(pool->cpus_have_tags);
	ida_destroy(&pool->ida);
}
EXPORT_SYMBOL_GPL(percpu_ida_destroy);

/**
 * percpu_ida_init - initialize a percpu tag pool
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
int percpu_ida_init(struct percpu_ida *pool, unsigned long nr_tags)
{
	unsigned cpu;

	memset(pool, 0, sizeof(*pool));

	init_waitqueue_head(&pool->wait);
	pool->nr_tags = nr_tags;

	/* Guard against overflow */
	if (nr_tags > (unsigned) INT_MAX + 1) {
		pr_err("tags.c: nr_tags too large\n");
		return -EINVAL;
	}

	if (ida_init_prealloc(&pool->ida, nr_tags))
		return -ENOMEM;

	pool->cpus_have_tags = kzalloc(BITS_TO_LONGS(nr_cpu_ids) *
				       sizeof(unsigned long), GFP_KERNEL);
	if (!pool->cpus_have_tags)
		goto err;

	pool->tag_cpu = __alloc_percpu(sizeof(struct percpu_ida_cpu) +
				       IDA_PCPU_SIZE * sizeof(unsigned),
				       sizeof(unsigned));
	if (!pool->tag_cpu)
		goto err;

	for_each_possible_cpu(cpu)
		spin_lock_init(&per_cpu_ptr(pool->tag_cpu, cpu)->lock);

	return 0;
err:
	percpu_ida_destroy(pool);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(percpu_ida_init);

/* IDR */

#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
#define MAX_IDR_BIT		(1U << MAX_IDR_SHIFT)

/* Leave the possibility of an incomplete final layer */
#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)

/* Number of id_layer structs to leave in free list */
#define MAX_IDR_FREE (MAX_IDR_LEVEL * 2)

static struct kmem_cache *idr_layer_cache;
static DEFINE_PER_CPU(struct idr_layer *, idr_preload_head);
static DEFINE_PER_CPU(int, idr_preload_cnt);

/* the maximum ID which can be allocated given idr->layers */
static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);

	return (1 << bits) - 1;
}

/*
 * Prefix mask for an idr_layer at @layer.  For layer 0, the prefix mask is
 * all bits except for the lower IDR_BITS.  For layer 1, 2 * IDR_BITS, and
 * so on.
 */
static int idr_layer_prefix_mask(int layer)
{
	return ~idr_max(layer + 1);
}

static struct idr_layer *get_from_free_list(struct idr *idp)
{
	struct idr_layer *p;
	unsigned long flags;

	spin_lock_irqsave(&idp->lock, flags);
	if ((p = idp->id_free)) {
		idp->id_free = p->ary[0];
		idp->id_free_cnt--;
		p->ary[0] = NULL;
	}
	spin_unlock_irqrestore(&idp->lock, flags);
	return(p);
}

/**
 * idr_layer_alloc - allocate a new idr_layer
 * @gfp_mask: allocation mask
 * @layer_idr: optional idr to allocate from
 *
 * If @layer_idr is %NULL, directly allocate one using @gfp_mask or fetch
 * one from the per-cpu preload buffer.  If @layer_idr is not %NULL, fetch
 * an idr_layer from @idr->id_free.
 *
 * @layer_idr is to maintain backward compatibility with the old alloc
 * interface - idr_pre_get() and idr_get_new*() - and will be removed
 * together with per-pool preload buffer.
 */
static struct idr_layer *idr_layer_alloc(gfp_t gfp_mask, struct idr *layer_idr)
{
	struct idr_layer *new;

	/* this is the old path, bypass to get_from_free_list() */
	if (layer_idr)
		return get_from_free_list(layer_idr);

	/*
	 * Try to allocate directly from kmem_cache.  We want to try this
	 * before preload buffer; otherwise, non-preloading idr_alloc()
	 * users will end up taking advantage of preloading ones.  As the
	 * following is allowed to fail for preloaded cases, suppress
	 * warning this time.
	 */
	new = kmem_cache_zalloc(idr_layer_cache, gfp_mask | __GFP_NOWARN);
	if (new)
		return new;

	/*
	 * Try to fetch one from the per-cpu preload buffer if in process
	 * context.  See idr_preload() for details.
	 */
	if (!in_interrupt()) {
		preempt_disable();
		new = __this_cpu_read(idr_preload_head);
		if (new) {
			__this_cpu_write(idr_preload_head, new->ary[0]);
			__this_cpu_dec(idr_preload_cnt);
			new->ary[0] = NULL;
		}
		preempt_enable();
		if (new)
			return new;
	}

	/*
	 * Both failed.  Try kmem_cache again w/o adding __GFP_NOWARN so
	 * that memory allocation failure warning is printed as intended.
	 */
	return kmem_cache_zalloc(idr_layer_cache, gfp_mask);
}

static void idr_layer_rcu_free(struct rcu_head *head)
{
	struct idr_layer *layer;

	layer = container_of(head, struct idr_layer, rcu_head);
	kmem_cache_free(idr_layer_cache, layer);
}

static inline void free_layer(struct idr *idr, struct idr_layer *p)
{
	if (idr->hint && idr->hint == p)
		RCU_INIT_POINTER(idr->hint, NULL);
	call_rcu(&p->rcu_head, idr_layer_rcu_free);
}

/* only called when idp->lock is held */
static void __move_to_free_list(struct idr *idp, struct idr_layer *p)
{
	p->ary[0] = idp->id_free;
	idp->id_free = p;
	idp->id_free_cnt++;
}

static void move_to_free_list(struct idr *idp, struct idr_layer *p)
{
	unsigned long flags;

	/*
	 * Depends on the return element being zeroed.
	 */
	spin_lock_irqsave(&idp->lock, flags);
	__move_to_free_list(idp, p);
	spin_unlock_irqrestore(&idp->lock, flags);
}

static void idr_mark_full(struct idr_layer **pa, int id)
{
	struct idr_layer *p = pa[0];
	int l = 0;

	__set_bit(id & IDR_MASK, p->bitmap);
	/*
	 * If this layer is full mark the bit in the layer above to
	 * show that this part of the radix tree is full.  This may
	 * complete the layer above and require walking up the radix
	 * tree.
	 */
	while (bitmap_full(p->bitmap, IDR_SIZE)) {
		if (!(p = pa[++l]))
			break;
		id = id >> IDR_BITS;
		__set_bit((id & IDR_MASK), p->bitmap);
	}
}

/**
 * sub_alloc - try to allocate an id without growing the tree depth
 * @idp: idr handle
 * @starting_id: id to start search at
 * @pa: idr_layer[MAX_IDR_LEVEL] used as backtrack buffer
 * @gfp_mask: allocation mask for idr_layer_alloc()
 * @layer_idr: optional idr passed to idr_layer_alloc()
 *
 * Allocate an id in range [@starting_id, INT_MAX] from @idp without
 * growing its depth.  Returns
 *
 *  the allocated id >= 0 if successful,
 *  -EAGAIN if the tree needs to grow for allocation to succeed,
 *  -ENOSPC if the id space is exhausted,
 *  -ENOMEM if more idr_layers need to be allocated.
 */
static int sub_alloc(struct idr *idp, int *starting_id, struct idr_layer **pa,
		     gfp_t gfp_mask, struct idr *layer_idr)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	int l, id, oid;

	id = *starting_id;
 restart:
	p = idp->top;
	l = idp->layers;
	pa[l--] = NULL;
	while (1) {
		/*
		 * We run around this while until we reach the leaf node...
		 */
		n = (id >> (IDR_BITS*l)) & IDR_MASK;
		m = find_next_zero_bit(p->bitmap, IDR_SIZE, n);
		if (m == IDR_SIZE) {
			/* no space available go back to previous layer. */
			l++;
			oid = id;
			id = (id | ((1 << (IDR_BITS * l)) - 1)) + 1;

			/* if already at the top layer, we need to grow */
			if (id >= 1 << (idp->layers * IDR_BITS)) {
				*starting_id = id;
				return -EAGAIN;
			}
			p = pa[l];
			BUG_ON(!p);

			/* If we need to go up one layer, continue the
			 * loop; otherwise, restart from the top.
			 */
			sh = IDR_BITS * (l + 1);
			if (oid >> sh == id >> sh)
				continue;
			else
				goto restart;
		}
		if (m != n) {
			sh = IDR_BITS*l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}
		if ((id >= MAX_IDR_BIT) || (id < 0))
			return -ENOSPC;
		if (l == 0)
			break;
		/*
		 * Create the layer below if it is missing.
		 */
		if (!p->ary[m]) {
			new = idr_layer_alloc(gfp_mask, layer_idr);
			if (!new)
				return -ENOMEM;
			new->layer = l-1;
			new->prefix = id & idr_layer_prefix_mask(new->layer);
			rcu_assign_pointer(p->ary[m], new);
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}

	pa[l] = p;
	return id;
}

static int idr_get_empty_slot(struct idr *idp, int starting_id,
			      struct idr_layer **pa, gfp_t gfp_mask,
			      struct idr *layer_idr)
{
	struct idr_layer *p, *new;
	int layers, v, id;
	unsigned long flags;

	id = starting_id;
build_up:
	p = idp->top;
	layers = idp->layers;
	if (unlikely(!p)) {
		if (!(p = idr_layer_alloc(gfp_mask, layer_idr)))
			return -ENOMEM;
		p->layer = 0;
		layers = 1;
	}
	/*
	 * Add a new layer to the top of the tree if the requested
	 * id is larger than the currently allocated space.
	 */
	while (id > idr_max(layers)) {
		layers++;
		if (!p->count) {
			/* special case: if the tree is currently empty,
			 * then we grow the tree by moving the top node
			 * upwards.
			 */
			p->layer++;
			WARN_ON_ONCE(p->prefix);
			continue;
		}
		if (!(new = idr_layer_alloc(gfp_mask, layer_idr))) {
			/*
			 * The allocation failed.  If we built part of
			 * the structure tear it down.
			 */
			spin_lock_irqsave(&idp->lock, flags);
			for (new = p; p && p != idp->top; new = p) {
				p = p->ary[0];
				new->ary[0] = NULL;
				new->count = 0;
				bitmap_clear(new->bitmap, 0, IDR_SIZE);
				__move_to_free_list(idp, new);
			}
			spin_unlock_irqrestore(&idp->lock, flags);
			return -ENOMEM;
		}
		new->ary[0] = p;
		new->count = 1;
		new->layer = layers-1;
		new->prefix = id & idr_layer_prefix_mask(new->layer);
		if (bitmap_full(p->bitmap, IDR_SIZE))
			__set_bit(0, new->bitmap);
		p = new;
	}
	rcu_assign_pointer(idp->top, p);
	idp->layers = layers;
	v = sub_alloc(idp, &id, pa, gfp_mask, layer_idr);
	if (v == -EAGAIN)
		goto build_up;
	return(v);
}

/*
 * @id and @pa are from a successful allocation from idr_get_empty_slot().
 * Install the user pointer @ptr and mark the slot full.
 */
static void idr_fill_slot(struct idr *idr, void *ptr, int id,
			  struct idr_layer **pa)
{
	/* update hint used for lookup, cleared from free_layer() */
	rcu_assign_pointer(idr->hint, pa[0]);

	rcu_assign_pointer(pa[0]->ary[id & IDR_MASK], (struct idr_layer *)ptr);
	pa[0]->count++;
	idr_mark_full(pa, id);
}

/**
 * idr_preload - preload for idr_alloc()
 * @gfp_mask: allocation mask to use for preloading
 *
 * Preload per-cpu layer buffer for idr_alloc().  Can only be used from
 * process context and each idr_preload() invocation should be matched with
 * idr_preload_end().  Note that preemption is disabled while preloaded.
 *
 * The first idr_alloc() in the preloaded section can be treated as if it
 * were invoked with @gfp_mask used for preloading.  This allows using more
 * permissive allocation masks for idrs protected by spinlocks.
 *
 * For example, if idr_alloc() below fails, the failure can be treated as
 * if idr_alloc() were called with GFP_KERNEL rather than GFP_NOWAIT.
 *
 *	idr_preload(GFP_KERNEL);
 *	spin_lock(lock);
 *
 *	id = idr_alloc(idr, ptr, start, end, GFP_NOWAIT);
 *
 *	spin_unlock(lock);
 *	idr_preload_end();
 *	if (id < 0)
 *		error;
 */
void idr_preload(gfp_t gfp_mask)
{
	/*
	 * Consuming preload buffer from non-process context breaks preload
	 * allocation guarantee.  Disallow usage from those contexts.
	 */
	WARN_ON_ONCE(in_interrupt());
	might_sleep_if(gfp_mask & __GFP_WAIT);

	preempt_disable();

	/*
	 * idr_alloc() is likely to succeed w/o full idr_layer buffer and
	 * return value from idr_alloc() needs to be checked for failure
	 * anyway.  Silently give up if allocation fails.  The caller can
	 * treat failures from idr_alloc() as if idr_alloc() were called
	 * with @gfp_mask which should be enough.
	 */
	while (__this_cpu_read(idr_preload_cnt) < MAX_IDR_FREE) {
		struct idr_layer *new;

		preempt_enable();
		new = kmem_cache_zalloc(idr_layer_cache, gfp_mask);
		preempt_disable();
		if (!new)
			break;

		/* link the new one to per-cpu preload list */
		new->ary[0] = __this_cpu_read(idr_preload_head);
		__this_cpu_write(idr_preload_head, new);
		__this_cpu_inc(idr_preload_cnt);
	}
}
EXPORT_SYMBOL(idr_preload);

/**
 * idr_alloc - allocate new idr entry
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp_mask: memory allocation flags
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
int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	int max = end > 0 ? end - 1 : INT_MAX;	/* inclusive upper limit */
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	int id;

	might_sleep_if(gfp_mask & __GFP_WAIT);

	/* sanity checks */
	if (WARN_ON_ONCE(start < 0))
		return -EINVAL;
	if (unlikely(max < start))
		return -ENOSPC;

	/* allocate id */
	id = idr_get_empty_slot(idr, start, pa, gfp_mask, NULL);
	if (unlikely(id < 0))
		return id;
	if (unlikely(id > max))
		return -ENOSPC;

	idr_fill_slot(idr, ptr, id, pa);
	return id;
}
EXPORT_SYMBOL_GPL(idr_alloc);

/**
 * idr_alloc_cyclic - allocate new idr entry in a cyclical fashion
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp_mask: memory allocation flags
 *
 * Essentially the same as idr_alloc, but prefers to allocate progressively
 * higher ids if it can. If the "cur" counter wraps, then it will start again
 * at the "start" end of the range and allocate one that has already been used.
 */
int idr_alloc_cyclic(struct idr *idr, void *ptr, int start, int end,
			gfp_t gfp_mask)
{
	int id;

	id = idr_alloc(idr, ptr, max(start, idr->cur), end, gfp_mask);
	if (id == -ENOSPC)
		id = idr_alloc(idr, ptr, start, end, gfp_mask);

	if (likely(id >= 0))
		idr->cur = id + 1;
	return id;
}
EXPORT_SYMBOL(idr_alloc_cyclic);

static void idr_remove_warning(int id)
{
	WARN(1, "idr_remove called for id=%d which is not allocated.\n", id);
}

static void sub_remove(struct idr *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_IDR_LEVEL + 1];
	struct idr_layer ***paa = &pa[0];
	struct idr_layer *to_free;
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		__clear_bit(n, p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (likely(p != NULL && test_bit(n, p->bitmap))) {
		__clear_bit(n, p->bitmap);
		rcu_assign_pointer(p->ary[n], NULL);
		to_free = NULL;
		while(*paa && ! --((**paa)->count)){
			if (to_free)
				free_layer(idp, to_free);
			to_free = **paa;
			**paa-- = NULL;
		}
		if (!*paa)
			idp->layers = 0;
		if (to_free)
			free_layer(idp, to_free);
	} else
		idr_remove_warning(id);
}

/**
 * idr_remove - remove the given id and free its slot
 * @idp: idr handle
 * @id: unique key
 */
void idr_remove(struct idr *idp, int id)
{
	struct idr_layer *p;
	struct idr_layer *to_free;

	if (id < 0)
		return;

	sub_remove(idp, (idp->layers - 1) * IDR_BITS, id);
	if (idp->top && idp->top->count == 1 && (idp->layers > 1) &&
	    idp->top->ary[0]) {
		/*
		 * Single child at leftmost slot: we can shrink the tree.
		 * This level is not needed anymore since when layers are
		 * inserted, they are inserted at the top of the existing
		 * tree.
		 */
		to_free = idp->top;
		p = idp->top->ary[0];
		rcu_assign_pointer(idp->top, p);
		--idp->layers;
		to_free->count = 0;
		bitmap_clear(to_free->bitmap, 0, IDR_SIZE);
		free_layer(idp, to_free);
	}
	while (idp->id_free_cnt >= MAX_IDR_FREE) {
		p = get_from_free_list(idp);
		/*
		 * Note: we don't call the rcu callback here, since the only
		 * layers that fall into the freelist are those that have been
		 * preallocated.
		 */
		kmem_cache_free(idr_layer_cache, p);
	}
	return;
}
EXPORT_SYMBOL(idr_remove);

static void __idr_remove_all(struct idr *idp)
{
	int n, id, max;
	int bt_mask;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	p = idp->top;
	rcu_assign_pointer(idp->top, NULL);
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		while (n > IDR_BITS && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = p->ary[(id >> n) & IDR_MASK];
		}

		bt_mask = id;
		id += 1 << n;
		/* Get the highest bit that the above add changed from 0->1. */
		while (n < fls(id ^ bt_mask)) {
			if (p)
				free_layer(idp, p);
			n += IDR_BITS;
			p = *--paa;
		}
	}
	idp->layers = 0;
}

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
void idr_destroy(struct idr *idp)
{
	__idr_remove_all(idp);

	while (idp->id_free_cnt) {
		struct idr_layer *p = get_from_free_list(idp);
		kmem_cache_free(idr_layer_cache, p);
	}
}
EXPORT_SYMBOL(idr_destroy);

void *idr_find_slowpath(struct idr *idp, int id)
{
	int n;
	struct idr_layer *p;

	if (id < 0)
		return NULL;

	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer+1) * IDR_BITS;

	if (id > idr_max(p->layer + 1))
		return NULL;
	BUG_ON(n == 0);

	while (n > 0 && p) {
		n -= IDR_BITS;
		BUG_ON(n != p->layer*IDR_BITS);
		p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
	}
	return((void *)p);
}
EXPORT_SYMBOL(idr_find_slowpath);

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
int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data)
{
	int n, id, max, error = 0;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	p = rcu_dereference_raw(idp->top);
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			error = fn(id, (void *)p, data);
			if (error)
				break;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}

	return error;
}
EXPORT_SYMBOL(idr_for_each);

/**
 * idr_get_next - lookup next object of id to given id.
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
void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer + 1) * IDR_BITS;
	max = idr_max(p->layer + 1);

	while (id >= 0 && id <= max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		/*
		 * Proceed to the next layer at the current level.  Unlike
		 * idr_for_each(), @id isn't guaranteed to be aligned to
		 * layer boundary at this point and adding 1 << n may
		 * incorrectly skip IDs.  Make sure we jump to the
		 * beginning of the next layer using round_up().
		 */
		id = round_up(id + 1, 1 << n);
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(idr_get_next);


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
void *idr_replace(struct idr *idp, void *ptr, int id)
{
	int n;
	struct idr_layer *p, *old_p;

	if (id < 0)
		return ERR_PTR(-EINVAL);

	p = idp->top;
	if (!p)
		return ERR_PTR(-EINVAL);

	n = (p->layer+1) * IDR_BITS;

	if (id >= (1 << n))
		return ERR_PTR(-EINVAL);

	n -= IDR_BITS;
	while ((n > 0) && p) {
		p = p->ary[(id >> n) & IDR_MASK];
		n -= IDR_BITS;
	}

	n = id & IDR_MASK;
	if (unlikely(p == NULL || !test_bit(n, p->bitmap)))
		return ERR_PTR(-ENOENT);

	old_p = p->ary[n];
	rcu_assign_pointer(p->ary[n], ptr);

	return old_p;
}
EXPORT_SYMBOL(idr_replace);

void __init idr_init_cache(void)
{
	idr_layer_cache = kmem_cache_create("idr_layer_cache",
				sizeof(struct idr_layer), 0, SLAB_PANIC, NULL);
}

/**
 * idr_init - initialize idr handle
 * @idp:	idr handle
 *
 * This function is use to set up the handle (@idp) that you will pass
 * to the rest of the functions.
 */
void idr_init(struct idr *idp)
{
	memset(idp, 0, sizeof(struct idr));
	spin_lock_init(&idp->lock);
}
EXPORT_SYMBOL(idr_init);
