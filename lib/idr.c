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
 * Completely rewritten by Kent Overstreet <koverstreet@google.com>.
 *
 * id allocator (scalable/resizable bitmap, essentially), and also idr which
 * combines ida with a radix tree to map pointers to small integers for you.
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
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

static int ida_preload(struct ida *ida, unsigned start, gfp_t gfp)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&ida->lock, flags);

	while (!ret &&
	       (ida->nodes - ida->first_leaf * BITS_PER_LONG <
		start + ida->allocated_ids + num_possible_cpus()))
		ret = __ida_resize(ida, gfp, &flags);

	spin_unlock_irqrestore(&ida->lock, flags);

	return ret;
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
	int tag;

	local_irq_save(flags);
	tags = this_cpu_ptr(pool->tag_cpu);

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
				set_bit(smp_processor_id(),
					pool->cpus_have_tags);
		}

		spin_unlock(&pool->ida.lock);
		local_irq_restore(flags);

		if (tag >= 0 || !(gfp & __GFP_WAIT))
			break;

		schedule();

		local_irq_save(flags);
		tags = this_cpu_ptr(pool->tag_cpu);
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
	unsigned nr_free;

	BUG_ON(tag >= pool->nr_tags);

	local_irq_save(flags);
	tags = this_cpu_ptr(pool->tag_cpu);

	spin_lock(&tags->lock);
	tags->freelist[tags->nr_free++] = tag;

	nr_free = tags->nr_free;
	spin_unlock(&tags->lock);

	if (nr_free == 1) {
		set_bit(smp_processor_id(),
			pool->cpus_have_tags);
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

/**
 * DOC: IDR description
 * IDR: Maps ids (small integers) to pointers.
 *
 * This merely combines ida (id allocation) with a radix tree; idr_alloc()
 * stores a pointer, and returns you a small integer by which you can refer to
 * it.
 *
 * It'll give you the smallest available integer (within a specified range if
 * you use idr_alloc_range()) - there's also idr_alloc_cyclic() if you don't
 * want ids to be reused right away.
 *
 * id -> pointer mappings can be deleted with idr_remove().
 */

/**
 * idr_find_next - lookup next object of id to given id.
 * @idr: idr handle
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
	void *ret = NULL;

	rcu_read_lock();

	radix_tree_for_each_slot(slot, &idr->ptrs, &iter, *nextidp) {
		*nextidp = iter.index;
		ret = radix_tree_deref_slot(slot);
		break;
	}

	rcu_read_unlock();

	return __radix_idr_ptr(ret);
}
EXPORT_SYMBOL(idr_find_next);

/**
 * idr_for_each - iterate through all stored pointers
 * @idr: idr handle
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
		error = fn(id, p, data);
		if (error)
			break;
	}

	return error;
}
EXPORT_SYMBOL(idr_for_each);

/**
 * idr_replace - replace pointer for given id
 * @idr: idr handle
 * @ptr: pointer you want associated with the id
 * @id: lookup key
 *
 * Replace the pointer registered with an id and return the old value.
 * A %-ENOENT return indicates that @id was not found.
 * A %-EINVAL return indicates that @id was not within valid constraints.
 */
void *idr_replace(struct idr *idr, void *ptr, unsigned id)
{
	void **slot, *old = ERR_PTR(-ENOENT);
	unsigned long flags;

	rcu_read_lock();
	spin_lock_irqsave(&idr->ida.lock, flags);

	slot = radix_tree_lookup_slot(&idr->ptrs, id);

	if (slot) {
		old = radix_tree_deref_slot(slot);
		if (old)
			radix_tree_replace_slot(slot, __idr_radix_ptr(ptr));
	}

	spin_unlock_irqrestore(&idr->ida.lock, flags);
	rcu_read_unlock();

	return __radix_idr_ptr(old);
}
EXPORT_SYMBOL(idr_replace);

/**
 * idr_remove - remove the given id and free its slot
 * @idr: idr handle
 * @id: unique key
 */
void idr_remove(struct idr *idr, unsigned id)
{
	unsigned long flags;

	spin_lock_irqsave(&idr->ida.lock, flags);

	radix_tree_delete(&idr->ptrs, id);
	__ida_remove(&idr->ida, id);

	spin_unlock_irqrestore(&idr->ida.lock, flags);
}
EXPORT_SYMBOL(idr_remove);

/**
 * idr_preload - preload for idr_alloc_range()
 * @idr: idr to ensure has room to allocate an id
 * @start: value that will be passed to ida_alloc_range()
 * @gfp: allocation mask to use for preloading
 *
 * On success, guarantees that one call of idr_alloc()/idr_alloc_range() won't
 * fail. Returns with preemption disabled; use idr_preload_end() when
 * finished.
 *
 * It's not required to check for failure if you're still checking for
 * idr_alloc() failure.
 *
 * In order to guarantee idr_alloc() won't fail, all allocations from @idr must
 * make use of idr_preload().
 */
int idr_preload(struct idr *idr, unsigned start, gfp_t gfp)
{
	int radix_ret, ida_ret = 0;

	might_sleep_if(gfp & __GFP_WAIT);

	while (1) {
		radix_ret = radix_tree_preload(gfp);

		/*
		 * Well this is horrible, but radix_tree_preload() doesn't
		 * disable preemption if it fails, and idr_preload() users don't
		 * check for errors
		 */
		if (radix_ret)
			preempt_disable();

		/* if ida_preload with GFP_WAIT failed, don't retry */
		if (ida_ret)
			break;

		if (!ida_preload(&idr->ida, start, GFP_NOWAIT) ||
		    !(gfp & __GFP_WAIT))
			break;

		radix_tree_preload_end();
		ida_ret = ida_preload(&idr->ida, start, gfp);
	}

	return radix_ret ?: ida_ret;
}
EXPORT_SYMBOL(idr_preload);

static int idr_insert(struct idr *idr, void *ptr, unsigned id,
		      gfp_t gfp, unsigned long *flags)
{
	int ret = radix_tree_preload(GFP_NOWAIT);
	if (ret) {
		spin_unlock_irqrestore(&idr->ida.lock, *flags);
		ret = radix_tree_preload(gfp);
		spin_lock_irqsave(&idr->ida.lock, *flags);

		if (ret) {
			__ida_remove(&idr->ida, id);
			return ret;
		}
	}

	ret = radix_tree_insert(&idr->ptrs, id, __idr_radix_ptr(ptr));
	BUG_ON(ret);
	radix_tree_preload_end();
	return id;
}

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
 * Note that @end is treated as max when <= 0.  This is to always allow using
 * @start + N as @end as long as N is inside integer range.
 */
int idr_alloc_range(struct idr *idr, void *ptr, unsigned start,
		    unsigned end, gfp_t gfp)
{
	int ret;
	unsigned id;
	unsigned long flags;

	might_sleep_if(gfp & __GFP_WAIT);

	spin_lock_irqsave(&idr->ida.lock, flags);

	ret = __ida_alloc_range_multiple(&idr->ida, &id, 1, start,
					 end, gfp, &flags);
	if (ret == 1)
		ret = idr_insert(idr, ptr, id, gfp, &flags);

	spin_unlock_irqrestore(&idr->ida.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(idr_alloc_range);

/**
 * idr_alloc_cyclic - allocate new idr entry in a cyclical fashion
 * @idr: the (initialized) idr
 * @ptr: pointer to be associated with the new id
 * @start: the minimum id (inclusive)
 * @end: the maximum id (exclusive, <= 0 for max)
 * @gfp: memory allocation flags
 *
 * Essentially the same as idr_alloc_range, but prefers to allocate
 * progressively higher ids if it can. If the "cur" counter wraps, then it will
 * start again at the "start" end of the range and allocate one that has already
 * been used.
 */
int idr_alloc_cyclic(struct idr *idr, void *ptr, unsigned start,
		     unsigned end, gfp_t gfp)
{
	int ret;
	unsigned long flags;

	might_sleep_if(gfp & __GFP_WAIT);

	spin_lock_irqsave(&idr->ida.lock, flags);

	ret = __ida_alloc_cyclic(&idr->ida, start, end, gfp, &flags);
	if (ret >= 0)
		ret = idr_insert(idr, ptr, ret, gfp, &flags);

	spin_unlock_irqrestore(&idr->ida.lock, flags);

	return ret;
}
EXPORT_SYMBOL(idr_alloc_cyclic);

/**
 * idr_destroy - free all memory owned by @idr
 * @idr: idr handle
 *
 * After this function, @idr is completely unused and can be freed / recycled.
 *
 * A typical clean-up sequence for objects stored in an idr tree will use
 * idr_for_each() to free all objects, if necessay, then idr_destroy() to
 * free the embedded ida and radix tree.
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
 * @idr:	idr handle
 *
 * This function is use to set up the handle (@idr) that you will pass
 * to the rest of the functions.
 */
void idr_init(struct idr *idr)
{
	ida_init(&idr->ida);
	INIT_RADIX_TREE(&idr->ptrs, GFP_NOWAIT);
}
EXPORT_SYMBOL(idr_init);
