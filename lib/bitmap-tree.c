
#include <linux/bitmap-tree.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

static unsigned first_leaf_from_nodes(unsigned nodes)
{
	unsigned ret = 0;

	while (ret * TREE_ARY + 1 < nodes)
		ret = ret * TREE_ARY + 1;

	return ret;
}

static unsigned first_leaf_from_leaves(unsigned leaves)
{
	unsigned ret = 0;

	while (ret * TREE_ARY + 1 < ret + leaves)
		ret = ret * TREE_ARY + 1;

	return ret;
}

static inline int __bitmap_tree_resize(struct bitmap_tree *map,
				       unsigned max_id, gfp_t gfp,
				       unsigned long *flags)
	__releases(&map->lock)
	__acquires(&map->lock)
{
	unsigned long *tree;
	unsigned old_nodes = map->nodes;
	unsigned cur_leaves = map->nodes - map->first_leaf;
	unsigned new_leaves = cur_leaves * 2;
	unsigned first_leaf = first_leaf_from_leaves(new_leaves);
	unsigned new_nodes = first_leaf + new_leaves;

	if (cur_leaves >= BITS_TO_LONGS(max_id))
		return -ENOSPC;

	spin_unlock_irqrestore(&map->lock, *flags);
	tree = kzalloc(new_nodes * sizeof(unsigned long), gfp);
	spin_lock_irqsave(&map->lock, *flags);

	if (!tree)
		return -ENOMEM;

	if (old_nodes != map->nodes) {
		kfree(tree);
		return 0;
	}

	if (first_leaf == map->first_leaf) {
		/* Depth doesn't change, just appending leaf nodes */
		memcpy(tree, map->tree, map->nodes * sizeof(unsigned long));
	} else {
		unsigned i, j, bit;

		memcpy(tree + first_leaf,
		       map->tree + map->first_leaf,
		       cur_leaves * sizeof(unsigned long));

		for (i = first_leaf; i < first_leaf + cur_leaves; i++) {
			j = i;

			while (!~tree[j] && j) {
				bit = (j - 1) % TREE_ARY;
				j = (j - 1) / TREE_ARY;

				__set_bit(bit, tree + j);
			}
		}
	}

	if (map->tree != map->inline_nodes)
		kfree(map->tree);

	map->nodes	= new_nodes;
	map->first_leaf = first_leaf;
	map->tree	= tree;

	return 0;
}

int bitmap_tree_resize(struct bitmap_tree *map, unsigned max_id, gfp_t gfp)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	ret = __bitmap_tree_resize(map, max_id, gfp, &flags);
	spin_unlock_irqrestore(&map->lock, flags);

	return ret;
}

void bitmap_tree_clear_bit(struct bitmap_tree *map, unsigned id)
{
	unsigned i = map->first_leaf + id / BITS_PER_LONG;
	unsigned bit = id % BITS_PER_LONG;

	BUG_ON(i >= map->nodes);

	while (1) {
		unsigned long *node = map->tree + i, old = *node;

		WARN_ON(!(node & 1 << bit));

		__clear_bit(bit, node);

		if (~old || !i)
			break;

		bit = (i - 1) % TREE_ARY;
		i = (i - 1) / TREE_ARY;
	}
}

int bitmap_tree_find_set_bits(struct bitmap_tree *map, unsigned *ids,
			      unsigned nr_bits, unsigned max_id, gfp_t gfp)
{
	unsigned i = 0, bits_found = 0, bit, id;
	unsigned long *node = map->tree;
	unsigned long flags;
	int err = 0;

	BUG_ON(!max_id);

	spin_lock_irqsave(&map->lock, flags);

	while (bits_found < nr_bits) {
		while (!~*node) {
resize:
			err = __bitmap_tree_resize(map, max_id, gfp, &flags);
			if (err)
				break;

			i = 0;
			node = map->tree;
		}

		while (1) {
			bit = ffz(*node);

			if (i >= map->first_leaf)
				break;

			i = i * TREE_ARY + 1 + bit;
			node = map->tree + i;

			if (i >= map->nodes)
				goto resize;

			BUG_ON(!~*node);
		}

		id = (i - map->first_leaf) * BITS_PER_LONG + bit;
		if (id >= max_id) {
			err = -ENOSPC;
			break;
		}

		ids[bits_found++] = id;

		while (1) {
			__set_bit(bit, node);

			if (~*node || !i)
				break;

			bit = (i - 1) % TREE_ARY;
			i = (i - 1) / TREE_ARY;

			node = map->tree + i;
		}
	}

	spin_unlock_irqrestore(&map->lock, flags);

	return bits_found ? bits_found : err;
}

int bitmap_tree_find_set_bits_from(struct bitmap_tree *map,
				   unsigned *ids, unsigned nr_ids,
				   unsigned min_id, unsigned max_id,
				   gfp_t gfp)
{
	unsigned i = 0, bit, bit_offset, id, ids_found = 0;
	unsigned long *node = map->tree;
	unsigned long flags;
	int err = 0;

	spin_lock_irqsave(&map->lock, flags);

	BUG_ON(min_id >= max_id);

	while (ids_found < nr_ids) {
		while (!~*node) {
resize:
			err = __bitmap_tree_resize(map, max_id, gfp, &flags);
			if (err)
				break;

			i = 0;
			node = map->tree;
		}

		if (min_id) {
			bit_offset = min_id % BITS_PER_LONG;
			i = map->first_leaf + min_id / BITS_PER_LONG;

			if (i >= map->nodes)
				goto resize;

			while (1) {
				node = map->tree + i;
				bit = ffz(*node >> bit_offset) + bit_offset;

				if (~*node && bit < BITS_PER_LONG)
					goto found;

				if (!i)
					goto resize;

				bit_offset = (i - 1) % TREE_ARY + 1;
				i = (i - 1) / TREE_ARY;
			}
		}

		while (1) {
			bit = ffz(*node);
found:
			if (i >= map->first_leaf)
				break;

			i = i * TREE_ARY + 1 + bit;
			node = map->tree + i;

			if (i >= map->nodes)
				goto resize;

			BUG_ON(!~*node);
		}

		id = (i - map->first_leaf) * BITS_PER_LONG + bit;
		BUG_ON(id < min_id);

		if (id >= max_id) {
			err = -ENOSPC;
			break;
		}

		while (1) {
			__set_bit(bit, node);

			if (~*node || !i)
				break;

			bit = (i - 1) % TREE_ARY;
			i = (i - 1) / TREE_ARY;

			node = map->tree + i;
		}
	}

	spin_unlock_irqrestore(&map->lock, flags);

	return ids_found ? ids_found : err;
}

void bitmap_tree_destroy(struct bitmap_tree *map)
{
	kfree(map->tree);
}

int bitmap_tree_init(struct bitmap_tree *map, unsigned prealloc)
{
	memset(map, 0, sizeof(*map));

	spin_lock_init(&map->lock);
	map->nodes	= TREE_INLINE_NODES;
	map->first_leaf = first_leaf_from_nodes(map->nodes);
	map->tree	= map->inline_nodes;

	if (prealloc) {
		unsigned leaves = BITS_TO_LONGS(prealloc);
		unsigned first_leaf = first_leaf_from_leaves(leaves);
		unsigned nodes = first_leaf + leaves;

		if (nodes > map->nodes) {
			nodes = roundup_pow_of_two(nodes);

			map->tree = kzalloc(nodes * sizeof(unsigned long),
					    GFP_KERNEL);
			if (!map->tree)
				return -ENOMEM;
		}

		map->nodes = nodes;
		map->first_leaf = first_leaf;
	}

	return 0;
}
