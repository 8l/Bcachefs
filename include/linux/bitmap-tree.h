#ifndef _LINUX_BITMAP_TREE_H
#define _LINUX_BITMAP_TREE_H

#include <linux/spinlock_types.h>
#include <linux/types.h>

#define TREE_ARY		BITS_PER_LONG
#define TREE_INLINE_NODES	16

struct bitmap_tree {
	spinlock_t		lock;
	unsigned		nodes;
	unsigned		first_leaf;
	unsigned long		*tree;
	unsigned long		inline_nodes[TREE_INLINE_NODES];
};

void bitmap_tree_clear_bit(struct bitmap_tree *, unsigned);
int bitmap_tree_find_set_bits(struct bitmap_tree *, unsigned *,
			      unsigned, unsigned, gfp_t);
int bitmap_tree_find_set_bits_from(struct bitmap_tree *, unsigned *, unsigned,
				   unsigned, unsigned, gfp_t);

void bitmap_tree_destroy(struct bitmap_tree *);
int bitmap_tree_init(struct bitmap_tree *, unsigned);

#define BITMAP_TREE_INIT(name)					\
{								\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),	\
	.nodes		= TREE_INLINE_NODES,			\
	.first_leaf	= 1,					\
	.tree		= name.inline_nodes,			\
}

#define DEFINE_BITMAP_TREE(name)				\
	struct bitmap_tree name = BITMAP_TREE_INIT(name)

#endif /* _LINUX_BITMAP_TREE_H */
