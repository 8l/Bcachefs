/*
 *  MMU context allocation for 64-bit kernels.
 *
 *  Copyright (C) 2004 Anton Blanchard, IBM Corp. <anton@samba.org>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/slab.h>

#include <asm/mmu_context.h>
#include <asm/pgalloc.h>

#include "icswx.h"

static DEFINE_IDA(mmu_context_ida);

int __init_new_context(void)
{
	return ida_get_range(ida, 1, MAX_USER_CONTEXT, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(__init_new_context);

int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	int index;

	index = __init_new_context();
	if (index < 0)
		return index;

	/* The old code would re-promote on fork, we don't do that
	 * when using slices as it could cause problem promoting slices
	 * that have been forced down to 4K
	 */
	if (slice_mm_new_context(mm))
		slice_set_user_psize(mm, mmu_virtual_psize);
	subpage_prot_init_new_context(mm);
	mm->context.id = index;
#ifdef CONFIG_PPC_ICSWX
	mm->context.cop_lockp = kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	if (!mm->context.cop_lockp) {
		__destroy_context(index);
		subpage_prot_free(mm);
		mm->context.id = MMU_NO_CONTEXT;
		return -ENOMEM;
	}
	spin_lock_init(mm->context.cop_lockp);
#endif /* CONFIG_PPC_ICSWX */

#ifdef CONFIG_PPC_64K_PAGES
	mm->context.pte_frag = NULL;
#endif
	return 0;
}

void __destroy_context(int context_id)
{
	ida_remove(&mmu_context_ida, context_id);
}
EXPORT_SYMBOL_GPL(__destroy_context);

#ifdef CONFIG_PPC_64K_PAGES
static void destroy_pagetable_page(struct mm_struct *mm)
{
	int count;
	void *pte_frag;
	struct page *page;

	pte_frag = mm->context.pte_frag;
	if (!pte_frag)
		return;

	page = virt_to_page(pte_frag);
	/* drop all the pending references */
	count = ((unsigned long)pte_frag & ~PAGE_MASK) >> PTE_FRAG_SIZE_SHIFT;
	/* We allow PTE_FRAG_NR fragments from a PTE page */
	count = atomic_sub_return(PTE_FRAG_NR - count, &page->_count);
	if (!count) {
		pgtable_page_dtor(page);
		free_hot_cold_page(page, 0);
	}
}

#else
static inline void destroy_pagetable_page(struct mm_struct *mm)
{
	return;
}
#endif


void destroy_context(struct mm_struct *mm)
{

#ifdef CONFIG_PPC_ICSWX
	drop_cop(mm->context.acop, mm);
	kfree(mm->context.cop_lockp);
	mm->context.cop_lockp = NULL;
#endif /* CONFIG_PPC_ICSWX */

	destroy_pagetable_page(mm);
	__destroy_context(mm->context.id);
	subpage_prot_free(mm);
	mm->context.id = MMU_NO_CONTEXT;
}
