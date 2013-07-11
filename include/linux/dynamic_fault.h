#ifndef _DYNAMIC_FAULT_H
#define _DYNAMIC_FAULT_H

#include <linux/bio.h>
#include <linux/jump_label.h>
#include <linux/slab.h>

/*
 * An instance of this structure is created in a special
 * ELF section at every dynamic fault callsite.  At runtime,
 * the special section is treated as an array of these.
 */
struct _dfault {
	const char		*modname;
	const char		*function;
	const char		*filename;
	unsigned int		lineno:24;
	/*
	 * The flags field controls the behaviour at the callsite.
	 * The bits here are changed dynamically when the user
	 * writes commands to <debugfs>/dynamic_debug/ddebug
	 */
#define _DFAULT_ON		(1<<0)
#define _DFAULT_ONE_SHOT	(1<<1)
	unsigned int		flags:8;
	struct static_key	enabled;
} __attribute__((aligned(8)));


#ifdef CONFIG_DYNAMIC_FAULT

extern long long dynamic_fault_enabled;
extern long long dynamic_fault_enabled2;

int dfault_add_module(struct _dfault *tab, unsigned int n, const char *mod);
int dfault_remove_module(char *mod_name);

#define __dynamic_fault_enabled(df)					\
({									\
	int __ret = 0;							\
	if (static_key_true(&(df).enabled)) {				\
		__ret = df.flags;					\
		df.flags &= ~_DFAULT_ONE_SHOT;				\
	}								\
	__ret;								\
})

#define dynamic_fault()							\
({									\
	static struct _dfault descriptor				\
	__used __attribute__((section("__faults"), aligned(8))) = {	\
		.modname	= KBUILD_MODNAME,			\
		.function	= __func__,				\
		.filename	= __FILE__,				\
		.lineno		= __LINE__,				\
	};								\
	__dynamic_fault_enabled(descriptor);				\
})

#define kmalloc(...)							\
	(dynamic_fault() ? NULL		: kmalloc(__VA_ARGS__))
#define kzalloc(...)							\
	(dynamic_fault() ? NULL		: kzalloc(__VA_ARGS__))
#define krealloc(...)							\
	(dynamic_fault() ? NULL		: krealloc(__VA_ARGS__))

#define __get_free_pages(...)						\
	(dynamic_fault() ? 0		: __get_free_pages(__VA_ARGS__))
#define alloc_pages_node(...)						\
	(dynamic_fault() ? NULL		: alloc_pages_node(__VA_ARGS__))
#define alloc_pages_nodemask(...)					\
	(dynamic_fault() ? NULL		: alloc_pages_nodemask(__VA_ARGS__))

#define bio_alloc_bioset(gfp, ...)					\
	(!(gfp & __GFP_WAIT) && dynamic_fault()				\
	 ? NULL	: bio_alloc_bioset(gfp, __VA_ARGS__))

#define bio_clone(bio, gfp)						\
	(!(gfp & __GFP_WAIT) && dynamic_fault()				\
	 ? NULL	: bio_clone(bio, gfp))

#define bio_clone_bioset(bio, gfp, bs)					\
	(!(gfp & __GFP_WAIT) && dynamic_fault()				\
	 ? NULL	: bio_clone_bioset(bio, gfp, bs))

#define bio_kmalloc(...)						\
	(dynamic_fault() ? NULL		: bio_kmalloc(__VA_ARGS__))
#define bio_clone_kmalloc(...)						\
	(dynamic_fault() ? NULL		: bio_clone_kmalloc(__VA_ARGS__))
#define bio_alloc_pages(...)						\
	(dynamic_fault() ? -ENOMEM	: bio_alloc_pages(__VA_ARGS__))

#else /* CONFIG_DYNAMIC_FAULT */

#define dfault_add_module(tab, n, modname)	0
#define dfault_remove_module(mod)		0
#define dynamic_fault()				0

#endif /* CONFIG_DYNAMIC_FAULT */

#endif
