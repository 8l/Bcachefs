/* System call table for x86-64. */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/errno.h>
#include <asm/asm-offsets.h>

#define __NO_STUBS

#define __SYSCALL(nr, sym) extern asmlinkage void sym(void) ;
#undef _ASM_X86_UNISTD_64_H
#include <asm/unistd_64.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym) [nr] = sym,
#undef _ASM_X86_UNISTD_64_H

typedef void (*sys_call_ptr_t)(void);

extern void sys_ni_syscall(void);

const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	*Smells like a like a compiler bug -- it doesn't work
	*when the & below is removed.
	*/
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/unistd_64.h>
};

long arch_call_syscall(unsigned int nr, long arg0, long arg1, long arg2,
		       long arg3, long arg4, long arg5)
{
	typedef asmlinkage long (*syscall_fn_t)(long, long, long, long, long,
						long);
	syscall_fn_t *calls = (syscall_fn_t *)sys_call_table;

	if (nr > __NR_syscall_max)
		return -ENOSYS;

	return calls[nr](arg0, arg1, arg2, arg3, arg4, arg5);
}
