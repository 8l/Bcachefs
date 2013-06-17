/*
 *  ICSWX and ACOP/PID Management
 *
 *  Copyright (C) 2011 Anton Blanchard, IBM Corp. <anton@samba.org>
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
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/module.h>
#include "icswx.h"

#define COP_PID_MIN (COP_PID_NONE + 1)
#define COP_PID_MAX (0xFFFF)

static DEFINE_IDA(cop_ida);

int get_cop_pid(struct mm_struct *mm)
{
	int pid;

	if (mm->context.cop_pid == COP_PID_NONE) {
		pid = ida_simple_get(&cop_ida, COP_PID_MIN,
				     COP_PID_MAX, GFP_KERNEL);
		if (pid >= 0)
			mm->context.cop_pid = pid;
	}
	return mm->context.cop_pid;
}

int disable_cop_pid(struct mm_struct *mm)
{
	int free_pid = COP_PID_NONE;

	if ((!mm->context.acop) && (mm->context.cop_pid != COP_PID_NONE)) {
		free_pid = mm->context.cop_pid;
		mm->context.cop_pid = COP_PID_NONE;
	}
	return free_pid;
}

void free_cop_pid(int free_pid)
{
	ida_simple_remove(&cop_ida, free_pid);
}
