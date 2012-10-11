/*
 * Copyright (C) 2008 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/pagemap.h>
#include <linux/acall.h>
#include <linux/compiler.h>
#include <linux/syscalls.h>
#include <asm/futex.h>

/* This is the kernel's version of the id which is opaque to userspace */
struct acall_kernel_id {
	u64 cpu;
	u64 counter;
};

static DEFINE_PER_CPU(u64, id_counter);

/*
 * We store some things per mm_struct.  This is allocated and stored in
 * the mm on first use and is freed as the mm exits.
 */
struct acall_mm {
	struct rb_root active_ops;
	wait_queue_head_t ring_waiters;
	wait_queue_head_t threads;
};

/*
 * This tracks an operation which is being performed by a acall thread.  It
 * is built up in the submitting task and then handed off to an acall thread
 * to process.  It is removed and freed by the acall thread once it's done.
 */
struct acall_operation {
	struct rb_node node;
	struct acall_kernel_id kid;
	wait_queue_head_t waitq;
	struct task_struct *task;
	struct acall_submission sub;
};

static void insert_op(struct rb_root *root, struct acall_operation *ins)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct acall_operation *op;
	int cmp;

	while (*p) {
		parent = *p;
		op = rb_entry(parent, struct acall_operation, node);

		cmp = memcmp(&ins->kid, &op->kid, sizeof(op->kid));
		BUG_ON(cmp == 0);

		if (cmp < 0)
			p = &(*p)->rb_left;
		else 
			p = &(*p)->rb_right;
	}

	rb_link_node(&ins->node, parent, p);
	rb_insert_color(&ins->node, root);
}

static struct acall_operation *find_op(struct rb_root *root, 
				       struct acall_kernel_id *kid)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent;
	struct acall_operation *op;
	int cmp;

	while (*p) {
		parent = *p;
		op = rb_entry(parent, struct acall_operation, node);

		cmp = memcmp(kid, &op->kid, sizeof(op->kid));
		if (cmp == 0)
			return op;

		if (cmp < 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	return NULL;
}

static struct acall_mm *get_amm(struct mm_struct *mm)
{
	struct acall_mm *amm = mm->acall_mm;
	if (amm)
		return amm;

	amm = kmalloc(sizeof(struct acall_mm), GFP_KERNEL);
	if (amm == NULL)
		return NULL;

	amm->active_ops = RB_ROOT;
	init_waitqueue_head(&amm->ring_waiters);
	init_waitqueue_head(&amm->threads);

	/* XXX I hope it's ok to abuse this sem. */
	down_write(&mm->mmap_sem);
	if (mm->acall_mm == NULL)
		mm->acall_mm = amm;
	else {
		kfree(amm);
		amm = mm->acall_mm;
	}
	up_write(&mm->mmap_sem);
	return amm;
}

/*
 * completions can be collected from user space as long as they load the
 * cookie before the return code and separate the two loads with a read
 * barrier:
 *
 * 	cookie = comp->cookie;
 * 	smp_rmb();
 * 	ret = comp->return_code;
 *	if (cookie)
 * 		return ret;
 * 	else
 * 		{ do more userspace business ; sys_acall_*_pwait(); }
 */
static int store_comp(struct acall_completion __user *comp, u64 return_code,
		      u64 cookie)
{
	if (__put_user(return_code, &comp->return_code))
		return -EFAULT;
	smp_wmb();
	if (__put_user(cookie, &comp->cookie))
		return -EFAULT;

	return 0;
}

static int store_ring(struct acall_completion_ring __user *uring,
		      u64 return_code, u64 cookie)
{
	struct acall_completion __user *ucomp;
	struct acall_mm *amm;
	u32 nr;
	u32 old;
	u32 head;
	int ret;

	if (__get_user(nr, &uring->nr))
		return -EFAULT;
	if (nr == 0)
		return -EINVAL;

	do {
		if (__get_user(head, &uring->head))
			return -EFAULT;

		pagefault_disable();
		old = futex_atomic_cmpxchg_inatomic(&uring->head, head,
						    head + 1);
		pagefault_enable();
		pr_debug("head %u old %u\n", head, old);
		/* XXX handle old = -EFAULT :P. */
	} while (old != head);

	ucomp = &uring->comps[head % nr];
	pr_debug("ucomp %p\n", ucomp);
	ret = store_comp(ucomp, return_code, cookie);
	if (ret)
		return ret;

	/*
	 * XXX We might want a barrier to order our ring store with our loading
	 * of acall_mm.  We don't want to miss a wake-up.
	 */
	amm = current->mm->acall_mm;
	if (amm)
		wake_up(&amm->ring_waiters);
	return 0;
}

static void process_op(struct acall_mm *amm, struct acall_operation *op)
{
	struct acall_completion_ring __user *uring;
	struct acall_completion __user *ucomp;
	struct acall_id __user *uid;
	struct acall_submission *sub = &op->sub;
	unsigned long flags;
	u64 rc;
	int ret;

	rc = arch_call_syscall(sub->nr, sub->args[0], sub->args[1],
			       sub->args[2], sub->args[3], sub->args[4],
			       sub->args[5]);

	ucomp = (void __user *)sub->completion_pointer;
	if (ucomp) {
		ret = store_comp(ucomp, rc, sub->cookie);
		if (ret)
			printk("comp store to %p failed ret %d\n", ucomp, ret);
	}

	uring = (void __user *)sub->completion_ring_pointer;
	if (uring) {
		ret = store_ring(uring, rc, sub->cookie);
		if (ret)
			printk("ring store to %p failed ret %d\n", uring, ret);
	}

	/*
	 * We're waking and freeing under the lock to avoid races with
	 * sys_acall_comp_pwait().  Something more efficient is surely
	 * possible, but this seems like a safe first pass.
	 */
	uid = (void __user *)sub->id_pointer;
	if (uid) {
		spin_lock_irqsave(&amm->threads.lock, flags);
		wake_up(&op->waitq);
		rb_erase(&op->node, &amm->active_ops);
		spin_unlock_irqrestore(&amm->threads.lock, flags);
	}
}

struct thread_wait_private {
	struct task_struct *task;
	struct acall_operation *op;
};

/*
 * This is called in the submit path to hand off an operation to a waiting
 * thread.  We also use the wait queue lock to protect the active ops
 * tracking so that we don't have to add more locking to the submission
 * path.
 */
static int wake_idle_thread(wait_queue_t *wait, unsigned mode, int sync,
			    void *key)
{
	struct thread_wait_private *wp = wait->private;
	struct acall_operation **caller_op = key;
	struct acall_mm *amm = current->mm->acall_mm;
	struct acall_operation *op;
	int ret;

	/* 
	 * XXX We don't use the generic wake functions because they reference
	 * wait->private instead of calling helpers which take the task
	 * struct.  Maybe we should export try_to_wake_up, or wrap it as
	 * wake_up_state_sync(), or something.  In any case, this is currently
	 * ignoring the sync argument.
	 */
	ret = wake_up_state(wp->task, mode);
	if (ret) {
		op = *caller_op;
		wp->op = op;
		*caller_op = NULL;

		op->task = wp->task;
		if (op->sub.id_pointer)
			insert_op(&amm->active_ops, op);

		list_del_init(&wait->task_list);
	}

	return ret;
}

static int acall_thread(void *data)
{
	struct acall_operation *op = data;
	struct acall_mm *amm = current->mm->acall_mm;
	struct thread_wait_private wp;
	wait_queue_t wait;

       /*
	* XXX We don't want our parent task to know that we've secretly
	* created kernel threads working on their behalf.  This at least stops
	* us from becoming zombies and waiting for our parent to wait on us.
	* I have no idea if this is the right way to do this.  Halp!
	*/
	current->exit_signal = -1;

	/*
	 * Let cancellation know which task is handling the op.  This isn't so
	 * great because there's a window where cancellation won't find a
	 * pending op.  It could be cleaned up if anyone cares.  Cancellation
	 * is inherently racey and rare to begin with.
	 */
	op->task = current;

	/* get the easy case out of the way.. */
	if (!(op->sub.flags & ACALL_SUBMIT_THREAD_POOL)) {
		process_op(amm, op);
		kfree(op);
		return 0;
	}

	/* 
	 * We're using our own wait queue entry func so we roll our own
	 * wait_event_*() :(
	 */
	wp.op = op;
	wp.task = current;
	init_wait(&wait);
	wait.private = &wp;
	wait.func = wake_idle_thread;

	/*
	 * This is being careful to test wp.op after finish_wait() is
	 * called in case we got woken up just before removing ourselves
	 * from the wait queue.
	 */
	while (wp.op) {
		process_op(amm, wp.op);
		kfree(wp.op);
		wp.op = NULL;

		prepare_to_wait_exclusive(&amm->threads, &wait,
					  TASK_INTERRUPTIBLE);
		if (wp.op == NULL)
			schedule_timeout(msecs_to_jiffies(200));
		if (wp.op == NULL)
			finish_wait(&amm->threads, &wait);
	}

	return 0;
}

static int setup_op_id(struct acall_operation *op, struct acall_id __user *uid)
{
	int cpu = get_cpu();
	op->kid.cpu = cpu;
	op->kid.counter = per_cpu(id_counter, cpu)++;
	put_cpu();

	init_waitqueue_head(&op->waitq);

	BUILD_BUG_ON(sizeof(struct acall_kernel_id) != sizeof(struct acall_id));
	if (copy_to_user(uid, &op->kid, sizeof(op->kid)))
		return -EFAULT;
	else
		return 0;
}

/*
 * Submits system calls to be executed by kernel threads.
 *
 * The submissions array contains pointers to submission structures, one for
 * each operation.  The pointer and submission struct are copied to the
 * kernel.  The submission struct is only referenced during this submission
 * call.  It will not be referenced once this submission call has returned.
 *
 * The 'flags' field alters behaviour of a given submission:
 *   ACALL_SUBMIT_THREAD_POOL: The submission will be handed off to a waiting
 *   	thread if one is available.  It will not be updated with the submitting
 *   	callers task state.  If a waiting thread isn't available then one
 *   	will be created.  After servicing the operation the thread will 
 *   	wait for 200ms for a chance to service another operation before it
 *   	exits.
 *
 * The 'id_pointer' field in the submission struct is a user space pointer to
 * a 'struct acall_id'.  If the field is non-zero then the kernel writes an id
 * to that address which identifies the operation.  The id can be used to
 * cancel the operation or wait for its completion.
 *
 * The 'completion_pointer' field in the submission struct is a user space
 * pointer to a 'struct acall_completion'.  If it is non-zero then the kernel
 * will write a completion struct to that address when the operation is
 * complete.
 *
 * The 'completion_ring_pointer' field in the submission struct is a user
 * space pointer to a 'struct acall_completion_ring'.  If it is non-zero then
 * the kernel will write a completion struct to the next available position in
 * the given ring.  It is up to the application to ensure that there is always
 * enough room in the ring by not submitting more operations than there are
 * entries in the ring.
 *
 * It is allowed to set all of these three pointers to null.  The operation
 * will still be processed.
 *
 * A positive return code gives the number of operations which are now
 * pending.  A return code less than 'nr' is possible if later submissions
 * contain errors.  A negative return code is the errno of the submission
 * failure of the first submission struct.  0 will be returned if 'nr' is 0.
 */
asmlinkage long sys_acall_submit(struct acall_submission __user *submissions,
				 unsigned long nr)
{
	struct acall_operation *op = NULL;
	struct acall_id __user *uid;
	struct acall_mm *amm = NULL;
	unsigned long flags;
	unsigned long i = 0;
	pid_t pid;
	int ret = 0;

	/*
	 * We don't strictly need this for all ops.  But it's a small amount
	 * of work and an unlikely failure case.  Ensuring that it exists
	 * makes uses later on in the loop cleaner and the majority of ops
	 * will use it eventually anyway.
	 */
	amm = get_amm(current->mm);
	if (amm == NULL)
		return -ENOMEM;

	for (; i < nr; i++) {
		op = kmalloc(sizeof(struct acall_operation), GFP_KERNEL);
		if (op == NULL) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(&op->sub, &submissions[i],
				   sizeof(struct acall_submission))) {
			ret = -EFAULT;
			break;
		}

		uid = (void __user *)op->sub.id_pointer;
		if (uid) {
			ret = setup_op_id(op, uid);
			if (ret)
				break;
		}

		/* the threads' waitq wake func passes it the op */
		if (op->sub.flags & ACALL_SUBMIT_THREAD_POOL) {
			__wake_up(&amm->threads, TASK_NORMAL, 1, &op);
			if (op == NULL)
				continue;
		}

		if (uid) {
			op->task = NULL;
			spin_lock_irqsave(&amm->threads.lock, flags);
			insert_op(&amm->active_ops, op);
			spin_unlock_irqrestore(&amm->threads.lock, flags);
		}

		pid = kernel_thread(acall_thread, op,
				CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_IO);
		if (pid < 0) {
			ret = pid;
			break;
		}
		op = NULL;
	}

	kfree(op);
	return i ? i : ret;
}

static int pwait_prologue(struct timespec __user *utime,
			  const sigset_t __user *sigmask, size_t sigsetsize,
			  struct hrtimer_sleeper *sleeper, sigset_t *sigsaved)
{
	sigset_t ksigmask;
	struct timespec ts;
	unsigned long slack;
	ktime_t t;

	if (utime) {
		if (copy_from_user(&ts, utime, sizeof(ts)) != 0)
			return -EFAULT;
		if (!timespec_valid(&ts))
			return -EINVAL;

		hrtimer_init_on_stack(&sleeper->timer, CLOCK_MONOTONIC,
					HRTIMER_MODE_ABS);
		hrtimer_init_sleeper(sleeper, current);

		t = ktime_add_safe(ktime_get(), timespec_to_ktime(ts));
		if (rt_task(current))
			slack = 0;
		else
			slack = current->timer_slack_ns;
		hrtimer_set_expires_range_ns(&sleeper->timer, t, slack);

		hrtimer_start_expires(&sleeper->timer, HRTIMER_MODE_ABS);
		if (!hrtimer_active(&sleeper->timer))
			sleeper->task = NULL;
	} else
		sleeper->task = current;

	if (sigmask) {
		if (sigsetsize != sizeof(sigset_t))
			return -EINVAL;
		if (copy_from_user(&ksigmask, sigmask, sizeof(ksigmask)))
			return -EFAULT;
		sigdelsetmask(&ksigmask, sigmask(SIGKILL) | sigmask(SIGSTOP));
		sigprocmask(SIG_SETMASK, &ksigmask, sigsaved);
	}

	return 0;
}

static void pwait_epilogue(int ret, struct timespec __user *utime,
			   const sigset_t __user *sigmask, 
			   struct hrtimer_sleeper *sleeper, sigset_t *sigsaved)
{
	if (utime) {
		hrtimer_cancel(&sleeper->timer);
		destroy_hrtimer_on_stack(&sleeper->timer);
	}

	if (sigmask) {
		if (ret == -EINTR) {
			memcpy(&current->saved_sigmask, sigsaved,
			       sizeof(*sigsaved));
			set_restore_sigmask();
		} else
			sigprocmask(SIG_SETMASK, sigsaved, NULL);
	}
}

struct comp_wait_private {
	struct task_struct *task;
	int woken;
};

/*
 * We have a wake function which sets a per-waiter boolean so that it can
 * tell when one of its wait queues has been woken without having to test
 * all of them.
 */
static int wake_comp_waiter(wait_queue_t *wait, unsigned mode, int sync,
			    void *key)
{
	struct comp_wait_private *wp = wait->private;
	int ret;

	/* 
	 * XXX We don't use the generic wake functions because they reference
	 * wait->private instead of calling helpers which take the task
	 * struct.  Maybe we should export try_to_wake_up, or wrap it as
	 * wake_up_state_sync(), or something.  In any case, this is currently
	 * ignoring the sync argument.
	 */
	ret = wake_up_state(wp->task, mode);
	if (ret) {
		wp->woken = 1;
		list_del_init(&wait->task_list);
	}

	return ret;
}

struct acall_wait {
	struct acall_wait *next;
	wait_queue_t wait;
	struct acall_operation *op;
};


/*
 * This waits for the given operations to complete.
 *
 * A return code of 1 indicates that some number of the operations have
 * completed.  They might have been completed before this system call was
 * executed or they might have completed while we were sleeping. 
 *
 * A return code of 0 indicates that there were no operations to wait for.
 * 'nr' might have been 0 or all the uid pointers were NULL.
 *
 * A negative return code indicates a negative errno which occurred during
 * processing of one of the specified operations.
 *
 * -EINVAL can be returned if the calling memory context has never submitted
 * operations with the id_pointer set, meaning that we could have no operations 
 * to wait for.
 *
 * This call has know way to know if a given id represents a valid id that was
 * issued in the past.  If it finds an id that does not correspond to an
 * operation that is currently processing it assumes that the operation has
 * been completed and returns 1.  Callers that pass in invalid ids will be
 * told that an operation has completed.
 */
asmlinkage long sys_acall_comp_pwait(struct acall_id __user *uids,
				     unsigned long nr,
				     struct timespec __user *utime,
				     const sigset_t __user *sigmask,
				     size_t sigsetsize)
{
	struct acall_mm *amm = current->mm->acall_mm;
	struct acall_kernel_id kid;
	struct hrtimer_sleeper sleeper;
	unsigned long flags;
	struct acall_operation *op;
	sigset_t sigsaved;
	struct acall_wait *aw;
	struct acall_wait *head = NULL;
	struct comp_wait_private wp = {
		.task = current,
		.woken = 0,
	};
	unsigned long i;
	int ret;

	if (amm == NULL)
		return -EINVAL;

	ret = pwait_prologue(utime, sigmask, sigsetsize, &sleeper, &sigsaved);
	if (ret)
		return ret;

	for (i = 0; i < nr; i++) {
		if (copy_from_user(&kid, &uids[i], sizeof(kid))) {
			ret = -EFAULT;
			break;
		}

		aw = kzalloc(sizeof(struct acall_wait), GFP_KERNEL);
		if (aw == NULL) {
			ret = -ENOMEM;
			break;
		}

		init_wait(&aw->wait);
		aw->wait.private = &wp;
		aw->wait.func = wake_comp_waiter;

		spin_lock_irqsave(&amm->threads.lock, flags);
		op = find_op(&amm->active_ops, &kid);
		if (op) {
			aw->op = op;
			add_wait_queue(&op->waitq, &aw->wait);
		}
		spin_unlock_irqrestore(&amm->threads.lock, flags);
		if (op == NULL) {
			kfree(aw);
			wp.woken = 1;
			break;
		}

		aw->next = head;
		head = aw;
	}

	if (head == NULL)
		goto out;

	/* we need the barrier in set_current_state() */
	set_current_state(TASK_INTERRUPTIBLE);

	if (!wp.woken && sleeper.task && !signal_pending(current))
		schedule();
	if (signal_pending(current))
		ret = -ERESTARTSYS;

	/*
	 * The op is freed after waking up the op's waitqueue, removing all its
	 * wait heads, while holding the lock.  If we acquire the lock, and our
	 * aw is still on the queue, then the op won't be freed until we
	 * release the lock.  finish_wait() only dereferences our op pointer if
	 * the entry is still on the queue.
	 *
	 * XXX How much work is too much work to do while holding the lock?
	 */
	while (head) {
		spin_lock_irqsave(&amm->threads.lock, flags);
		for (i = 0; (aw = head) && i < 100; i++) {
			head = head->next;
			finish_wait(&aw->op->waitq, &aw->wait);
			kfree(aw);
		}
		spin_unlock_irqrestore(&amm->threads.lock, flags);
	}

out:
	pwait_epilogue(ret, utime, sigmask, &sleeper, &sigsaved);
	if (wp.woken)
		ret = 1;
	return ret;
}

/*
 * This returns non-zero if the calling wait_event_*() loop should break
 * out and fall back to sampling the head with a blocking read.  We want to
 * do this either if the read faults or if we see enough space in the ring.
 *
 * The calling wait_event_*() loop has set our task state.  We need
 * to be very careful that we don't set it in the process of testing the
 * userspace pointer.  We could lose a wake-up if we did.
 */
static int should_get_user(struct acall_completion_ring __user *uring,
			   u32 tail, u32 min)
{
	u32 head;
	int ret;

	pagefault_disable();
	ret = __copy_from_user_inatomic(&head, &uring->head, sizeof(head));
	pagefault_enable();
	return ret || (head - tail >= min);
}

/*
 * This waits for the given number of completions to appear in the given ring.
 *
 * Userspace specifies the tail value which indicates the index of the last
 * completion that they've consumed.  We watch the head pointer until it
 * indicates that 'min' number of completions are waiting.
 *
 * If 'min' is 0 then the call will return 0 immediately without reading
 * the ring.
 *
 * The number of pending events is not returned because it may be larger
 * than the signed int that many archs use to represent the return code
 * of a system call.  Userspace is expected to perform u32 math on the
 * head index and their tail index.
 *
 * We'll only be woken by threads which complete into our ring if we share
 * the same mm context as they do.  We could provide a flag to submission
 * and waiting to indicate that we should track sleepers outside of a given
 * mm context.
 *
 * This first pass just uses a boring wait queue head in our per-mm data
 * We wake when anything hits the ring and re-evaluate our situation.  We could
 * spend some code and complexity on a more clever data structure which would
 * allow the completer to only wake us when the ring has the given number
 * of events that we want. 
 */
asmlinkage long sys_acall_ring_pwait(struct acall_completion_ring __user *uring,
				     u32 tail, u32 min,
				     struct timespec __user *utime,
				     const sigset_t __user *sigmask,
				     size_t sigsetsize)
{
	struct hrtimer_sleeper sleeper;
	struct acall_mm *amm;
	sigset_t sigsaved;
	u32 head;
	int ret;

	amm = get_amm(current->mm);
	if (amm == NULL)
		return -ENOMEM;

	if (min == 0)
		return 0;

	ret = pwait_prologue(utime, sigmask, sigsetsize, &sleeper, &sigsaved);
	if (ret)
		return ret;

	for(;;) {
		/* XXX read memory barrier? */
		if (__get_user(head, &uring->head)) {
			ret = -EFAULT;
			break;
		}

		/* XXX is the wrapping u32 math ok? */
		if (head - tail >= min) {
			break;
		}

		ret = wait_event_interruptible(amm->ring_waiters,
					       !sleeper.task ||
					       should_get_user(uring, tail,
							       min));
		if (ret || !sleeper.task)
			break;
	}

	pwait_epilogue(ret, utime, sigmask, &sleeper, &sigsaved);
	return ret;
}

/*
 * Cancels the operation specified by the given id.  The id is set by the
 * kernel as the operation begins processing.  It is so large as to be
 * effectively unique for the life time of the system.
 *
 * -EAGAIN can be returned when:
 * - the callers thread group has never issued an acall operation
 * - the given id is not pending
 * - the operation could not be canceled
 *
 * -EINVAL can be returned if the calling memory context has never submitted
 * operations with the id_pointer set, meaning that we could have no operations 
 * to cancel.
 *
 * 0 will be returned if a successful attempt was made to cancel the
 * operation.  How the operation copes with an attempt to cancel it, sending
 * its thread SIGKILL, depends on the operation.  Some will abort immediately.
 * Some may complete with partial progress.  Some may ignore the signal.
 * A completion struct will be generated as usual according to the event's
 * submission.  Its return code may reflect the cancellation attempt, or
 * it may not.
 */
asmlinkage long sys_acall_cancel(struct acall_id __user *uid)

{
	struct acall_mm *amm = current->mm->acall_mm;
	struct acall_operation *op;
	struct siginfo info;
	struct acall_kernel_id kid;
	unsigned long flags;
	int ret;

	if (amm == NULL)
		return -EAGAIN;
	if (copy_from_user(&kid, uid, sizeof(kid)))
		return -EFAULT;

	/*
	 * The target task exits after having removed its op from the tree
	 * under the lock.  If the op is in the tree then the task won't
	 * exit until we release the lock.
	 */
	ret = -EAGAIN;
	spin_lock_irqsave(&amm->threads.lock, flags);
	op = find_op(&amm->active_ops, &kid);
	if (op && op->task) {
		info.si_signo = SIGKILL;
		info.si_errno = 0;
		info.si_code = SI_KERNEL;
		info.si_pid = task_tgid_vnr(current);
		info.si_uid = current_uid();
		if (force_sig_info(info.si_signo, &info, op->task) == 0)
			ret = 0;
	}
	spin_unlock_irqrestore(&amm->threads.lock, flags);

	return ret;
}
