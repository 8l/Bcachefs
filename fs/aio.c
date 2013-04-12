/*
 *	An async IO implementation for Linux
 *	Written by Benjamin LaHaise <bcrl@kvack.org>
 *
 *	Implements an efficient asynchronous io interface.
 *
 *	Copyright 2000, 2001, 2002 Red Hat, Inc.  All Rights Reserved.
 *
 *	See ../COPYING for licensing terms.
 */
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/aio_abi.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/backing-dev.h>
#include <linux/uio.h>

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/bio.h>
#include <linux/mmu_context.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/aio.h>
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/eventfd.h>
#include <linux/blkdev.h>
#include <linux/compat.h>
#include <linux/percpu-refcount.h>
#include <linux/tags.h>

#include <asm/kmap_types.h>
#include <asm/uaccess.h>

#include "aio.h"

/* Contextless AIO */

struct kiocb_noctx {
	struct kiocb		req;

	struct page		*list_head;
	struct page		*list_entry;
	unsigned		list_head_offset;
	unsigned		list_entry_offset;
};

static unsigned noctx_ring_put(struct kioctx *ctx, struct kiocb *_req, unsigned tail)
{
	struct kiocb_noctx *req = container_of(_req, struct kiocb_noctx, req);
	struct iocb_noctx **head, **entry;

	void *head_p = kmap_atomic(req->list_head);
	void *entry_p = kmap_atomic(req->list_entry);

	head = head_p + req->list_head_offset;
	entry = entry_p + req->list_entry_offset;

	do {
		*entry = *head;

		cmpxchg(head, *entry, req->req.ki_obj.user);
	} while (0);

	kunmap_atomic(entry_p);
	kunmap_atomic(head_p);

	return 0;
}

static void kiocb_noctx_free(struct kiocb *_req)
{
	struct kiocb_noctx *req = container_of(_req, struct kiocb_noctx, req);

	if (req->list_head)
		put_page(req->list_head);
	if (req->list_entry)
		put_page(req->list_entry);

	kfree(req);
}

static int io_submit_one_noctx(struct iocb_noctx __user *user_iocb,
			       struct iocb_noctx *iocb,
			       struct iocb_noctx __user *completion_list,
			       bool compat)
{
	struct kiocb_noctx *req;
	ssize_t ret = -EAGAIN;;

	/* enforce forwards compatibility on users */
	if (unlikely(iocb->aio_reserved1)) {
		pr_debug("EINVAL: reserve field set\n");
		return -EINVAL;
	}

	/* prevent overflows */
	if (unlikely(
	    (iocb->aio_buf != (unsigned long)iocb->aio_buf) ||
	    (iocb->aio_nbytes != (size_t)iocb->aio_nbytes) ||
	    ((ssize_t)iocb->aio_nbytes < 0))) {
		pr_debug("EINVAL: io_submit: overflow check\n");
		return -EINVAL;
	}

	/* Check alignment */
	if ((((unsigned long) &user_iocb->completion_list) &
	     (sizeof(user_iocb->completion_list) - 1)) ||
	    (((unsigned long) completion_list) &
	     (sizeof(completion_list) - 1)))
		return -EFAULT;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (unlikely(!req))
		return -ENOMEM;

	if (get_user_pages_fast((unsigned long) completion_list,
				1, 1, &req->list_head) != 1)
		goto err;

	if (get_user_pages_fast((unsigned long) &user_iocb->completion_list,
				1, 1, &req->list_entry) != 1)
		goto err;

	req->list_head_offset = ((unsigned long) completion_list) &
		(PAGE_SIZE - 1);
	req->list_entry_offset = ((unsigned long) &user_iocb->completion_list) &
		(PAGE_SIZE - 1);

	req->req.ki_ctx		= (struct kioctx *) &acall_ctx;
	req->req.ki_obj.user	= user_iocb;
	req->req.ki_user_data	= iocb->aio_data;
	req->req.ki_pos		= iocb->aio_offset;
	req->req.ki_nbytes	= iocb->aio_nbytes;

	/*
	 * ki_obj.user must point to the right iocb before making the kiocb
	 * cancellable by setting ki_cancel = NULL:
	 */
	smp_wmb();
	req->req.ki_cancel = NULL;

	ret = put_user(req->req.ki_id, &user_iocb->aio_key);
	if (unlikely(ret)) {
		pr_debug("EFAULT: aio_key\n");
		goto err;
	}

	req->req.ki_filp = fget(iocb->aio_fildes);
	if (unlikely(!req->req.ki_filp)) {
		ret = -EBADF;
		goto err;
	}

	ret = aio_run_iocb(&req->req, iocb->aio_lio_opcode,
			   (char __user *)(unsigned long)iocb->aio_buf,
			   compat);
	if (ret)
		goto err;

	return 0;
err:
	kiocb_noctx_free(&req->req);
	return ret;
}

SYSCALL_DEFINE2(io_submit_noctx,
		struct iocb_noctx __user *, user_iocb,
		struct iocb_noctx __user *, completion_list)
{
	struct iocb_noctx iocb;

	if (unlikely(copy_from_user(&iocb, user_iocb, sizeof(iocb))))
		return -EFAULT;

	return io_submit_one_noctx(user_iocb, &iocb, completion_list, 0);
}

/* Core code */

static inline struct kiocb *kiocb_from_id(struct kioctx *ctx, unsigned id)
{
	struct page *p = ctx->kiocb_pages[id / KIOCBS_PER_PAGE];

	return p
		? ((struct kiocb *) page_address(p)) + (id % KIOCBS_PER_PAGE)
		: NULL;
}

void kiocb_set_cancel_fn(struct kiocb *req, kiocb_cancel_fn *cancel)
{
	kiocb_cancel_fn *p, *old = req->ki_cancel;

	do {
		if (old == KIOCB_CANCELLED) {
			cancel(req);
			return;
		}

		p = old;
		old = cmpxchg(&req->ki_cancel, old, cancel);
	} while (old != p);
}
EXPORT_SYMBOL(kiocb_set_cancel_fn);

void kiocb_cancel(struct kiocb *req)
{
	kiocb_cancel_fn *old, *new, *cancel = req->ki_cancel;

	local_irq_disable();

	do {
		if (cancel == KIOCB_CANCELLING ||
		    cancel == KIOCB_CANCELLED)
			goto out;

		old = cancel;
		new = cancel ? KIOCB_CANCELLING : KIOCB_CANCELLED;

		cancel = cmpxchg(&req->ki_cancel, old, KIOCB_CANCELLING);
	} while (old != cancel);

	if (cancel) {
		cancel(req);
		smp_wmb();
		req->ki_cancel = KIOCB_CANCELLED;
	}
out:
	local_irq_enable();
}

void ioctx_free(struct kioctx *ctx)
{
	unsigned i;

	for (i = 0; i < DIV_ROUND_UP(ctx->nr_kiocbs, KIOCBS_PER_PAGE); i++)
		if (ctx->kiocb_pages[i])
			__free_page(ctx->kiocb_pages[i]);

	kfree(ctx->kiocb_pages);
	tag_pool_free(&ctx->kiocb_tags);
}

void cancel_all_kiocbs(struct kioctx *ctx)
{
	unsigned i;

	for (i = 0; i < ctx->nr_kiocbs; i++) {
		struct kiocb *req = kiocb_from_id(ctx, i);

		if (req)
			kiocb_cancel(req);
	}
}

int ioctx_init(struct kioctx *ctx, unsigned nr_kiocbs)
{
	int ret;

	ctx->nr_kiocbs = nr_kiocbs;

	init_waitqueue_head(&ctx->wait);

	ret = tag_pool_init(&ctx->kiocb_tags, ctx->nr_kiocbs);
	if (ret)
		return ret;

	ctx->kiocb_pages =
		kzalloc(DIV_ROUND_UP(ctx->nr_kiocbs, KIOCBS_PER_PAGE) *
			sizeof(struct page *), GFP_KERNEL);
	if (!ctx->kiocb_pages)
		goto err;

	return 0;
err:
	tag_pool_free(&ctx->kiocb_tags);
	return ret;
}

/* wait_on_sync_kiocb:
 *	Waits on the given sync kiocb to complete.
 */
ssize_t wait_on_sync_kiocb(struct kiocb *req)
{
	while (!req->ki_ctx) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (req->ki_ctx)
			break;
		io_schedule();
	}
	__set_current_state(TASK_RUNNING);
	return req->ki_user_data;
}
EXPORT_SYMBOL(wait_on_sync_kiocb);

void kiocb_free(struct kiocb *req)
{
	if (req->ki_eventfd) {
		eventfd_signal(req->ki_eventfd, 1);
		eventfd_ctx_put(req->ki_eventfd);
	}

	if (req->ki_filp)
		fput(req->ki_filp);

	if (req->ki_ctx != &acall_ctx)
		tag_free(&req->ki_ctx->kiocb_tags, req->ki_id);
	else
		kiocb_noctx_free(req);
}

/* aio_get_req
 *	Allocate a slot for an aio request.
 * Returns NULL if no requests are free.
 */
struct kiocb *aio_get_req(struct kioctx *ctx)
{
	struct kiocb *req;
	unsigned id;

	id = tag_alloc(&ctx->kiocb_tags, false);
	if (!id)
		return NULL;

	req = kiocb_from_id(ctx, id);
	if (!req) {
		unsigned i, page_nr = id / KIOCBS_PER_PAGE;
		struct page *p = alloc_page(GFP_KERNEL);
		if (!p)
			goto err;

		req = page_address(p);

		for (i = 0; i < KIOCBS_PER_PAGE; i++) {
			req[i].ki_cancel = KIOCB_CANCELLED;
			req[i].ki_id = page_nr * KIOCBS_PER_PAGE + i;
		}

		smp_wmb();

		if (cmpxchg(&ctx->kiocb_pages[page_nr], NULL, p) != NULL)
			__free_page(p);
	}

	req = kiocb_from_id(ctx, id);

	/*
	 * Can't set ki_cancel to NULL until we're ready for it to be
	 * cancellable - leave it as KIOCB_CANCELLED until then
	 */
	memset(req, 0, offsetof(struct kiocb, ki_cancel));
	req->ki_ctx = ctx;

	return req;
err:
	tag_free(&req->ki_ctx->kiocb_tags, id);
	return NULL;
}

/*
 * exit_aio: called when the last user of mm goes away.  At this point, there is
 * no way for any new requests to be submited or any of the io_* syscalls to be
 * called on the context.
 *
 * There may be outstanding kiocbs, but free_ioctx() will explicitly wait on
 * them.
 */
void exit_aio(struct mm_struct *mm)
{
	ioctx_v1_exit_aio(mm);
	ioctx_v2_exit_aio(mm);
}

static inline unsigned kioctx_ring_put(struct batch_complete *batch,
				       struct kioctx *ctx, struct kiocb *req,
				       unsigned tail)
{
	switch (ctx->version) {
	case KIOCTX_VERSION_1:
		return ioctx_v1_ring_put(ctx, req, tail);
	case KIOCTX_VERSION_2:
		return ioctx_v2_ring_put(batch, ctx, req, tail);
	case KIOCTX_VERSION_ACALL:
		return noctx_ring_put(ctx, req, tail);
	}

	return tail;
}

static inline void kioctx_ring_unlock(struct kioctx *ctx, unsigned tail)
{
	if (!ctx)
		return;

	switch (ctx->version) {
	case KIOCTX_VERSION_1:
		return ioctx_v1_ring_unlock(ctx, tail);
	case KIOCTX_VERSION_2:
		return ioctx_v2_ring_unlock(ctx, tail);
	case KIOCTX_VERSION_ACALL:
		/* Nothing */
		break;
	}
}

void batch_complete_aio(struct batch_complete *batch)
{
	struct kioctx *ctx = NULL;
	struct rb_node *n;
	unsigned long flags;
	unsigned tail = 0;

	n = rb_first(&batch->kiocb);
	if (!n)
		return;

	/*
	 * Take rcu_read_lock() in case the kioctx is being destroyed, as we
	 * need to issue a wakeup after incrementing reqs_available.
	 */
	rcu_read_lock();
	local_irq_save(flags);

	while (n) {
		struct kiocb *req = container_of(n, struct kiocb, ki_node);
		n = rb_next(n);

		if (req->ki_ctx != ctx) {
			kioctx_ring_unlock(ctx, tail);

			ctx = req->ki_ctx;
			tail = kioctx_ring_lock(ctx);
		}

		tail = kioctx_ring_put(batch, ctx, req, tail);
	}

	kioctx_ring_unlock(ctx, tail);
	local_irq_restore(flags);
	rcu_read_unlock();

	n = rb_first(&batch->kiocb);
	while (n) {
		struct kiocb *req = container_of(n, struct kiocb, ki_node);

		if (n->rb_right) {
			n->rb_right->__rb_parent_color = n->__rb_parent_color;
			n = n->rb_right;

			while (n->rb_left)
				n = n->rb_left;
		} else {
			n = rb_parent(n);
		}

		kiocb_free(req);
	}
}
EXPORT_SYMBOL(batch_complete_aio);

/* aio_complete_batch
 *	Called when the io request on the given iocb is complete; @batch may be
 *	NULL.
 */
void aio_complete_batch(struct kiocb *req, long res, long res2,
			struct batch_complete *batch)
{
	kiocb_cancel_fn *old = NULL, *cancel = req->ki_cancel;

	do {
		if (cancel == KIOCB_CANCELLING) {
			cpu_relax();
			cancel = req->ki_cancel;
			continue;
		}

		old = cancel;
		cancel = cmpxchg(&req->ki_cancel, old, KIOCB_CANCELLED);
	} while (old != cancel);

	req->ki_res = res;
	req->ki_res2 = res2;

	/*
	 * Special case handling for sync iocbs:
	 *  - events go directly into the iocb for fast handling
	 *  - the sync task with the iocb in its stack holds the single iocb
	 *    ref, no other paths have a way to get another ref
	 *  - the sync task helpfully left a reference to itself in the iocb
	 */
	if (is_sync_kiocb(req)) {
		req->ki_user_data = req->ki_res;
		smp_wmb();
		req->ki_ctx = ERR_PTR(-EXDEV);
		wake_up_process(req->ki_obj.tsk);
	} else if (batch) {
		int res;
		struct kiocb *t;
		struct rb_node **n = &batch->kiocb.rb_node, *parent = NULL;

		while (*n) {
			parent = *n;
			t = container_of(*n, struct kiocb, ki_node);

			res = req->ki_ctx != t->ki_ctx
				? req->ki_ctx < t->ki_ctx
				: req->ki_eventfd != t->ki_eventfd
				? req->ki_eventfd < t->ki_eventfd
				: req < t;

			n = res ? &(*n)->rb_left : &(*n)->rb_right;
		}

		rb_link_node(&req->ki_node, parent, n);
		rb_insert_color(&req->ki_node, &batch->kiocb);
	} else {
		struct batch_complete batch_stack;

		memset(&req->ki_node, 0, sizeof(req->ki_node));
		batch_stack.kiocb.rb_node = &req->ki_node;

		batch_complete_aio(&batch_stack);
	}
}
EXPORT_SYMBOL(aio_complete_batch);

typedef ssize_t (aio_rw_op)(struct kiocb *, const struct iovec *,
			    unsigned long, loff_t);

static ssize_t aio_setup_vectored_rw(struct kiocb *kiocb,
				     int rw, char __user *buf,
				     unsigned long *nr_segs,
				     struct iovec **iovec,
				     bool compat)
{
	ssize_t ret;

	*nr_segs = kiocb->ki_nbytes;

#ifdef CONFIG_COMPAT
	if (compat)
		ret = compat_rw_copy_check_uvector(rw,
				(struct compat_iovec __user *)buf,
				*nr_segs, 1, *iovec, iovec);
	else
#endif
		ret = rw_copy_check_uvector(rw,
				(struct iovec __user *)buf,
				*nr_segs, 1, *iovec, iovec);
	if (ret < 0)
		return ret;

	/* ki_nbytes now reflect bytes instead of segs */
	kiocb->ki_nbytes = ret;
	return 0;
}

static ssize_t aio_setup_single_vector(struct kiocb *kiocb,
				       int rw, char __user *buf,
				       unsigned long *nr_segs,
				       struct iovec *iovec)
{
	if (unlikely(!access_ok(!rw, buf, kiocb->ki_nbytes)))
		return -EFAULT;

	iovec->iov_base = buf;
	iovec->iov_len = kiocb->ki_nbytes;
	*nr_segs = 1;
	return 0;
}

/*
 * aio_setup_iocb:
 *	Performs the initial checks and aio retry method
 *	setup for the kiocb at the time of io submission.
 */
ssize_t aio_run_iocb(struct kiocb *req, unsigned opcode,
		     char __user *buf, bool compat)
{
	struct file *file = req->ki_filp;
	ssize_t ret;
	unsigned long nr_segs;
	int rw;
	fmode_t mode;
	aio_rw_op *rw_op;
	struct iovec inline_vec, *iovec = &inline_vec;

	switch (opcode) {
	case IOCB_CMD_PREAD:
	case IOCB_CMD_PREADV:
		mode	= FMODE_READ;
		rw	= READ;
		rw_op	= file->f_op->aio_read;
		goto rw_common;

	case IOCB_CMD_PWRITE:
	case IOCB_CMD_PWRITEV:
		mode	= FMODE_WRITE;
		rw	= WRITE;
		rw_op	= file->f_op->aio_write;
		goto rw_common;
rw_common:
		if (unlikely(!(file->f_mode & mode)))
			return -EBADF;

		if (!rw_op)
			return -EINVAL;

		ret = (opcode == IOCB_CMD_PREADV ||
		       opcode == IOCB_CMD_PWRITEV)
			? aio_setup_vectored_rw(req, rw, buf, &nr_segs,
						&iovec, compat)
			: aio_setup_single_vector(req, rw, buf, &nr_segs,
						  iovec);
		if (ret)
			return ret;

		ret = rw_verify_area(rw, file, &req->ki_pos, req->ki_nbytes);
		if (ret < 0) {
			if (iovec != &inline_vec)
				kfree(iovec);
			return ret;
		}

		req->ki_nbytes = ret;

		/* XXX: move/kill - rw_verify_area()? */
		/* This matches the pread()/pwrite() logic */
		if (req->ki_pos < 0) {
			ret = -EINVAL;
			break;
		}

		ret = rw_op(req, iovec, nr_segs, req->ki_pos);
		break;

	case IOCB_CMD_FDSYNC:
		if (!file->f_op->aio_fsync)
			return -EINVAL;

		ret = file->f_op->aio_fsync(req, 1);
		break;

	case IOCB_CMD_FSYNC:
		if (!file->f_op->aio_fsync)
			return -EINVAL;

		ret = file->f_op->aio_fsync(req, 0);
		break;

	default:
		pr_debug("EINVAL: no operation provided\n");
		return -EINVAL;
	}

	if (iovec != &inline_vec)
		kfree(iovec);

	if (ret != -EIOCBQUEUED) {
		/*
		 * There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		if (unlikely(ret == -ERESTARTSYS || ret == -ERESTARTNOINTR ||
			     ret == -ERESTARTNOHAND || ret == -ERESTART_RESTARTBLOCK))
			ret = -EINTR;
		aio_complete(req, ret, 0);
	}

	return 0;
}

/* lookup_kiocb
 *	Finds a given iocb for cancellation.
 */
struct kiocb *lookup_kiocb(struct kioctx *ctx, struct iocb __user *iocb,
			   u32 key)
{
	struct kiocb *req;

	if (key > ctx->nr_kiocbs)
		return NULL;

	req = kiocb_from_id(ctx, key);

	if (req && req->ki_obj.user == iocb)
		return req;

	return NULL;
}
