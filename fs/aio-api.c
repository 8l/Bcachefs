
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

#define KIOCTX_V2_MAX_REQS	4096
#define KIOCTX_V2_RING_ORDER	1

struct kioctx_v2 {
	struct kioctx		ctx;

	struct percpu_ref	users;

	/* This needs improving */
	unsigned long		user_id;
	struct hlist_node	list;

	struct rcu_head		rcu_head;
	struct work_struct	rcu_work;

	struct io_event_v2	*ring;
	unsigned		ring_mask;

	unsigned long		head;
	unsigned long		tail;
	struct list_head	overflow;
};

static inline unsigned __io_event_bytes(unsigned attr_bytes)
{
	return sizeof(struct io_event_v2) + attr_bytes;
}

static inline unsigned io_event_bytes(struct io_event_v2 *ev)
{
	return __io_event_bytes(ev->attr_bytes);
}

static inline void *ring_ptr(struct kioctx_v2 *ctx, unsigned offset)
{
	return ((void *) ctx->ring) + (offset & ctx->ring_mask);
}

static inline int ioctx_v2_ring_copy(struct kioctx_v2 *ctx, struct kiocb *req,
				     unsigned *tail)
{
	struct io_event_v2 *ev;
	unsigned bytes = sizeof(*ev);
	unsigned avail = (ctx->head - *tail - 1) & ctx->ring_mask;

	if (unlikely(bytes > avail))
		return -1;

	ev = ring_ptr(ctx, *tail);
	*tail += bytes;

	ev->data	= req->ki_user_data;
	ev->res		= req->ki_res;
	ev->res2	= req->ki_res2;
	ev->attr_bytes	= 0;

	return 0;
}

static inline unsigned ioctx_v2_copy_overflow(struct kioctx_v2 *ctx, unsigned *tail)
{

	while (!list_empty(&ctx->overflow)) {
		struct kiocb *req = list_first_entry(&ctx->overflow,
						     struct kiocb,
						     ki_list);

		if (ioctx_v2_ring_copy(ctx, req, tail))
			return -1;

		list_del_init(&req->ki_list);
		kiocb_free(req);
	}

	return 0;
}

unsigned ioctx_v2_ring_put(struct batch_complete *batch,
			   struct kioctx *_ctx, struct kiocb *req,
			   unsigned tail)
{
	struct kioctx_v2 *ctx = container_of(_ctx, struct kioctx_v2, ctx);

	if (ioctx_v2_copy_overflow(ctx, &tail) ||
	    ioctx_v2_ring_copy(ctx, req, &tail)) {
		rb_erase(&req->ki_node, &batch->kiocb);
		list_add_tail(&req->ki_list, &ctx->overflow);
	}

	pr_debug("%p[%u]: %p: %p %Lx %lx %lx\n",
		 ctx, tail, req, req->ki_obj.user, req->ki_user_data,
		 req->ki_res, req->ki_res2);

	return tail;
}

void ioctx_v2_ring_unlock(struct kioctx *_ctx, unsigned tail)
{
	struct kioctx_v2 *ctx = container_of(_ctx, struct kioctx_v2, ctx);

	/* make event visible before updating tail */
	smp_wmb();

	ctx->tail = tail;

	/* unlock, make new tail visible before checking waitlist */
	smp_mb();

	ctx->ctx.tail = tail;

	if (waitqueue_active(&ctx->ctx.wait)) {
		/* Irqs are already disabled */
		spin_lock(&ctx->ctx.wait.lock);
		wake_up_locked(&ctx->ctx.wait);
		spin_unlock(&ctx->ctx.wait.lock);
	}
}

static struct kioctx_v2 *ioctx_lookup(unsigned long ctx_id)
{
	struct mm_struct *mm = current->mm;
	struct kioctx_v2 *ctx, *ret = NULL;

	rcu_read_lock();

	hlist_for_each_entry_rcu(ctx, &mm->ioctx_v2_list, list) {
		if (ctx->user_id == ctx_id) {
			percpu_ref_get(&ctx->users);
			ret = ctx;
			break;
		}
	}

	rcu_read_unlock();

	if (!ret)
		pr_debug("invalid context id\n");

	return ret;
}

static void ioctx_free_rcu(struct rcu_head *head)
{
	struct kioctx_v2 *ctx = container_of(head, struct kioctx_v2, rcu_head);

	pr_debug("freeing %p\n", ctx);

	free_pages((unsigned long) ctx->ring, KIOCTX_V2_RING_ORDER);
	ioctx_free(&ctx->ctx);
	kfree(ctx);
}

static void ioctx_v2_free(struct kioctx_v2 *ctx)
{
	cancel_all_kiocbs(&ctx->ctx);

	/* XXX: wait on all kiocbs */

	/*
	 * Here the call_rcu() is between the wait_event() for reqs_active to
	 * hit 0, and freeing the ioctx.
	 *
	 * aio_complete() decrements reqs_active, but it has to touch the ioctx
	 * after to issue a wakeup so we use rcu.
	 */
	call_rcu(&ctx->rcu_head, ioctx_free_rcu);
}

static void ioctx_put(struct kioctx_v2 *ctx)
{
	if (percpu_ref_put(&ctx->users))
		ioctx_v2_free(ctx);
}

static void ioctx_kill_work(struct work_struct *work)
{
	struct kioctx_v2 *ctx = container_of(work, struct kioctx_v2, rcu_work);

	wake_up_all(&ctx->ctx.wait);
	ioctx_put(ctx);
}

static void ioctx_kill(struct kioctx_v2 *ctx)
{
	if (percpu_ref_kill(&ctx->users)) {
		hlist_del_rcu(&ctx->list);
		/* Between hlist_del_rcu() and dropping the initial ref */
		synchronize_rcu();

		/*
		 * We can't punt to workqueue here because put_ioctx() ->
		 * free_ioctx() will unmap the ringbuffer, and that has to be
		 * done in the original process's context. kill_ioctx_rcu/work()
		 * exist for exit_aio(), as in that path free_ioctx() won't do
		 * the unmap.
		 */
		ioctx_kill_work(&ctx->rcu_work);
	}
}

static struct kioctx_v2 *ioctx_alloc(unsigned features)
{
	struct mm_struct *mm = current->mm;
	struct kioctx_v2 *ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ctx->overflow);

	percpu_ref_init(&ctx->users);
	rcu_read_lock();
	percpu_ref_get(&ctx->users);
	rcu_read_unlock();

	ctx->user_id = (unsigned long) ctx;
	ctx->ring_mask = (PAGE_SIZE << KIOCTX_V2_RING_ORDER) - 1;

	ret = ENOMEM;
	ctx->ring = (void *) __get_free_pages(GFP_KERNEL,
					      KIOCTX_V2_RING_ORDER);
	if (!ctx->ring)
		goto out_freectx;

	ret = ioctx_init(&ctx->ctx, KIOCTX_V2_MAX_REQS);
	if (ret)
		goto out_freering;

	/* now link into global list. */
	spin_lock(&mm->ioctx_lock);
	hlist_add_head_rcu(&ctx->list, &mm->ioctx_v2_list);
	spin_unlock(&mm->ioctx_lock);

	pr_debug("allocated ioctx %p[%ld]: mm=%p\n",
		 ctx, ctx->user_id, mm);
	return ctx;

out_freering:
	free_pages((unsigned long) ctx->ring, KIOCTX_V2_RING_ORDER);
out_freectx:
	kfree(ctx);
	pr_debug("error allocating ioctx %d\n", ret);
	return ERR_PTR(ret);
}

/* sys_io_setup:
 *	Create an aio_context capable of receiving at least nr_events.
 *	ctxp must not point to an aio_context that already exists, and
 *	must be initialized to 0 prior to the call.  On successful
 *	creation of the aio_context, *ctxp is filled in with the resulting
 *	handle.  May fail with -EINVAL if *ctxp is not initialized,
 *	if the specified nr_events exceeds internal limits.  May fail
 *	with -EAGAIN if the specified nr_events exceeds the user's limit
 *	of available events.  May fail with -ENOMEM if insufficient kernel
 *	resources are available.  May fail with -EFAULT if an invalid
 *	pointer is passed for ctxp.  Will fail with -ENOSYS if not
 *	implemented.
 */
SYSCALL_DEFINE2(io_setup2, aio_context_t __user *, ctxp,
		unsigned, features)
{
	struct kioctx_v2 *ctx = NULL;
	unsigned long ctx_id;
	long ret;

	if (features)
		return -EINVAL;

	ret = get_user(ctx_id, ctxp);
	if (unlikely(ret))
		return ret;

	if (unlikely(ctx_id)) {
		pr_debug("EINVAL: io_setup: ctx %lu\n", ctx_id);
		return -EINVAL;
	}

	ctx = ioctx_alloc(features);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ret = put_user(ctx->user_id, ctxp);
	if (ret)
		ioctx_kill(ctx);

	ioctx_put(ctx);
	return ret;
}

static void ioctx_kill_rcu(struct rcu_head *head)
{
	struct kioctx_v2 *ctx = container_of(head, struct kioctx_v2, rcu_head);

	INIT_WORK(&ctx->rcu_work, ioctx_kill_work);
	schedule_work(&ctx->rcu_work);
}

void ioctx_v2_exit_aio(struct mm_struct *mm)
{
	struct kioctx_v2 *ctx;
	struct hlist_node *n;

	hlist_for_each_entry_safe(ctx, n, &mm->ioctx_v2_list, list)
		if (percpu_ref_kill(&ctx->users)) {
			hlist_del_rcu(&ctx->list);
			call_rcu(&ctx->rcu_head, ioctx_kill_rcu);
		}
}

/* sys_io_destroy:
 *	Destroy the aio_context specified.  May cancel any outstanding
 *	AIOs and block on completion.  Will fail with -ENOSYS if not
 *	implemented.  May fail with -EINVAL if the context pointed to
 *	is invalid.
 */
SYSCALL_DEFINE1(io_destroy2, aio_context_t, ctx_id)
{
	struct kioctx_v2 *ctx;

	ctx = ioctx_lookup(ctx_id);
	if (!ctx)
		return -EINVAL;

	ioctx_kill(ctx);
	ioctx_put(ctx);
	return 0;
}

static const size_t iocb_attr_sizes[] = {
//	[IOCB_ATTR_proxy_pid] = sizeof(struct iocb_attr_proxy_pid),
};

static const size_t iocb_attr_ret_sizes[] = {
//	[IOCB_ATTR_proxy_pid] = sizeof(struct iocb_attr_ret_proxy_pid),
};

static int aio_setup_attrs(struct iocb_v2 __user *user_iocb,
			   struct iocb_v2 *iocb, struct kiocb *req)
{
	struct iocb_attr *attr, *end;
	struct iocb_attr_ret *attr_ret;
	int ret;

	if (!iocb->aio_attr_bytes)
		return 0;

	if (unlikely(iocb->aio_attr_bytes > PAGE_SIZE))
		return -EFAULT;

	req->ki_attr_bytes = iocb->aio_attr_bytes;

	req->ki_attrs = kmalloc(req->ki_attr_bytes, GFP_KERNEL);
	if (unlikely(!req->ki_attrs))
		return  -ENOMEM;

	ret = -EFAULT;
	if (unlikely(copy_from_user(req->ki_attrs,
				    user_iocb->attrs,
				    req->ki_attr_bytes)))
		goto err_free;

	end = ((void *) req->ki_attrs) + req->ki_attr_bytes;

	ret = -EINVAL;
	for_each_iocb_attr(req, attr) {
		if (attr > end)
			goto err_free;

		if (attr->size < sizeof(struct iocb_attr))
			goto err_free;

		if (attr->id >= IOCB_ATTR_MAX)
			goto err_free;

		if (attr->size != iocb_attr_sizes[attr->id])
			goto err_free;

		req->ki_attr_ret_bytes += iocb_attr_ret_sizes[attr->id];
	}

	ret = -ENOMEM;
	req->ki_attr_rets = kmalloc(req->ki_attr_ret_bytes, GFP_KERNEL);
	if (!req->ki_attr_rets)
		goto err_free;

	attr_ret = req->ki_attr_rets;

	for_each_iocb_attr(req, attr) {
		attr_ret->cookie = attr->cookie;
		attr_ret->size = iocb_attr_ret_sizes[attr->id];
		attr_ret->ret = -EINVAL;

		attr->cookie = (unsigned long) attr_ret;

		attr_ret = ((void *) attr_ret) + attr_ret->size;
	}

	return 0;
err_free:
	kfree(req->ki_attrs);
	req->ki_attrs = NULL;
	return ret;
}

static int io_submit_one(struct kioctx_v2 *ctx,
			    struct iocb_v2 __user *user_iocb,
			    struct iocb_v2 *iocb, bool compat)
{
	struct kiocb *req;
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

	req = aio_get_req(&ctx->ctx);
	if (unlikely(!req))
		return -ENOMEM;

	ret = aio_setup_attrs(user_iocb, iocb, req);
	if (ret)
		goto out_put_req;

	req->ki_filp = fget(iocb->aio_fildes);
	if (unlikely(!req->ki_filp)) {
		ret = -EBADF;
		goto out_put_req;
	}

	ret = put_user(req->ki_id, &user_iocb->aio_key);
	if (unlikely(ret)) {
		pr_debug("EFAULT: aio_key\n");
		goto out_put_req;
	}

	req->ki_obj.user = user_iocb;
	req->ki_user_data = iocb->aio_data;
	req->ki_pos = iocb->aio_offset;
	req->ki_nbytes = iocb->aio_nbytes;

	/*
	 * ki_obj.user must point to the right iocb before making the kiocb
	 * cancellable by setting ki_cancel = NULL:
	 */
	smp_wmb();
	req->ki_cancel = NULL;

	ret = aio_run_iocb(req, iocb->aio_lio_opcode,
			   (char __user *)(unsigned long)iocb->aio_buf,
			   compat);
	if (ret)
		goto out_put_req;

	return 0;
out_put_req:
	kiocb_free(req);
	return ret;
}

static long do_io_submit_v2(aio_context_t ctx_id, long nr,
			    struct iocb_v2 __user *__user *iocbpp, bool compat)
{
	struct kioctx_v2 *ctx;
	long ret = 0;
	int i = 0;
	struct blk_plug plug;

	if (unlikely(nr < 0))
		return -EINVAL;

	if (unlikely(nr > LONG_MAX/sizeof(*iocbpp)))
		nr = LONG_MAX/sizeof(*iocbpp);

	if (unlikely(!access_ok(VERIFY_READ, iocbpp, (nr*sizeof(*iocbpp)))))
		return -EFAULT;

	ctx = ioctx_lookup(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	blk_start_plug(&plug);

	/*
	 * AKPM: should this return a partial result if some of the IOs were
	 * successfully submitted?
	 */
	for (i=0; i<nr; i++) {
		struct iocb_v2 __user *user_iocb;
		struct iocb_v2 tmp;

		if (unlikely(__get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		if (unlikely(copy_from_user(&tmp, user_iocb, sizeof(tmp)))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, user_iocb, &tmp, compat);
		if (ret)
			break;
	}
	blk_finish_plug(&plug);

	ioctx_put(ctx);
	return i ? i : ret;
}

SYSCALL_DEFINE3(io_submit2, aio_context_t, ctx_id, long, nr,
		struct iocb_v2 __user * __user *, iocbpp)
{
	return do_io_submit_v2(ctx_id, nr, iocbpp, 0);
}

/* sys_io_cancel:
 *	Attempts to cancel an iocb previously passed to io_submit.  If
 *	the operation is successfully cancelled, the resulting event is
 *	copied into the memory pointed to by result without being placed
 *	into the completion queue and 0 is returned.  May fail with
 *	-EFAULT if any of the data structures pointed to are invalid.
 *	May fail with -EINVAL if aio_context specified by ctx_id is
 *	invalid.  May fail with -EAGAIN if the iocb specified was not
 *	cancelled.  Will fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE2(io_cancel2, aio_context_t, ctx_id,
		struct iocb_v2 __user *, iocb)
{
	struct kioctx_v2 *ctx;
	struct kiocb *kiocb;
	u32 key;
	int ret;

	ret = get_user(key, &iocb->aio_key);
	if (unlikely(ret))
		return -EFAULT;

	ctx = ioctx_lookup(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	kiocb = lookup_kiocb(&ctx->ctx, (void *) iocb, key);
	if (kiocb) {
		kiocb_cancel(kiocb);
		/*
		 * The result argument is no longer used - the io_event is
		 * always delivered via the ring buffer. -EINPROGRESS indicates
		 * cancellation is progress:
		 */
		ret = -EINPROGRESS;
	}

	ioctx_put(ctx);
	return ret;
}

static long aio_read_events_ring(struct kioctx_v2 *ctx,
				 void __user *buf, long nbytes)
{
	unsigned old, avail;
	unsigned head = ctx->head;
	unsigned tail = ctx->tail;
	long ret;
	int copy_ret;
	bool checked_overflow = false;

	pr_debug("h%u t%u m%u\n", head, tail, ctx->ring_mask);
retry:
	ret = 0;
	old = head;

	if (head == tail) {
		if (checked_overflow ||
		    list_empty_careful(&ctx->overflow))
			return 0;

		tail = kioctx_ring_lock(&ctx->ctx);
		ioctx_v2_copy_overflow(ctx, &tail);
		ioctx_v2_ring_unlock(&ctx->ctx, tail);

		checked_overflow = true;
		goto retry;
	}

	avail = (tail - head) & ctx->ring_mask;

	if (avail > nbytes - ret) {
		avail = 0;

		while (1) {
			u64 *attr_bytes = ring_ptr(ctx, head + avail +
				 offsetof(struct io_event_v2, attr_bytes));

			if (avail + __io_event_bytes(*attr_bytes) >
			    nbytes - ret)
				break;

			avail += __io_event_bytes(*attr_bytes);
		}

		if (!avail) {
			/* Return an error */
		}
	}

	while (avail) {
		struct io_event_v2 *ev = ring_ptr(ctx, head);
		unsigned to_copy = min(avail, -head & ctx->ring_mask);

		copy_ret = copy_to_user(buf + ret, ev, to_copy);

		if (unlikely(copy_ret))
			return -EFAULT;

		avail -= to_copy;
		ret += to_copy;
		head += to_copy;
	}

	head = cmpxchg(&ctx->head, old, head);
	if (head != old)
		goto retry;

	pr_debug("%li  h%u t%u\n", ret, head, tail);

	return ret;
}

static bool aio_read_events(struct kioctx_v2 *ctx, void __user *buf,
			    size_t nbytes, long *done)
{
	long ret = aio_read_events_ring(ctx, buf + *done, nbytes - *done);

	if (ret > 0)
		*done += ret;

	if (unlikely(percpu_ref_dead(&ctx->users)))
		ret = -EINVAL;

	if (!*done)
		*done = ret;

	return *done;
}

static long read_events(struct kioctx_v2 *ctx, void __user *buf,
			size_t nbytes, struct timespec __user *timeout)
{
	ktime_t until = { .tv64 = KTIME_MAX };
	long ret = 0;

	if (timeout) {
		struct timespec	ts;

		if (unlikely(copy_from_user(&ts, timeout, sizeof(ts))))
			return -EFAULT;

		until = timespec_to_ktime(ts);
	}

	/*
	 * Note that aio_read_events() is being called as the conditional - i.e.
	 * we're calling it after prepare_to_wait() has set task state to
	 * TASK_INTERRUPTIBLE.
	 *
	 * But aio_read_events() can block, and if it blocks it's going to flip
	 * the task state back to TASK_RUNNING.
	 *
	 * This should be ok, provided it doesn't flip the state back to
	 * TASK_RUNNING and return 0 too much - that causes us to spin. That
	 * will only happen if the mutex_lock() call blocks, and we then find
	 * the ringbuffer empty. So in practice we should be ok, but it's
	 * something to be aware of when touching this code.
	 */
	wait_event_interruptible_hrtimeout(ctx->ctx.wait,
			aio_read_events(ctx, buf, nbytes, &ret), until);

	if (!ret && signal_pending(current))
		ret = -EINTR;

	return ret;
}

/* io_getevents:
 *	Attempts to read at least min_nr events and up to nr events from
 *	the completion queue for the aio_context specified by ctx_id. If
 *	it succeeds, the number of read events is returned. May fail with
 *	-EINVAL if ctx_id is invalid, if min_nr is out of range, if nr is
 *	out of range, if timeout is out of range.  May fail with -EFAULT
 *	if any of the memory specified is invalid.  May return 0 or
 *	< min_nr if the timeout specified by timeout has elapsed
 *	before sufficient events are available, where timeout == NULL
 *	specifies an infinite timeout. Note that the timeout pointed to by
 *	timeout is relative and will be updated if not NULL and the
 *	operation blocks. Will fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE4(io_getevents2, aio_context_t, ctx_id,
		struct io_event_v2 __user *, events,
		size_t, nbytes, struct timespec __user *, timeout)
{
	struct kioctx_v2 *ctx;
	long ret;

	ctx = ioctx_lookup(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	ret = read_events(ctx, events, nbytes, timeout);

	ioctx_put(ctx);
	asmlinkage_protect(4, ret, ctx_id, nbytes, events, timeout);
	return ret;
}
