
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

/*------ sysctl variables----*/
static DEFINE_SPINLOCK(aio_nr_lock);
unsigned long aio_nr;		/* current system wide number of aio requests */
unsigned long aio_max_nr = 0x10000; /* system wide maximum number of aio requests */
/*----end sysctl variables---*/

#define AIO_RING_MAGIC			0xa10a10a1
#define AIO_RING_COMPAT_FEATURES	1
#define AIO_RING_INCOMPAT_FEATURES	0
struct aio_ring_v1 {
	unsigned	id;	/* kernel internal index number */
	unsigned	nr;	/* number of io_events */
	unsigned	head;
	unsigned	tail;

	unsigned	magic;
	unsigned	compat_features;
	unsigned	incompat_features;
	unsigned	header_length;	/* size of aio_ring_v1 */


	struct io_event		io_events[0];
}; /* 128 bytes + ring size */

#define AIO_RING_PAGES	8

struct kioctx_cpu {
	unsigned		reqs_available;
};

struct kioctx_v1 {
	struct kioctx		ctx;

	struct percpu_ref	users;

	/* This needs improving */
	unsigned long		user_id;
	struct hlist_node	list;

	struct rcu_head		rcu_head;
	struct work_struct	rcu_work;

	struct __percpu kioctx_cpu *cpu;

	/*
	 * For percpu reqs_available, number of slots we move to/from global
	 * counter at a time:
	 */
	unsigned		req_batch;
	/*
	 * This is what userspace passed to io_setup(), it's not used for
	 * anything but counting against the global max_reqs quota.
	 *
	 * The real limit is nr_events - 1, which will be larger (see
	 * aio_setup_ring())
	 */
	unsigned		max_reqs;

	struct page		**ring_pages;
	long			nr_pages;

	/* Size of ringbuffer, in units of struct io_event */
	unsigned		nr_events;

	unsigned long		mmap_base;
	unsigned long		mmap_size;

	struct {
		struct mutex	ring_lock;
	} ____cacheline_aligned_in_smp;

	struct {
		/*
		 * This counts the number of available slots in the ringbuffer,
		 * so we avoid overflowing it: it's decremented (if positive)
		 * when allocating a kiocb and incremented when the resulting
		 * io_event is pulled off the ringbuffer.
		 *
		 * We batch accesses to it with a percpu version.
		 */
		atomic_t	reqs_available;
	} ____cacheline_aligned_in_smp;

	struct page		*internal_pages[AIO_RING_PAGES];
};

#define AIO_EVENTS_PER_PAGE	(PAGE_SIZE / sizeof(struct io_event))
#define AIO_EVENTS_FIRST_PAGE	((PAGE_SIZE - sizeof(struct aio_ring_v1)) / sizeof(struct io_event))
#define AIO_EVENTS_OFFSET	(AIO_EVENTS_PER_PAGE - AIO_EVENTS_FIRST_PAGE)

unsigned ioctx_v1_ring_put(struct kioctx *_ctx, struct kiocb *req,
			   unsigned tail)
{
	struct kioctx_v1 *ctx = container_of(_ctx, struct kioctx_v1, ctx);
	struct io_event	*ev_page, *event;
	unsigned pos = tail + AIO_EVENTS_OFFSET;

	if (++tail >= ctx->nr_events)
		tail = 0;

	ev_page = kmap_atomic(ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE]);
	event = ev_page + pos % AIO_EVENTS_PER_PAGE;

	event->obj	= (u64)(unsigned long)req->ki_obj.user;
	event->data	= req->ki_user_data;
	event->res	= req->ki_res;
	event->res2	= req->ki_res2;

	kunmap_atomic(ev_page);
	flush_dcache_page(ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE]);

	pr_debug("%p[%u]: %p: %p %Lx %lx %lx\n",
		 ctx, tail, req, req->ki_obj.user, req->ki_user_data,
		 req->ki_res, req->ki_res2);

	return tail;
}

void ioctx_v1_ring_unlock(struct kioctx *_ctx, unsigned tail)
{
	struct kioctx_v1 *ctx = container_of(_ctx, struct kioctx_v1, ctx);
	struct aio_ring_v1 *ring;

	/* make event visible before updating tail */
	smp_wmb();

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->tail = tail;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

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

static void put_reqs_available(struct kioctx_v1 *ctx, unsigned nr)
{
	struct kioctx_cpu *kcpu;

	preempt_disable();
	kcpu = this_cpu_ptr(ctx->cpu);

	kcpu->reqs_available += nr;
	while (kcpu->reqs_available >= ctx->req_batch * 2) {
		kcpu->reqs_available -= ctx->req_batch;
		atomic_add(ctx->req_batch, &ctx->reqs_available);
	}

	preempt_enable();
}

static bool get_reqs_available(struct kioctx_v1 *ctx)
{
	struct kioctx_cpu *kcpu;
	bool ret = false;

	preempt_disable();
	kcpu = this_cpu_ptr(ctx->cpu);

	if (!kcpu->reqs_available) {
		int old, avail = atomic_read(&ctx->reqs_available);

		do {
			if (avail < ctx->req_batch)
				goto out;

			old = avail;
			avail = atomic_cmpxchg(&ctx->reqs_available,
					       avail, avail - ctx->req_batch);
		} while (avail != old);

		kcpu->reqs_available += ctx->req_batch;
	}

	ret = true;
	kcpu->reqs_available--;
out:
	preempt_enable();
	return ret;
}

static struct kioctx_v1 *ioctx_lookup(unsigned long ctx_id)
{
	struct mm_struct *mm = current->mm;
	struct kioctx_v1 *ctx, *ret = NULL;

	rcu_read_lock();

	hlist_for_each_entry_rcu(ctx, &mm->ioctx_v1_list, list) {
		if (ctx->user_id == ctx_id) {
			percpu_ref_get(&ctx->users);
			ret = ctx;
			break;
		}
	}

	rcu_read_unlock();
	return ret;
}

static void ioctx_ring_free(struct kioctx_v1 *ctx)
{
	long i;

	for (i = 0; i < ctx->nr_pages; i++)
		put_page(ctx->ring_pages[i]);

	if (ctx->mmap_size)
		vm_munmap(ctx->mmap_base, ctx->mmap_size);

	if (ctx->ring_pages && ctx->ring_pages != ctx->internal_pages)
		kfree(ctx->ring_pages);
}

static int ioctx_ring_init(struct kioctx_v1 *ctx)
{
	struct aio_ring_v1 *ring;
	unsigned nr_events = ctx->max_reqs;
	struct mm_struct *mm = current->mm;
	unsigned long size, populate;
	int nr_pages;

	/* Compensate for the ring buffer's head/tail overlap entry */
	nr_events += 2;	/* 1 is required, 2 for good luck */

	size = sizeof(struct aio_ring_v1);
	size += sizeof(struct io_event) * nr_events;
	nr_pages = (size + PAGE_SIZE-1) >> PAGE_SHIFT;

	if (nr_pages < 0)
		return -EINVAL;

	nr_events = (PAGE_SIZE * nr_pages - sizeof(struct aio_ring_v1)) / sizeof(struct io_event);

	ctx->nr_events = 0;
	ctx->ring_pages = ctx->internal_pages;
	if (nr_pages > AIO_RING_PAGES) {
		ctx->ring_pages = kcalloc(nr_pages, sizeof(struct page *),
					  GFP_KERNEL);
		if (!ctx->ring_pages)
			return -ENOMEM;
	}

	ctx->mmap_size = nr_pages * PAGE_SIZE;
	pr_debug("attempting mmap of %lu bytes\n", ctx->mmap_size);
	down_write(&mm->mmap_sem);
	ctx->mmap_base = do_mmap_pgoff(NULL, 0, ctx->mmap_size,
				       PROT_READ|PROT_WRITE,
				       MAP_ANONYMOUS|MAP_PRIVATE, 0, &populate);
	if (IS_ERR((void *)ctx->mmap_base)) {
		up_write(&mm->mmap_sem);
		ctx->mmap_size = 0;
		goto err;
	}

	pr_debug("mmap address: 0x%08lx\n", ctx->mmap_base);
	ctx->nr_pages = get_user_pages(current, mm, ctx->mmap_base, nr_pages,
				       1, 0, ctx->ring_pages, NULL);
	up_write(&mm->mmap_sem);

	if (unlikely(ctx->nr_pages != nr_pages))
		goto err;

	if (populate)
		mm_populate(ctx->mmap_base, populate);

	ctx->user_id = ctx->mmap_base;
	ctx->nr_events = nr_events; /* trusted copy */

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->nr = nr_events;	/* user copy */
	ring->id = ctx->user_id;
	ring->head = ring->tail = 0;
	ring->magic = AIO_RING_MAGIC;
	ring->compat_features = AIO_RING_COMPAT_FEATURES;
	ring->incompat_features = AIO_RING_INCOMPAT_FEATURES;
	ring->header_length = sizeof(struct aio_ring_v1);
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	return 0;
err:
	ioctx_ring_free(ctx);
	return -EAGAIN;
}

static void ioctx_free_rcu(struct rcu_head *head)
{
	struct kioctx_v1 *ctx = container_of(head, struct kioctx_v1, rcu_head);

	ioctx_free(&ctx->ctx);

	free_percpu(ctx->cpu);
	kfree(ctx);
}

/*
 * When this function runs, the kioctx has been removed from the "hash table"
 * and ctx->users has dropped to 0, so we know no more kiocbs can be submitted -
 * now it's safe to cancel any that need to be.
 */
static void ioctx_v1_free(struct kioctx_v1 *ctx)
{
	struct aio_ring_v1 *ring;
	unsigned cpu, avail;
	DEFINE_WAIT(wait);

	cancel_all_kiocbs(&ctx->ctx);

	for_each_possible_cpu(cpu) {
		struct kioctx_cpu *kcpu = per_cpu_ptr(ctx->cpu, cpu);

		atomic_add(kcpu->reqs_available, &ctx->reqs_available);
		kcpu->reqs_available = 0;
	}

	while (1) {
		prepare_to_wait(&ctx->ctx.wait, &wait, TASK_UNINTERRUPTIBLE);

		ring = kmap_atomic(ctx->ring_pages[0]);
		avail = (ring->head <= ring->tail)
			 ? ring->tail - ring->head
			 : ctx->nr_events - ring->head + ring->tail;

		atomic_add(avail, &ctx->reqs_available);
		ring->head = ring->tail;
		kunmap_atomic(ring);

		if (atomic_read(&ctx->reqs_available) >= ctx->nr_events - 1)
			break;

		schedule();
	}
	finish_wait(&ctx->ctx.wait, &wait);

	WARN_ON(atomic_read(&ctx->reqs_available) > ctx->nr_events - 1);

	ioctx_ring_free(ctx);

	spin_lock(&aio_nr_lock);
	BUG_ON(aio_nr - ctx->max_reqs > aio_nr);
	aio_nr -= ctx->max_reqs;
	spin_unlock(&aio_nr_lock);

	pr_debug("freeing %p\n", ctx);

	/*
	 * Here the call_rcu() is between the wait_event() for reqs_active to
	 * hit 0, and freeing the ioctx.
	 *
	 * aio_complete() decrements reqs_active, but it has to touch the ioctx
	 * after to issue a wakeup so we use rcu.
	 */
	call_rcu(&ctx->rcu_head, ioctx_free_rcu);
}

static void ioctx_put(struct kioctx_v1 *ctx)
{
	if (percpu_ref_put(&ctx->users))
		ioctx_v1_free(ctx);
}

/* ioctx_alloc
 *	Allocates and initializes an ioctx.  Returns an ERR_PTR if it failed.
 */
static struct kioctx_v1 *ioctx_alloc(unsigned nr_events)
{
	struct mm_struct *mm = current->mm;
	struct kioctx_v1 *ctx;
	int ret;

	/*
	 * We keep track of the number of available ringbuffer slots, to prevent
	 * overflow (reqs_available), and we also use percpu counters for this.
	 *
	 * So since up to half the slots might be on other cpu's percpu counters
	 * and unavailable, double nr_events so userspace sees what they
	 * expected: additionally, we move req_batch slots to/from percpu
	 * counters at a time, so make sure that isn't 0:
	 */
	nr_events = max(nr_events, num_possible_cpus() * 4);
	nr_events *= 2;

	/* Prevent overflows */
	if ((nr_events > (0x10000000U / sizeof(struct io_event))) ||
	    (nr_events > (0x10000000U / sizeof(struct kiocb)))) {
		pr_debug("ENOMEM: nr_events too high\n");
		return ERR_PTR(-EINVAL);
	}

	if (!nr_events || (unsigned long)nr_events > aio_max_nr)
		return ERR_PTR(-EAGAIN);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->max_reqs = nr_events;

	percpu_ref_init(&ctx->users);
	rcu_read_lock();
	percpu_ref_get(&ctx->users);
	rcu_read_unlock();

	mutex_init(&ctx->ring_lock);

	ret = ENOMEM;
	ctx->cpu = alloc_percpu(struct kioctx_cpu);
	if (!ctx->cpu)
		goto out_freectx;

	if (ioctx_ring_init(ctx) < 0)
		goto out_freepcpu;

	atomic_set(&ctx->reqs_available, ctx->nr_events - 1);
	ctx->req_batch = (ctx->nr_events - 1) / (num_possible_cpus() * 4);
	BUG_ON(!ctx->req_batch);

	ret = ioctx_init(&ctx->ctx, ctx->nr_events - 1);
	if (ret)
		goto out_freering;

	/* limit the number of system wide aios */
	spin_lock(&aio_nr_lock);
	if (aio_nr + nr_events > aio_max_nr ||
	    aio_nr + nr_events < aio_nr) {
		spin_unlock(&aio_nr_lock);
		goto out_cleanup;
	}
	aio_nr += ctx->max_reqs;
	spin_unlock(&aio_nr_lock);

	/* now link into global list. */
	spin_lock(&mm->ioctx_lock);
	hlist_add_head_rcu(&ctx->list, &mm->ioctx_v1_list);
	spin_unlock(&mm->ioctx_lock);

	pr_debug("allocated ioctx %p[%ld]: mm=%p mask=0x%x\n",
		 ctx, ctx->user_id, mm, ctx->nr_events);
	return ctx;

out_cleanup:
	ret = -EAGAIN;
	ioctx_free(&ctx->ctx);
out_freering:
	ioctx_ring_free(ctx);
out_freepcpu:
	free_percpu(ctx->cpu);
out_freectx:
	kfree(ctx);
	pr_debug("error allocating ioctx %d\n", ret);
	return ERR_PTR(ret);
}

static void ioctx_kill_work(struct work_struct *work)
{
	struct kioctx_v1 *ctx = container_of(work, struct kioctx_v1, rcu_work);

	wake_up_all(&ctx->ctx.wait);
	ioctx_put(ctx);
}

/* ioctx_kill
 *	Cancels all outstanding aio requests on an aio context.  Used
 *	when the processes owning a context have all exited to encourage
 *	the rapid destruction of the kioctx.
 */
static void ioctx_kill(struct kioctx_v1 *ctx)
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
SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
{
	struct kioctx_v1 *ioctx = NULL;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctxp);
	if (unlikely(ret))
		goto out;

	ret = -EINVAL;
	if (unlikely(ctx || nr_events == 0)) {
		pr_debug("EINVAL: io_setup: ctx %lu nr_events %u\n",
			 ctx, nr_events);
		goto out;
	}

	ioctx = ioctx_alloc(nr_events);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		ret = put_user(ioctx->user_id, ctxp);
		if (ret)
			ioctx_kill(ioctx);
		ioctx_put(ioctx);
	}

out:
	return ret;
}

static void ioctx_kill_rcu(struct rcu_head *head)
{
	struct kioctx_v1 *ctx = container_of(head, struct kioctx_v1, rcu_head);

	INIT_WORK(&ctx->rcu_work, ioctx_kill_work);
	schedule_work(&ctx->rcu_work);
}

void ioctx_v1_exit_aio(struct mm_struct *mm)
{
	struct kioctx_v1 *ctx;
	struct hlist_node *n;

	hlist_for_each_entry_safe(ctx, n, &mm->ioctx_v1_list, list) {
		/*
		 * We don't need to bother with munmap() here -
		 * exit_mmap(mm) is coming and it'll unmap everything.
		 * Since aio_free_ring() uses non-zero ->mmap_size
		 * as indicator that it needs to unmap the area,
		 * just set it to 0; aio_free_ring() is the only
		 * place that uses ->mmap_size, so it's safe.
		 */
		ctx->mmap_size = 0;

		if (percpu_ref_kill(&ctx->users)) {
			hlist_del_rcu(&ctx->list);
			call_rcu(&ctx->rcu_head, ioctx_kill_rcu);
		}
	}
}

/* sys_io_destroy:
 *	Destroy the aio_context specified.  May cancel any outstanding
 *	AIOs and block on completion.  Will fail with -ENOSYS if not
 *	implemented.  May fail with -EINVAL if the context pointed to
 *	is invalid.
 */
SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
{
	struct kioctx_v1 *ioctx = ioctx_lookup(ctx);

	if (ioctx) {
		ioctx_kill(ioctx);
		ioctx_put(ioctx);
		return 0;
	}
	pr_debug("EINVAL: io_destroy: invalid context id\n");
	return -EINVAL;
}

static int io_submit_one(struct kioctx_v1 *ctx,
			 struct iocb __user *user_iocb,
			 struct iocb *iocb, bool compat)
{
	struct kiocb *req;
	ssize_t ret = -EAGAIN;;

	/* enforce forwards compatibility on users */
	if (unlikely(iocb->aio_reserved1 || iocb->aio_reserved2)) {
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

	if (!get_reqs_available(ctx))
		return -EAGAIN;

	req = aio_get_req(&ctx->ctx);
	if (unlikely(!req))
		goto out_put;

	req->ki_filp = fget(iocb->aio_fildes);
	if (unlikely(!req->ki_filp)) {
		ret = -EBADF;
		goto out_put_req;
	}

	if (iocb->aio_flags & IOCB_FLAG_RESFD) {
		/*
		 * If the IOCB_FLAG_RESFD flag of aio_flags is set, get an
		 * instance of the file* now. The file descriptor must be
		 * an eventfd() fd, and will be signaled for each completed
		 * event using the eventfd_signal() function.
		 */
		req->ki_eventfd = eventfd_ctx_fdget((int) iocb->aio_resfd);
		if (IS_ERR(req->ki_eventfd)) {
			ret = PTR_ERR(req->ki_eventfd);
			req->ki_eventfd = NULL;
			goto out_put_req;
		}
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
out_put:
	put_reqs_available(ctx, 1);
	return ret;
}

long do_io_submit(aio_context_t ctx_id, long nr,
		  struct iocb __user *__user *iocbpp, bool compat)
{
	struct kioctx_v1 *ctx;
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
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	blk_start_plug(&plug);

	/*
	 * AKPM: should this return a partial result if some of the IOs were
	 * successfully submitted?
	 */
	for (i=0; i<nr; i++) {
		struct iocb __user *user_iocb;
		struct iocb tmp;

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

/* sys_io_submit:
 *	Queue the nr iocbs pointed to by iocbpp for processing.  Returns
 *	the number of iocbs queued.  May return -EINVAL if the aio_context
 *	specified by ctx_id is invalid, if nr is < 0, if the iocb at
 *	*iocbpp[0] is not properly initialized, if the operation specified
 *	is invalid for the file descriptor in the iocb.  May fail with
 *	-EFAULT if any of the data structures point to invalid data.  May
 *	fail with -EBADF if the file descriptor specified in the first
 *	iocb is invalid.  May fail with -EAGAIN if insufficient resources
 *	are available to queue any iocbs.  Will return 0 if nr is 0.  Will
 *	fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
		struct iocb __user * __user *, iocbpp)
{
	return do_io_submit(ctx_id, nr, iocbpp, 0);
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
SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
		struct io_event __user *, result)
{
	struct kioctx_v1 *ctx;
	struct kiocb *kiocb;
	u32 key;
	int ret;

	ret = get_user(key, &iocb->aio_key);
	if (unlikely(ret))
		return -EFAULT;

	ctx = ioctx_lookup(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	kiocb = lookup_kiocb(&ctx->ctx, iocb, key);
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

/* aio_read_events
 *	Pull an event off of the ioctx's event ring.  Returns the number of
 *	events fetched
 */
static long aio_read_events_ring(struct kioctx_v1 *ctx,
				 struct io_event __user *event, long nr)
{
	struct aio_ring_v1 *ring;
	unsigned head, tail, pos;
	long ret = 0;
	int copy_ret;

	mutex_lock(&ctx->ring_lock);

	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	tail = ring->tail;
	kunmap_atomic(ring);

	pr_debug("h%u t%u m%u\n", head, tail, ctx->nr_events);

	if (head == tail)
		goto out;

	while (ret < nr) {
		long avail = (head <= tail
			      ? tail : ctx->nr_events) - head;
		struct io_event *ev;
		struct page *page;

		if (head == tail)
			break;

		avail = min(avail, nr - ret);
		avail = min_t(long, avail, AIO_EVENTS_PER_PAGE -
			      ((head + AIO_EVENTS_OFFSET) % AIO_EVENTS_PER_PAGE));

		pos = head + AIO_EVENTS_OFFSET;
		page = ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE];
		pos %= AIO_EVENTS_PER_PAGE;

		ev = kmap(page);
		copy_ret = copy_to_user(event + ret, ev + pos, sizeof(*ev) * avail);
		kunmap(page);

		if (unlikely(copy_ret)) {
			ret = -EFAULT;
			goto out;
		}

		ret += avail;
		head += avail;
		head %= ctx->nr_events;
	}

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->head = head;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	pr_debug("%li  h%u t%u\n", ret, head, tail);

	put_reqs_available(ctx, ret);
out:
	mutex_unlock(&ctx->ring_lock);

	return ret;
}

static bool aio_read_events(struct kioctx_v1 *ctx, long min_nr, long nr,
			    struct io_event __user *event, long *i)
{
	long ret = aio_read_events_ring(ctx, event + *i, nr - *i);

	if (ret > 0)
		*i += ret;

	if (unlikely(percpu_ref_dead(&ctx->users)))
		ret = -EINVAL;

	if (!*i)
		*i = ret;

	return ret < 0 || *i >= min_nr;
}

static long read_events(struct kioctx_v1 *ctx, long min_nr, long nr,
			struct io_event __user *event,
			struct timespec __user *timeout)
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
			aio_read_events(ctx, min_nr, nr, event, &ret), until);

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
SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct timespec __user *, timeout)
{
	struct kioctx_v1 *ioctx = ioctx_lookup(ctx_id);
	long ret = -EINVAL;

	if (likely(ioctx)) {
		if (likely(min_nr <= nr && min_nr >= 0))
			ret = read_events(ioctx, min_nr, nr, events, timeout);
		ioctx_put(ioctx);
	}

	asmlinkage_protect(5, ret, ctx_id, min_nr, nr, events, timeout);
	return ret;
}
