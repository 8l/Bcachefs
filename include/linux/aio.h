#ifndef __LINUX__AIO_H
#define __LINUX__AIO_H

#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/aio_abi.h>
#include <linux/uio.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/batch_complete.h>

struct kioctx;
struct kiocb;
struct batch_complete;

/*
 * CANCELLATION
 *
 * SEMANTICS:
 *
 * Userspace may indicate (via io_cancel()) that they wish an iocb to be
 * cancelled. io_cancel() does nothing more than indicate that the iocb should
 * be cancelled if possible; it does not indicate whether it succeeded (nor will
 * it block).
 *
 * If cancellation does succeed, userspace should be informed by passing
 * -ECANCELLED to aio_complete(); userspace retrieves the io_event in the usual
 * manner.
 *
 * DRIVERS:
 *
 * A driver that wishes to support cancellation may (but does not have to)
 * implement a ki_cancel callback. If it doesn't implement a callback, it can
 * check if the kiocb has been marked as cancelled (with kiocb_cancelled()).
 * This is what the block layer does - when dequeuing requests it checks to see
 * if it's for a bio that's been marked as cancelled, and if so doesn't send it
 * to the device.
 *
 * Some drivers are going to need to kick something to notice that kiocb has
 * been cancelled - those will want to implement a ki_cancel function. The
 * callback could, say, issue a wakeup so that the thread processing the kiocb
 * can notice the cancellation - or it might do something else entirely.
 * kiocb->private is owned by the driver, so that ki_cancel can find the
 * driver's state.
 *
 * A driver must guarantee that a kiocb completes in bounded time if it's been
 * cancelled - this means that ki_cancel may have to guarantee forward progress.
 *
 * ki_cancel() may not call aio_complete().
 *
 * SYNCHRONIZATION:
 *
 * The aio code ensures that after aio_complete() returns, no ki_cancel function
 * can be called or still be executing. Thus, the driver should free whatever
 * kiocb->private points to after calling aio_complete().
 *
 * Drivers must not set kiocb->ki_cancel directly; they should use
 * kiocb_set_cancel_fn(), which guards against races with kiocb_cancel(). It
 * might be the case that userspace cancelled the iocb before the driver called
 * kiocb_set_cancel_fn() - in that case, kiocb_set_cancel_fn() will immediately
 * call the cancel function you passed it, and leave ki_cancel set to
 * KIOCB_CANCELLED.
 */

/*
 * Special values for kiocb->ki_cancel - these indicate that a kiocb has either
 * been cancelled, or has a ki_cancel function currently running.
 */
#define KIOCB_CANCELLED		((void *) (-1LL))
#define KIOCB_CANCELLING	((void *) (-2LL))

typedef int (kiocb_cancel_fn)(struct kiocb *);

struct kiocb {
	struct kiocb		*ki_next;	/* batch completion */

	/*
	 * If the aio_resfd field of the userspace iocb is not zero,
	 * this is the underlying eventfd context to deliver events to.
	 */
	struct eventfd_ctx	*ki_eventfd;
	struct file		*ki_filp;
	struct kioctx		*ki_ctx;	/* NULL for sync ops */
	void			*private;

	/* Only zero up to here in aio_get_req() */
	kiocb_cancel_fn		*ki_cancel;
	unsigned		ki_id;

	union {
		void __user		*user;
		struct task_struct	*tsk;
	} ki_obj;

	__u64			ki_user_data;	/* user's data for completion */
	long			ki_res;
	long			ki_res2;

	loff_t			ki_pos;
	size_t			ki_nbytes;	/* copy of iocb->aio_nbytes */
};

static inline bool kiocb_cancelled(struct kiocb *kiocb)
{
	return kiocb->ki_cancel == KIOCB_CANCELLED;
}

static inline bool is_sync_kiocb(struct kiocb *kiocb)
{
	return kiocb->ki_ctx == NULL;
}

static inline void init_sync_kiocb(struct kiocb *kiocb, struct file *filp)
{
	*kiocb = (struct kiocb) {
			.ki_ctx = NULL,
			.ki_filp = filp,
			.ki_obj.tsk = current,
		};
}

/* prototypes */
#ifdef CONFIG_AIO
extern ssize_t wait_on_sync_kiocb(struct kiocb *iocb);
extern void batch_complete_aio(struct batch_complete *batch);
extern void aio_complete_batch(struct kiocb *iocb, long res, long res2,
			       struct batch_complete *batch);
struct mm_struct;
extern void exit_aio(struct mm_struct *mm);
extern long do_io_submit(aio_context_t ctx_id, long nr,
			 struct iocb __user *__user *iocbpp, bool compat);
void kiocb_set_cancel_fn(struct kiocb *req, kiocb_cancel_fn *cancel);
#else
static inline ssize_t wait_on_sync_kiocb(struct kiocb *iocb) { return 0; }
static inline void batch_complete_aio(struct batch_complete *batch) { }
static inline void aio_complete_batch(struct kiocb *iocb, long res, long res2,
				      struct batch_complete *batch)
{
	return;
}
struct mm_struct;
static inline void exit_aio(struct mm_struct *mm) { }
static inline long do_io_submit(aio_context_t ctx_id, long nr,
				struct iocb __user * __user *iocbpp,
				bool compat) { return 0; }
static inline void kiocb_set_cancel_fn(struct kiocb *req,
				       kiocb_cancel_fn *cancel) { }
#endif /* CONFIG_AIO */

static inline void aio_complete(struct kiocb *iocb, long res, long res2)
{
	aio_complete_batch(iocb, res, res2, NULL);
}

/* for sysctl: */
extern unsigned long aio_nr;
extern unsigned long aio_max_nr;

#endif /* __LINUX__AIO_H */
