#ifndef _BCACHE_CLOCK_TYPES_H
#define _BCACHE_CLOCK_TYPES_H

#define NR_IO_TIMERS		8

/*
 * Clocks/timers in units of sectors of IO:
 *
 * Note - they use percpu batching, so they're only approximate.
 */

struct io_timer;
typedef void (*io_timer_fn)(struct io_timer *);

struct io_timer {
	io_timer_fn		fn;
	unsigned long		expire;
};

/* Amount to buffer up on a percpu counter */
#define IO_CLOCK_PCPU_SECTORS	128

struct io_clock {
	atomic_long_t		now;
	u16 __percpu		*pcpu_buf;

	spinlock_t		timer_lock;
	DECLARE_HEAP(struct io_timer *, timers);
};

#endif /* _BCACHE_CLOCK_TYPES_H */

