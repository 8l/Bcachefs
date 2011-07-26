#undef TRACE_SYSTEM
#define TRACE_SYSTEM bcache

#if !defined(_TRACE_BCACHE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BCACHE_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(bcache_search_waiting,

	TP_PROTO(struct closure *c, unsigned long ip),

	TP_ARGS(c, ip),

	TP_STRUCT__entry(
		__field( unsigned long,		ptr		)
		__field( int,			remaining	)
		__field( unsigned int,		flags		)
		__field( unsigned long,		ip		)
	),

	TP_fast_assign(
		__entry->ptr		= (unsigned long) c;
		__entry->remaining	= atomic_read(&c->remaining);
		__entry->flags		= c->flags;
		__entry->ip		= ip;
	),

	TP_printk("%16lx,%d,%2x,%lx", __entry->ptr,
		  __entry->remaining, __entry->flags, __entry->ip)
);

DEFINE_EVENT(bcache_search_waiting, bcache_start_closure_wait,

	TP_PROTO(struct closure *c, unsigned long ip),

	TP_ARGS(c, ip)

);

DEFINE_EVENT(bcache_search_waiting, bcache_end_closure_wait,

	TP_PROTO(struct closure *c, unsigned long ip),

	TP_ARGS(c, ip)

);

#endif /* _TRACE_BCACHE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

