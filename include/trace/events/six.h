#undef TRACE_SYSTEM
#define TRACE_SYSTEM six

#if !defined(_TRACE_SIX_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SIX_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(six,
	TP_PROTO(void *lock, const char *type),
	TP_ARGS(lock, type),

	TP_STRUCT__entry(
		__field(void *,			lock		)
		__field(const char *,		type		)
	),

	TP_fast_assign(
		__entry->lock		= lock;
		__entry->type		= type;
	),

	TP_printk("%p %s", __entry->lock, __entry->type)
);

DECLARE_EVENT_CLASS(six_convert,
	TP_PROTO(void *lock, const char *from, const char *to),
	TP_ARGS(lock, from, to),

	TP_STRUCT__entry(
		__field(void *,			lock		)
		__field(const char *,		from		)
		__field(const char *,		to		)
	),

	TP_fast_assign(
		__entry->lock		= lock;
		__entry->from		= from;
		__entry->to		= to;
	),

	TP_printk("%p from %s to %s", __entry->lock, __entry->from, __entry->to)
);

DEFINE_EVENT(six, six_trylock,
	TP_PROTO(void *lock, const char *type),
	TP_ARGS(lock, type)
);

DEFINE_EVENT(six, six_lock,
	TP_PROTO(void *lock, const char *type),
	TP_ARGS(lock, type)
);

DEFINE_EVENT(six, six_unlock,
	TP_PROTO(void *lock, const char *type),
	TP_ARGS(lock, type)
);

DEFINE_EVENT(six_convert, six_trylock_convert,
	TP_PROTO(void *lock, const char *from, const char* to),
	TP_ARGS(lock, from, to)
);

DEFINE_EVENT(six_convert, six_lock_convert,
	TP_PROTO(void *lock, const char *from, const char* to),
	TP_ARGS(lock, from, to)
);

#endif /* _TRACE_SIX_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
