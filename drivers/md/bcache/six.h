
#ifndef _BCACHE_SIX_H
#define _BCACHE_SIX_H

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "util.h"

#ifdef CONFIG_SIX_LOCKS_DEBUG
#include <trace/events/six.h>
#else
#define trace_six_trylock(lock, type)
#define trace_six_relock(lock, type)
#define trace_six_lock(lock, type)
#define trace_six_unlock(lock, type)
#define trace_six_trylock_convert(lock, from, to)
#define trace_six_lock_convert(lock, from, to)
#endif

/*
 * LOCK STATES:
 *
 * read, intent, write (i.e. shared/intent/exclusive, hence the name)
 *
 * read and write work as with normal read/write locks - a lock can have
 * multiple readers, but write excludes reads and other write locks.
 *
 * Intent does not block read, but it does block other intent locks. The idea is
 * by taking an intent lock, you can then later upgrade to a write lock without
 * dropping your read lock and without deadlocking - because no other thread has
 * the intent lock and thus no other thread could be trying to take the write
 * lock.
 */

union six_lock_state {
	struct {
		atomic64_t	counter;
	};

	struct {
		u64		v;
	};

	struct {
		/*
		 * seq works much like in seqlocks: it's incremented every time
		 * we lock and unlock for write.
		 *
		 * If it's odd write lock is held, even unlocked.
		 *
		 * Thus readers can unlock, and then lock again later iff it
		 * hasn't been modified in the meantime.
		 */
		u32		seq;
		u16		read_lock;
		unsigned	intent_lock:1;
		unsigned	waiters:15;
	};
};

struct six_lock {
	union six_lock_state	state;
	wait_queue_head_t	wait;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
};

static inline void __six_lock_init(struct six_lock *lock, const char *name,
				   struct lock_class_key *key)
{
	atomic64_set(&lock->state.counter, 0);
	init_waitqueue_head(&lock->wait);
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	debug_check_no_locks_freed((void *) lock, sizeof(*lock));
	lockdep_init_map(&lock->dep_map, name, key, 0);
#endif
}

#define six_lock_init(lock)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__six_lock_init((lock), #lock, &__key);				\
} while (0)

bool __six_trylock_convert(struct six_lock *, unsigned long,
			   unsigned long, unsigned long);
void __six_lock_convert(struct six_lock *, unsigned long,
			unsigned long, unsigned long);
bool __six_trylock(struct six_lock *, unsigned long, unsigned long);
bool __six_relock(struct six_lock *, unsigned long, unsigned long, unsigned);
void __six_lock(struct six_lock *, unsigned long, unsigned long);
void __six_unlock(struct six_lock *, unsigned long);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

#define six_acquire(l)	lock_acquire(l, 0, 0, 0, 0, NULL, _THIS_IP_)
#define six_release(l)	lock_release(l, 0, _THIS_IP_)

#else

#define six_acquire(l)
#define six_release(l)

#endif

#define __SIX_VAL(field, _v)	(((union six_lock_state) { .field = _v }).v)

#define __SIX_VAL_WAIT			__SIX_VAL(waiters, 1)

#define __SIX_LOCK_HELD_read		__SIX_VAL(read_lock, ~0)
#define __SIX_LOCK_HELD_intent		__SIX_VAL(intent_lock, 1)
#define __SIX_LOCK_HELD_write		__SIX_VAL(seq, 1)

#define __SIX_LOCK_FAIL_read		__SIX_LOCK_HELD_write
#define __SIX_LOCK_VAL_read		__SIX_VAL(read_lock, 1)
#define __SIX_UNLOCK_VAL_read		(-__SIX_VAL(read_lock, 1))

#define __SIX_LOCK_FAIL_intent		__SIX_LOCK_HELD_intent
#define __SIX_LOCK_VAL_intent		__SIX_VAL(intent_lock, 1)
#define __SIX_UNLOCK_VAL_intent		(-__SIX_VAL(intent_lock, 1))

#define __SIX_LOCK_FAIL_write		__SIX_LOCK_HELD_read
#define __SIX_LOCK_VAL_write		__SIX_VAL(seq, 1)
#define __SIX_UNLOCK_VAL_write		__SIX_VAL(seq, 1)

#define __SIX_LOCK(type)						\
	static inline bool six_trylock_##type(struct six_lock *lock)	\
	{								\
		trace_six_trylock(lock, #type);				\
		return __six_trylock(lock,				\
				     __SIX_LOCK_VAL_##type,		\
				     __SIX_LOCK_FAIL_##type);		\
	}								\
									\
	static inline bool six_relock_##type(struct six_lock *lock, u32 seq)\
	{								\
		trace_six_relock(lock, #type);				\
		return __six_relock(lock,				\
				    __SIX_LOCK_VAL_##type,		\
				    __SIX_LOCK_FAIL_##type,		\
				    seq);				\
	}								\
									\
	static inline void six_lock_##type(struct six_lock *lock)	\
	{								\
		__six_lock(lock,					\
			   __SIX_LOCK_VAL_##type,			\
			   __SIX_LOCK_FAIL_##type);			\
		trace_six_lock(lock, #type);				\
	}								\
									\
	static inline void six_unlock_##type(struct six_lock *lock)	\
	{								\
		trace_six_unlock(lock, #type);				\
		__six_unlock(lock, __SIX_UNLOCK_VAL_##type);		\
	}

__SIX_LOCK(read)
__SIX_LOCK(intent)
__SIX_LOCK(write)

#define six_trylock_convert(lock, from, to)				\
({									\
	trace_six_trylock_convert(lock, #from, #to);			\
	__six_trylock_convert(lock,					\
			      __SIX_UNLOCK_VAL_##from,			\
			      __SIX_LOCK_VAL_##to,			\
			      __SIX_LOCK_FAIL_##to);			\
})

#define six_lock_convert(lock, from, to)				\
do {									\
	__six_lock_convert(lock,					\
			   __SIX_UNLOCK_VAL_##from,			\
			   __SIX_LOCK_VAL_##to,				\
			   __SIX_LOCK_FAIL_##to);			\
	trace_six_lock_convert(lock, #from, #to);			\
} while (0)

#endif /* _BCACHE_SIX_H */
