
#ifndef _BCACHE_SIX_H
#define _BCACHE_SIX_H

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>

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
		atomic_long_t	counter;
	};

	struct {
		unsigned long	v;
	};

	struct {
		unsigned long	read_lock:BITS_PER_LONG - 2;
		unsigned long	intent_lock:1;
		unsigned long	write_lock:1;
	};
};

struct six_lock {
	union six_lock_state		state;
	wait_queue_head_t		wait;
};

static inline void six_lock_init(struct six_lock *lock)
{
	atomic_long_set(&lock->state.counter, 0);
	init_waitqueue_head(&lock->wait);
}

#define __SIX_VAL(type)	((union six_lock_state) { .type##_lock = 1 }).v

#define six_trylock_convert(lock, from, to)				\
({									\
	union six_lock_state _old = (lock)->state, _new;		\
	unsigned long v;						\
	bool _ret = false;						\
									\
	while (1) {							\
		BUG_ON(!_old.from##_lock);				\
									\
		_new = _old;						\
		_new.v -= __SIX_VAL(from);				\
									\
		if (!__six_trylock_##to(&_new))				\
			break;						\
									\
		v = cmpxchg((&(lock)->state.v), _old.v, _new.v);	\
		if (v == _old.v) {					\
			_ret = true;					\
			if (!list_empty_careful(&(lock)->wait.task_list))\
				wake_up(&(lock)->wait);			\
			break;						\
		}							\
									\
		_old.v = v;						\
	}								\
									\
	_ret;								\
})

#define six_lock_convert(lock, from, to)				\
	wait_event((lock)->wait, six_trylock_convert((lock), from, to))

#define __SIX_LOCK(type)						\
	static inline bool six_trylock_##type(struct six_lock *lock)	\
	{								\
		union six_lock_state old = lock->state;			\
									\
		while (1) {						\
			union six_lock_state new = old;			\
			unsigned long v;				\
									\
			if (!__six_trylock_##type(&new))		\
				return false;				\
									\
			v = cmpxchg((&lock->state.v), old.v, new.v);	\
			if (v == old.v)					\
				return true;				\
									\
			old.v = v;					\
		}							\
	}								\
									\
	static inline void six_lock_##type(struct six_lock *lock)	\
	{								\
		wait_event(lock->wait, six_trylock_##type(lock));	\
	}								\
									\
	static inline void six_unlock_##type(struct six_lock *lock)	\
	{								\
		BUG_ON(!lock->state.type##_lock);			\
									\
		smp_wmb();						\
		atomic_long_sub(__SIX_VAL(type),			\
				&lock->state.counter);			\
		smp_rmb();						\
									\
		if (!list_empty_careful(&(lock)->wait.task_list))	\
			wake_up(&(lock)->wait);				\
	}

static inline bool __six_trylock_read(union six_lock_state *lock)
{
	if (lock->write_lock)
		return false;

	lock->read_lock++;
	return true;
}

__SIX_LOCK(read)

static inline bool __six_trylock_intent(union six_lock_state *lock)
{
	if (lock->intent_lock)
		return false;

	lock->intent_lock = 1;
	return true;
}

__SIX_LOCK(intent)

static inline bool __six_trylock_write(union six_lock_state *lock)
{
	BUG_ON(lock->write_lock);
	BUG_ON(!lock->intent_lock);
	if (lock->read_lock)
		return false;

	lock->write_lock = 1;
	return true;
}

__SIX_LOCK(write)

#endif /* _BCACHE_SIX_H */
