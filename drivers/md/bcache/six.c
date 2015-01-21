
#include "six.h"

bool __six_trylock(struct six_lock *lock,
		   unsigned long lock_val,
		   unsigned long lock_fail)
{
	union six_lock_state old = lock->state;
	unsigned long v;

	while (1) {
		EBUG_ON(lock_val == __SIX_LOCK_VAL_write &&
			((old.v & __SIX_LOCK_HELD_write) ||
			 !(old.v & __SIX_LOCK_HELD_intent)));

		if (old.v & lock_fail)
			return false;

		v = cmpxchg(&lock->state.v, old.v, old.v + lock_val);
		if (v == old.v)
			return true;

		old.v = v;
	}
}

bool __six_relock(struct six_lock *lock,
		  unsigned long lock_val,
		  unsigned long lock_fail,
		  unsigned seq)
{
	union six_lock_state old = lock->state;
	unsigned long v;

	while (1) {
		if (old.seq != seq ||
		    old.v & lock_fail)
			return false;

		v = cmpxchg(&lock->state.v, old.v, old.v + lock_val);
		if (v == old.v)
			return true;

		old.v = v;
	}
}

void __six_lock(struct six_lock *lock,
		unsigned long lock_val,
		unsigned long lock_fail)
{
	if (!__six_trylock(lock, lock_val, lock_fail)) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&lock->wait, &wait, TASK_UNINTERRUPTIBLE);
		atomic64_add(__SIX_VAL_WAIT, &lock->state.counter);

		while (!__six_trylock(lock, lock_val, lock_fail)) {
			schedule();
			prepare_to_wait(&lock->wait, &wait,
					TASK_UNINTERRUPTIBLE);
		}

		atomic64_sub(__SIX_VAL_WAIT, &lock->state.counter);
		finish_wait(&lock->wait, &wait);
	}
}

void __six_unlock(struct six_lock *lock,
		  unsigned long unlock_val)
{
	union six_lock_state state;

	smp_wmb();
	state.v = atomic64_add_return(unlock_val, &lock->state.counter);
	if (state.waiters)
		wake_up(&lock->wait);
}

bool __six_trylock_convert(struct six_lock *lock,
			   unsigned long unlock_val,
			   unsigned long lock_val,
			   unsigned long lock_fail)
{
	union six_lock_state old = lock->state, new;
	unsigned long v;

	while (1) {
		new = old;
		new.v += unlock_val;

		if (new.v & lock_fail)
			return false;

		v = cmpxchg(&lock->state.v, old.v, new.v + lock_val);
		if (v == old.v) {
			if (!list_empty_careful(&(lock)->wait.task_list))
				wake_up(&(lock)->wait);
			return true;
		}

		old.v = v;
	}
}
