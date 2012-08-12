#ifndef _WRITE_BUFFER_H
#define _WRITE_BUFFER_H

struct cache;
struct write_buffer_entry;

struct write_buffer {
	wait_queue_head_t		wait;

	unsigned			head;
	unsigned			tail;
	unsigned			mask;

	unsigned			buffer_bits;

	struct bio_set			*bs;

	void				*buffer;
	struct write_buffer_entry	*entries;
	struct hlist_head		*hash;
};

#define __wait_event_locked(wq, condition, exclusive, irq) \
do {									\
	DEFINE_WAIT(__wait);						\
	if (exclusive)							\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;			\
	do {								\
		if (likely(list_empty(&__wait.task_list)))		\
			__add_wait_queue_tail(&(wq), &__wait);		\
		set_current_state(TASK_UNINTERRUPTIBLE);		\
		if (irq)						\
			spin_unlock_irq(&(wq).lock);			\
		else							\
			spin_unlock(&(wq).lock);			\
		schedule();						\
		if (irq)						\
			spin_lock_irq(&(wq).lock);			\
		else							\
			spin_lock(&(wq).lock);				\
	} while (!(condition));						\
	__remove_wait_queue(&(wq), &__wait);				\
	__set_current_state(TASK_RUNNING);				\
} while (0)

#define wait_event_locked_irq(wq, condition)				\
do {									\
	if (condition)							\
		break;							\
	 __wait_event_locked(wq, condition, 0, 1);			\
} while (0)

void bch_write_buffer_exit(struct cache *ca);
int bch_write_buffer_init(struct cache *ca);

#endif /* _WRITE_BUFFER_H */
