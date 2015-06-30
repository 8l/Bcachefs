#ifndef _BCACHE_FIFO_H
#define _BCACHE_FIFO_H

#define DECLARE_FIFO(type, name)					\
	struct {							\
		size_t front, back, size, mask;				\
		type *data;						\
	} name

#define init_fifo(fifo, _size, gfp)					\
({									\
	bool _ret = true;						\
									\
	(fifo)->size	= (_size);					\
	(fifo)->front	= (fifo)->back = 0;				\
	(fifo)->data	= NULL;						\
									\
	if ((fifo)->size) {						\
		size_t _allocated_size, _bytes;				\
									\
		_allocated_size = roundup_pow_of_two((fifo)->size + 1);	\
		_bytes = _allocated_size * sizeof(*(fifo)->data);	\
									\
		(fifo)->mask = _allocated_size - 1;			\
									\
		if (_bytes < KMALLOC_MAX_SIZE)				\
			(fifo)->data = kmalloc(_bytes, (gfp));		\
		if ((!(fifo)->data) && ((gfp) & GFP_KERNEL))		\
			(fifo)->data = vmalloc(_bytes);			\
		if ((!(fifo)->data))					\
			_ret = false;					\
	}								\
	_ret;								\
})

#define free_fifo(fifo)							\
do {									\
	if (is_vmalloc_addr((fifo)->data))				\
		vfree((fifo)->data);					\
	else								\
		kfree((fifo)->data);					\
	(fifo)->data = NULL;						\
} while (0)

#define fifo_swap(l, r)							\
do {									\
	swap((l)->front, (r)->front);					\
	swap((l)->back, (r)->back);					\
	swap((l)->size, (r)->size);					\
	swap((l)->mask, (r)->mask);					\
	swap((l)->data, (r)->data);					\
} while (0)

#define fifo_move(dest, src)						\
do {									\
	typeof(*((dest)->data)) _t;					\
	while (!fifo_full(dest) &&					\
	       fifo_pop(src, _t))					\
		fifo_push(dest, _t);					\
} while (0)

#define fifo_used(fifo)		(((fifo)->back - (fifo)->front) & (fifo)->mask)
#define fifo_free(fifo)		((fifo)->size - fifo_used(fifo))

#define fifo_empty(fifo)	(!fifo_used(fifo))
#define fifo_full(fifo)		(!fifo_free(fifo))

#define fifo_front(fifo)	((fifo)->data[(fifo)->front])
#define fifo_back(fifo)							\
	((fifo)->data[((fifo)->back - 1) & (fifo)->mask])

#define fifo_entry_idx(fifo, p)	(((p) - &fifo_front(fifo)) & (fifo)->mask)

#define fifo_push_back(fifo, i)						\
({									\
	bool _r = !fifo_full((fifo));					\
	if (_r) {							\
		(fifo)->data[(fifo)->back++] = (i);			\
		(fifo)->back &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_pop_front(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r) {							\
		(i) = (fifo)->data[(fifo)->front++];			\
		(fifo)->front &= (fifo)->mask;				\
	}								\
	_r;								\
})

#define fifo_push_front(fifo, i)					\
({									\
	bool _r = !fifo_full((fifo));					\
	if (_r) {							\
		--(fifo)->front;					\
		(fifo)->front &= (fifo)->mask;				\
		(fifo)->data[(fifo)->front] = (i);			\
	}								\
	_r;								\
})

#define fifo_pop_back(fifo, i)						\
({									\
	bool _r = !fifo_empty((fifo));					\
	if (_r) {							\
		--(fifo)->back;						\
		(fifo)->back &= (fifo)->mask;				\
		(i) = (fifo)->data[(fifo)->back]			\
	}								\
	_r;								\
})

#define fifo_push(fifo, i)	fifo_push_back(fifo, (i))
#define fifo_pop(fifo, i)	fifo_pop_front(fifo, (i))

#define fifo_peek_front(fifo)	((fifo)->data[(fifo)->front])
#define fifo_peek(fifo)		fifo_peek_front(fifo)

#define fifo_for_each_entry(_entry, _fifo, _iter)			\
	for (_iter = (_fifo)->front;					\
	     ((_iter != (_fifo)->back) &&				\
	      (_entry = (_fifo)->data[(_iter)], true));			\
	     _iter = ((_iter) + 1) & (_fifo)->mask)

#define fifo_for_each_entry_ptr(_ptr, _fifo, _iter)			\
	for (_iter = (_fifo)->front;					\
	     ((_iter != (_fifo)->back) &&				\
	      (_ptr = &(_fifo)->data[(_iter)], true));			\
	     _iter = ((_iter) + 1) & (_fifo)->mask)

#endif /* _BCACHE_FIFO_H */

