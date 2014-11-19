#ifndef _BCACHE_KEYBUF_TYPES_H
#define _BCACHE_KEYBUF_TYPES_H

#include <linux/mempool.h>

/* IMPORTANT: The ref can be -1, 0, or a positive number.
   It is -1 when the I/O that uses the key has not yet been started.
   It is 0 when it has finished.
   It is positive when in progress.
*/

struct keybuf_key {
	struct rb_node		node;
	BKEY_PADDED(key);
	atomic_t		ref;
};

struct keybuf {
	struct bkey		last_scanned;
	spinlock_t		lock;

	/*
	 * Beginning and end of range in rb tree - so that we can skip taking
	 * lock and checking the rb tree when we need to check for overlapping
	 * keys.
	 */
	struct bkey		start;
	struct bkey		end;

	struct rb_root		keys;

	unsigned		max_in_flight;
	struct semaphore	in_flight;

#define DFLT_KEYBUF_KEYBUF_NR		500
#define DFLT_KEYBUF_IN_FLIGHT		250
	unsigned		reserve;
	unsigned		size;
	mempool_t		*pool;
};

#endif /* _BCACHE_KEYBUF_TYPES_H */
