#ifndef _BCACHE_KEYLIST_TYPES_H
#define _BCACHE_KEYLIST_TYPES_H

/* struct keylist is defined in include/linux/bcache-kernel.h */

/*
 * scan_keylists are conceptually similar to keybufs, but they don't
 * have an internal RB tree.
 * keybufs should be used when read or write operations need to
 * examine keys in flight, as for writeback.
 * But for moving operations (moving gc, tiering, moving data off
 * devices), read and writes don't need to look at all, so we don't
 * need the RB tree and use scan_keylists instead.
 *
 * Note that unlike keybufs, they don't contain a semaphore to limit
 * bios.  That must be done externally, if necessary.
 */

#define DFLT_SCAN_KEYLIST_MAX_SIZE	(1 << 14)

struct scan_keylist {
	spinlock_t		lock;
	struct bkey		last_scanned;
	unsigned		max_size;
	struct keylist		list;
};

typedef bool (scan_keylist_pred_fn)(struct scan_keylist *, struct bkey *);

#endif /* _BCACHE_KEYLIST_TYPES_H */
