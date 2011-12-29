#ifndef _BCACHE_JOURNAL_H
#define _BCACHE_JOURNAL_H

#define JSET_VERSION	0

/*
 * On disk format for a journal entry:
 * seq is monotonically increasing; every journal entry has its own unique
 * sequence number.
 *
 * last_seq is the oldest journal entry that still has keys the btree hasn't
 * flushed to disk yet.
 *
 * version is for on disk format changes.
 */
struct jset {
	uint64_t		csum;
	uint64_t		magic;
	uint64_t		seq;
	uint32_t		version;
	uint32_t		keys;

	uint64_t		last_seq;

	BKEY_PADDED(uuid_bucket);
	BKEY_PADDED(btree_root);
	uint16_t		btree_level;
	uint16_t		pad[3];

	uint64_t		prio_bucket[MAX_CACHES_PER_SET];

	union {
		struct bkey	start[0];
		uint64_t	d[0];
	};
};

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	struct list_head	list;
	atomic_t		*pin;
	struct jset		j;
};

/*
 * We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
	struct jset		*data;
#define JSET_BITS		3

	struct cache_set	*c;
	closure_list_t		wait;
	bool			need_write;
};

struct journal {
	struct work_struct	work;
	spinlock_t		lock;
	/* used when waiting because the journal was full */
	closure_list_t		wait;
	atomic_t		io;

	unsigned		blocks_free;
	uint64_t		seq;
	DECLARE_FIFO(atomic_t, pin);

	BKEY_PADDED(key);

	struct journal_write	w[2], *cur;
};

struct journal_device {
	unsigned		cur;
	unsigned		last;
	uint64_t		seq[SB_JOURNAL_BUCKETS];

	struct bio		bio;
	struct bio_vec		bv[8];
};

#define journal_pin_cmp(c, l, r)				\
	(fifo_idx(&(c)->journal.pin, (l)->journal) >		\
	 fifo_idx(&(c)->journal.pin, (r)->journal))

#define JOURNAL_PIN	20000

#define journal_full(j)						\
	(!(j)->blocks_free || fifo_free(&(j)->pin) <= 1)

struct closure;
struct cache_set;
struct btree_op;

void bcache_journal(struct closure *);
void bcache_journal_next(struct journal *);
void bcache_journal_mark(struct cache_set *, struct list_head *);
void bcache_journal_meta(struct cache_set *, struct closure *);
int bcache_journal_read(struct cache_set *, struct list_head *,
			struct btree_op *);
int bcache_journal_replay(struct cache_set *, struct list_head *,
			  struct btree_op *);

void bcache_journal_free(struct cache_set *);
int bcache_journal_alloc(struct cache_set *);

#endif /* _BCACHE_JOURNAL_H */
