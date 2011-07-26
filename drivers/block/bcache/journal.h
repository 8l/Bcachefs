
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

/* Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	struct list_head	list;
	atomic_t		*pin;
	struct jset		j;
};

/* For keeping track of the space in the journal that's used by the open
 * journal entries
 */
struct journal_seq {
	uint64_t	seq;
	sector_t	sector;
};

/* We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
	BKEY_PADDED(key);

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

	unsigned		sectors_free;
	uint64_t		seq;
	DECLARE_FIFO(atomic_t, pin);

	struct journal_write	w[2], *cur;
};

#define journal_pin_cmp(c, l, r)				\
	(fifo_idx(&(c)->journal.pin, (l)->journal) >		\
	 fifo_idx(&(c)->journal.pin, (r)->journal))
