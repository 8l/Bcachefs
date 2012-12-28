
#include "bcache.h"
#include "btree.h"
#include "inode.h"

void bch_inode_rm(struct cache_set *c, uint64_t inode_nr)
{
	struct btree_op op;
	struct bch_inode_deleted inode;

	BCH_INODE_INIT(&inode);
	SET_KEY_INODE(&inode.k, inode_nr);

	bch_btree_op_init_stack(&op);
	bch_keylist_add(&op.keys, &inode.k);

	bch_btree_insert(&op, c);
	closure_sync(&op.cl);
}

struct uuid_op {
	struct btree_op		op;
	struct bch_inode_uuid	*search;
};

static bool uuid_inode_write_new_fn(struct btree_op *op, struct btree *b)
{
	struct bkey *k;
	struct btree_iter iter;

	bch_btree_iter_init(b, &iter, &KEY(op->c->unused_inode_hint, 0, 0));


	return false;
}

int bch_uuid_inode_write_new(struct cache_set *c, struct bch_inode_uuid *u)
{
	struct btree_op op;
	struct bkey start = KEY(c->unused_inode_hint, 0, 0);

	bch_btree_op_init_stack(&op);
	op.c = c;

	bch_btree_map_node(&u.op, BTREE_ID_INODES,
			   &KEY(c->unused_inode_hint, 0, 0),
			   uuid_inode_write_new_fn);

	return 0;
}

void bch_uuid_inode_write(struct cache_set *c, struct bch_inode_uuid *u)
{
	struct btree_op op;
	bch_btree_op_init_stack(&op);

	bch_keylist_add(&op.keys, &u->k);

	bch_btree_insert(&op, c);
	closure_sync(&op.cl);
}

static bool uuid_inode_find_fn(struct btree_op *op, struct btree *b, struct bkey *k)
{
	struct uuid_op *u = container_of(op, struct uuid_op, op);
	struct bch_inode_uuid *inode;

	if (KEY_INODE(k) >= UUID_INODE_MAX)
		return true;

	inode = (void *) k;
	if (!memcmp(u->search->uuid, inode->uuid, 16)) {
		memcpy(u->search, inode, sizeof(*inode));
		return true;
	}

	return false;
}

int bch_uuid_inode_find(struct cache_set *c, struct bch_inode_uuid *search)
{
	struct uuid_op u;

	bch_btree_op_init_stack(&u.op);
	u.op.c = c;
	u.search = search;

	SET_KEY_PTRS(&search->k, 0);

	bch_btree_map(&u.op, BTREE_ID_INODES, &ZERO_KEY,
		      uuid_inode_find_fn);

	if (!KEY_PTRS(&search->k))
		return -1;

	return 0;
}

/* Old UUID code */

struct uuid_entry_v0 {
	uint8_t		uuid[16];
	uint8_t		label[32];
	uint32_t	first_reg;
	uint32_t	last_reg;
	uint32_t	invalidated;
	uint32_t	pad;
};

struct uuid_entry {
	union {
		struct {
			uint8_t		uuid[16];
			uint8_t		label[32];
			uint32_t	first_reg;
			uint32_t	last_reg;
			uint32_t	invalidated;

			uint32_t	flags;
			/* Size of flash only volumes */
			uint64_t	sectors;
		};

		uint8_t	pad[128];
	};
};

BITMASK(UUID0_FLASH_ONLY,	struct uuid_entry, flags, 0, 1);

static void uuid_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

static int uuid_io(struct cache_set *c, struct bkey *k,
		   struct uuid_entry *uuids)
{
	int err = -EIO;
	struct closure cl;
	closure_init_stack(&cl);

	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bio *bio = bch_bbio_alloc(c);

		bio->bi_rw	= REQ_SYNC|REQ_META|READ_SYNC;
		bio->bi_size	= KEY_SIZE(k) << 9;

		bio->bi_end_io	= uuid_endio;
		bio->bi_private = &cl;
		bio_map(bio, uuids);

		bch_submit_bbio(bio, c, k, i);
		closure_sync(&cl);

		err = !test_bit(BIO_UPTODATE, &bio->bi_flags);
		bch_bbio_free(bio, c);

		if (!err)
			return 0;
	}

	return -EIO;

	return 0;
}

char *uuid_convert(struct cache_set *c, struct jset *j, struct closure *cl)
{
	int level;
	unsigned nr_uuids = bucket_bytes(c) / sizeof(struct uuid_entry);
	unsigned i, order;
	struct uuid_entry *uuids;
	struct bkey *k;
	struct btree_op op;

	bch_btree_op_init_stack(&op);

	k = bch_journal_find_btree_root(c, j, BTREE_ID_UUIDS, &level);
	if (!k)
		return "bad uuid pointer";

	order = ilog2(bucket_pages(c));

	uuids = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!uuids)
		return "-ENOMEM";

	if (uuid_io(c, k, uuids))
		return "error reading old style uuids";

	if (j->version < BCACHE_JSET_VERSION_UUIDv1) {
		struct uuid_entry_v0	*u0 = (void *) uuids;
		struct uuid_entry	*u1 = (void *) uuids;

		closure_sync(cl);

		/*
		 * Since the new uuid entry is bigger than the old, we have to
		 * convert starting at the highest memory address and work down
		 * in order to do it in place
		 */

		for (int i = nr_uuids - 1;
		     i >= 0;
		     --i) {
			memcpy(u1[i].uuid,	u0[i].uuid, 16);
			memcpy(u1[i].label,	u0[i].label, 32);

			u1[i].first_reg		= u0[i].first_reg;
			u1[i].last_reg		= u0[i].last_reg;
			u1[i].invalidated	= u0[i].invalidated;

			u1[i].flags	= 0;
			u1[i].sectors	= 0;
		}
	}

	for (i = 0; i < nr_uuids; i++) {
		struct uuid_entry *u = uuids + i;
		struct bch_inode_uuid ui;

		if (is_zero(u->uuid, 16))
			continue;

		pr_debug("Slot %zi: %pU: %s: 1st: %u last: %u inv: %u",
			 u - uuids, u->uuid, u->label,
			 u->first_reg, u->last_reg, u->invalidated);

		BCH_INODE_INIT(&ui);
		ui.sectors	= u->sectors;
		ui.flags	= u->flags;
		ui.first_reg	= u->first_reg;
		ui.last_reg	= u->last_reg;

		memcpy(ui.uuid, u->uuid, 16);
		memcpy(ui.label, u->label, 32);
		SET_UUID_FLASH_ONLY(&ui, UUID0_FLASH_ONLY(u));

		SET_KEY_INODE(&ui.k, i);

		bch_keylist_add(&op.keys, &ui.k);
	}

	free_pages((unsigned long) uuids, order);

	return NULL;
}
