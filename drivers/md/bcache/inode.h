#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

#define UUID_INODE_MAX	4096

enum bch_inode_types {
	BCH_INODE		= 0,
	BCH_INODE_DELETED	= 1,
	BCH_INODE_UUID		= 2,
};

struct bch_inode {
	struct bkey	k;

	uint16_t	i_inode_type;

	uint16_t	i_mode;

	uint32_t	i_uid;
	uint32_t	i_gid;

	uint64_t	i_size;

	uint64_t	i_atime;
	uint64_t	i_ctime;
	uint64_t	i_mtime;

	uint32_t	i_atime_ns;
	uint32_t	i_ctime_ns;
	uint32_t	i_mtime_ns;

	uint32_t	i_nlink;

	uint32_t	i_generation;
};

struct bch_inode_deleted {
	struct bkey	k;

	uint16_t	i_inode_type;
};

struct bch_inode_uuid {
	struct bkey	k;

	uint16_t	i_inode_type;

	uint16_t	pad;
	uint32_t	flags;

	uint32_t	first_reg;
	uint32_t	last_reg;

	/* Size of flash only volumes */
	uint64_t	sectors;

	uint8_t		uuid[16];
	uint8_t		label[32];
};

BITMASK(UUID_FLASH_ONLY,	struct bch_inode_uuid, flags, 0, 1);

#define BCH_INODE_INIT(inode)					\
do {								\
	memset(inode, 0, sizeof(*(inode)));			\
	SET_KEY_PTRS(&(inode)->k, (sizeof(*inode) / 8) - 2);	\
								\
	if (__builtin_types_compatible_p(typeof(inode),		\
			struct bch_inode *))			\
		(inode)->i_inode_type = BCH_INODE;		\
	else if (__builtin_types_compatible_p(typeof(inode),	\
			struct bch_inode_deleted *))		\
		(inode)->i_inode_type = BCH_INODE_DELETED;	\
	else if (__builtin_types_compatible_p(typeof(inode),	\
			struct bch_inode_uuid *))		\
		(inode)->i_inode_type = BCH_INODE_UUID;		\
} while (0)

void bch_inode_rm(struct cache_set *c, uint64_t inode_nr);

int bch_uuid_inode_write_new(struct cache_set *c, struct bch_inode_uuid *u);
void bch_uuid_inode_write(struct cache_set *c, struct bch_inode_uuid *u);
int bch_uuid_inode_find(struct cache_set *c, struct bch_inode_uuid *u);

char *uuid_convert(struct cache_set *c, struct jset *j, struct closure *cl);

#endif
