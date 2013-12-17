#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

int bch_inode_create(struct cache_set *, struct bch_inode *, u64, u64, u64 *);
void bch_inode_update(struct cache_set *, struct bch_inode *);
void bch_inode_rm(struct cache_set *c, uint64_t inode_nr);

int bch_inode_find_by_inum(struct cache_set *, u64, struct bch_inode *);
int bch_blockdev_inode_find_by_uuid(struct cache_set *, u8 *,
				    struct bch_inode_blockdev *);

char *bch_uuid_convert(struct cache_set *, struct jset *, struct closure *);

#endif
