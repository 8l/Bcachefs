
#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "dirent.h"
#include "extents.h"
#include "inode.h"
#include "request.h"
#include "xattr.h"

#include "linux/buffer_head.h"
#include "linux/statfs.h"
#include "linux/xattr.h"

struct bch_inode_info {
	struct bch_inode	inode;
	struct inode		vfs_inode;
};

#define to_bch_ei(i)	container_of(inode, struct bch_inode_info, vfs_inode)

static struct kmem_cache *bch_inode_cache;

static void bch_inode_init(struct bch_inode_info *);
static int bch_read_single_page(struct page *, struct address_space *);

static struct inode *bch_vfs_inode_get(struct super_block *sb, u64 inum)
{
	struct cache_set *c = sb->s_fs_info;
	struct bch_inode_info *ei;
	struct inode *inode;
	int ret;

	pr_debug("inum %llu", inum);

	inode = iget_locked(sb, inum);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ei = to_bch_ei(inode);

	/* XXX: init bch_inode */

	ret = bch_inode_find_by_inum(c, inum, &ei->inode);
	if (ret) {
		iget_failed(inode);
		return ERR_PTR(ret);
	}

	BUG_ON(KEY_U64s(&ei->inode.i_key) != sizeof(ei->inode) / sizeof(u64));

	bch_inode_init(ei);
	unlock_new_inode(inode);

	return inode;
}

static struct inode *bch_vfs_inode_create(struct cache_set *c,
					  struct inode *parent,
					  umode_t mode)
{
	struct inode *inode;
	struct bch_inode_info *ei;
	struct bch_inode *bi;
	s64 now = timekeeping_clocktai_ns();
	int ret;

	inode = new_inode(parent->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	ei = to_bch_ei(inode);
	bi = &ei->inode;

	BCH_INODE_INIT(bi);

	inode_init_owner(inode, parent, mode);

	bi->i_uid	= i_uid_read(inode);
	bi->i_gid	= i_gid_read(inode);

	bi->i_mode	= mode;
	bi->i_atime	= now;
	bi->i_mtime	= now;
	bi->i_ctime	= now;
	bi->i_nlink	= S_ISDIR(mode) ? 2 : 1;
	/* XXX: init bch_inode */

	ret = bch_inode_create(c, bi,
			       BLOCKDEV_INODE_MAX,
			       BCACHE_USER_INODE_RANGE,
			       &c->unused_inode_hint);
	if (ret) {
		iput(inode);
		return ERR_PTR(ret);
	}

	bch_inode_init(ei);
	insert_inode_hash(inode);

	return inode;
}

static int __bch_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;
	int ret;

	inode = bch_vfs_inode_create(c, dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	ret = bch_dirent_create(c, dir->i_ino, &dentry->d_name, inode->i_ino);
	if (ret) {
		bch_inode_rm(c, inode->i_ino);
		iput(inode);
		return ret;
	}

	d_instantiate(dentry, inode);
	return 0;
}

static int __bch_write_inode(struct inode *inode)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_inode *bi = &ei->inode;

	pr_debug("i_size now %llu", inode->i_size);

	bi->i_mode	= inode->i_mode;
	bi->i_uid	= i_uid_read(inode);
	bi->i_gid	= i_gid_read(inode);
	bi->i_nlink	= inode->i_nlink;
	bi->i_dev	= inode->i_rdev;
	bi->i_size	= inode->i_size;
	bi->i_atime	= timespec_to_ns(&inode->i_atime);
	bi->i_mtime	= timespec_to_ns(&inode->i_mtime);
	bi->i_ctime	= timespec_to_ns(&inode->i_ctime);

	bch_inode_update(c, bi);

	return 0;
}

/* methods */

static struct dentry *bch_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = NULL;
	u64 inum;

	inum = bch_dirent_lookup(c, dir->i_ino, &dentry->d_name);

	pr_debug("");

	if (inum)
		inode = bch_vfs_inode_get(dir->i_sb, inum);

	return d_splice_alias(inode, dentry);
}

static int bch_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	return __bch_create(dir, dentry, mode|S_IFREG, 0);
}

static int bch_link(struct dentry *old_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = old_dentry->d_inode;
	int ret;

	inode->i_ctime = CURRENT_TIME;
	inode_inc_link_count(inode);
	ihold(inode);

	ret = bch_dirent_create(c, dir->i_ino, &dentry->d_name, inode->i_ino);
	if (ret) {
		inode_dec_link_count(inode);
		iput(inode);
		return ret;
	}

	d_instantiate(dentry, inode);
	return 0;
}

static int bch_unlink(struct inode *dir, struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;
	int ret;

	ret = bch_dirent_delete(c, dir->i_ino, &dentry->d_name);
	if (ret)
		return -ENOENT;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);

	return 0;
}

static int bch_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;
	int ret;

	inode = bch_vfs_inode_create(c, dir, S_IFLNK|S_IRWXUGO);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	ret = page_symlink(inode, symname, strlen(symname) + 1);
	if (ret)
		goto err;

	ret = bch_dirent_create(c, dir->i_ino, &dentry->d_name, inode->i_ino);
	if (ret)
		goto err;

	d_instantiate(dentry, inode);
	return 0;
err:
	bch_inode_rm(c, inode->i_ino);
	iput(inode);
	return ret;
}

static int bch_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int ret;

	ret = __bch_create(dir, dentry, mode|S_IFDIR, 0);
	if (ret)
		return ret;

	inode_inc_link_count(dir);

	return 0;
}

static int bch_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;
	int ret;

	if (bch_empty_dir(c, inode->i_ino))
		return -ENOTEMPTY;

	ret = bch_unlink(dir, dentry);
	if (ret)
		return ret;

	inode->i_size = 0;
	inode_dec_link_count(inode);
	inode_dec_link_count(dir);

	return 0;
}

static int bch_mknod(struct inode *dir, struct dentry *dentry,
		     umode_t mode, dev_t rdev)
{
	if (!new_valid_dev(rdev))
		return -EINVAL;

	return __bch_create(dir, dentry, mode, rdev);
}

static int bch_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct cache_set *c = old_dir->i_sb->s_fs_info;
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	int ret;

	if (S_ISDIR(old_inode->i_mode))
		return -EINVAL;

	if (new_inode) {
		ret = bch_dirent_update(c, new_dir->i_ino,
					&new_dentry->d_name,
					old_inode->i_ino);
		if (ret) {
			__WARN();
			return ret;
		}

		new_inode->i_ctime = CURRENT_TIME;
		inode_dec_link_count(new_inode);
	} else {
		ret = bch_dirent_create(c, new_dir->i_ino,
					&new_dentry->d_name,
					old_inode->i_ino);
		if (ret)
			return ret;
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 */
	old_inode->i_ctime = CURRENT_TIME;
	__bch_write_inode(old_inode);

	bch_dirent_delete(c, old_dir->i_ino, &old_dentry->d_name);

	return 0;
}

static int bch_truncate_page(struct address_space *mapping, loff_t from)
{
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	struct page *page;
	int ret = 0;

	/* Page boundary? Nothing to do */
	if (!offset)
		return 0;

	page = grab_cache_page(mapping, from >> PAGE_CACHE_SHIFT);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
#if 0
	/* unmapped? It's a hole - nothing to do */
	if (!PageMappedToDisk(page))
		goto unlock;
#endif
	/* Ok, it's mapped. Make sure it's up-to-date */
	if (!PageUptodate(page))
		if (bch_read_single_page(page, mapping)) {
			ret = -EIO;
			goto unlock;
		}

	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	set_page_dirty(page);
unlock:
	unlock_page(page);
	page_cache_release(page);
out:
	return ret;
}

static int bch_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret;

	pr_debug("i_size was %llu update has %llu",
		 inode->i_size, iattr->ia_size);

	ret = inode_change_ok(inode, iattr);
	if (ret)
		return ret;

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size) {
		inode_dio_wait(inode);

		ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
		if (ret)
			return ret;

		truncate_setsize(inode, iattr->ia_size);

		ret = bch_inode_truncate(c, inode->i_ino,
					 DIV_ROUND_UP(iattr->ia_size, 512));
		if (ret)
			return ret;

		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	}

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

	return 0;
}

static int bch_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct cache_set *c = dir->i_sb->s_fs_info;
	struct inode *inode;

	/* XXX: i_nlink should be 0? */
	inode = bch_vfs_inode_create(c, dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	d_tmpfile(dentry, inode);
	return 0;
}

struct fiemap_op {
	struct btree_op			op;
	struct fiemap_extent_info	*fieinfo;
	struct bkey			end;
};

static int bch_fiemap_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct fiemap_op *op = container_of(b_op, struct fiemap_op, op);
	unsigned ptr;
	int ret;

	if (bkey_cmp(&START_KEY(k), &op->end) >= 0)
		return MAP_DONE;

	for (ptr = 0; ptr < bch_extent_ptrs(k); ptr++) {
		ret = fiemap_fill_next_extent(op->fieinfo,
					      KEY_START(k),
					      PTR_OFFSET(k, ptr),
					      KEY_SIZE(k), 0);
		if (ret < 0)
			return ret;
	}

	return MAP_CONTINUE;
}

static int bch_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		      u64 start, u64 len)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct fiemap_op op;
	int ret;

	if (start + len < start)
		return -EINVAL;

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, -1);
	op.fieinfo = fieinfo;
	op.end = KEY(inode->i_ino, start + len, 0);

	ret = bch_btree_map_keys(&op.op, c,
				 &KEY(inode->i_ino, start, 0),
				 bch_fiemap_fn, 0);

	return ret < 0 ? ret : 0;
}

const struct file_operations bch_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
//	.release	= bch_release_file,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};

const struct inode_operations bch_file_inode_operations = {
	.setattr	= bch_setattr,
	.fiemap		= bch_fiemap,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= bch_xattr_list,
	.removexattr	= generic_removexattr,
#if 0
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
#endif
};
static const struct inode_operations bch_dir_inode_operations = {
	.lookup		= bch_lookup,
	.create		= bch_create,
	.link		= bch_link,
	.unlink		= bch_unlink,
	.symlink	= bch_symlink,
	.mkdir		= bch_mkdir,
	.rmdir		= bch_rmdir,
	.mknod		= bch_mknod,
	.rename		= bch_rename,
	.setattr	= bch_setattr,
	.tmpfile	= bch_tmpfile,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= bch_xattr_list,
	.removexattr	= generic_removexattr,
#if 0
	.get_acl	= bch_get_acl,
	.set_acl	= bch_set_acl,
#endif
};

static const struct file_operations bch_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= bch_readdir,
	.fsync		= generic_file_fsync,
};

static int bch_bio_add_page(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << (PAGE_CACHE_SHIFT - 9);

	if (!bio->bi_vcnt) {
		bio->bi_iter.bi_sector = offset;
	} else if (bio_end_sector(bio) != offset ||
		   bio->bi_vcnt == bio->bi_max_vecs)
		return -1;

	bio->bi_io_vec[bio->bi_vcnt++] = (struct bio_vec) {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};

	bio->bi_iter.bi_size += PAGE_SIZE;

	return 0;
}

static void bch_readpages_end_io(struct bio *bio, int err)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

static int bch_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio = NULL;
	struct page *page;
	ssize_t ret;

	pr_debug("reading %u pages", nr_pages);

	while (nr_pages) {
		page = list_entry(pages->prev, struct page, lru);
		prefetchw(&page->flags);
		list_del(&page->lru);

		if (!add_to_page_cache_lru(page, mapping,
					   page->index, GFP_NOFS)) {
again:
			if (!bio) {
				bio = bio_alloc(GFP_NOFS,
						min_t(unsigned, nr_pages,
						      BIO_MAX_PAGES));

				bio->bi_end_io = bch_readpages_end_io;
			}

			if (bch_bio_add_page(bio, page)) {
				ret = bch_read(c, bio, inode->i_ino);
				bio_endio(bio, 0);
				bio = NULL;

				if (ret < 0) {
					pr_debug("error %zi", ret);
					return ret;
				}
				goto again;
			}
		}

		nr_pages--;
		page_cache_release(page);
	}

	if (bio) {
		ret = bch_read(c, bio, inode->i_ino);
		bio_endio(bio, 0);

		if (ret < 0) {
			pr_debug("error %zi", ret);
			return ret;
		}
	}

	pr_debug("success");
	return 0;
}

static int bch_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;
	int ret;

	bio = bio_alloc(GFP_NOFS, 1);
	bio->bi_rw = READ_SYNC;
	bio->bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(bio, page);

	ret = bch_read(c, bio, inode->i_ino);
	bio_endio(bio, 0);

	return ret;
}

struct bch_writepage_io {
	struct closure		cl;
	struct data_insert_op	op;
	struct bbio		bio;
};

struct bch_writepage {
	struct cache_set	*c;
	u64			inum;
	struct bch_writepage_io	*io;
};

static void bch_writepage_io_free(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	const int uptodate = test_bit(BIO_UPTODATE, &io->bio.bio.bi_flags);
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment_all(bvec, &io->bio.bio, i) {
		struct page *page = bvec->bv_page;

		if (!uptodate) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}
		end_page_writeback(page);
	}

	kfree(io);
}

static void bch_writepage_do_io(struct bch_writepage_io *io)
{
	pr_debug("writing %u sectors to %llu:%llu",
		 bio_sectors(&io->bio.bio),
		 KEY_INODE(&io->op.insert_key),
		 (u64) io->bio.bio.bi_iter.bi_sector);

	closure_call(&io->op.cl, bch_data_insert, NULL, &io->cl);
	closure_return_with_destructor(&io->cl, bch_writepage_io_free);
}

static int __bch_writepage(struct page *page, struct writeback_control *wbc,
			   void *data)
{
	struct inode *inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	struct bch_writepage *w = data;
	struct bio *bio;

	unsigned long end_index = i_size >> PAGE_CACHE_SHIFT;
	if (page->index >= end_index) {
		/*
		 * The page straddles i_size.  It must be zeroed out on each
		 * and every writepage invocation because it may be mmapped.
		 * "A file is mapped in multiples of the page size.  For a file
		 * that is not a multiple of the page size, the remaining memory
		 * is zeroed when mapped, and writes to that region are not
		 * written out to the file."
		 */
		unsigned offset = i_size & (PAGE_CACHE_SIZE - 1);

		BUG_ON(page->index > end_index || !offset);
		zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	}

again:
	if (!w->io) {
		w->io = kzalloc(sizeof(struct bch_writepage_io) +
				sizeof(struct bio_vec) * BIO_MAX_PAGES,
				GFP_NOFS);
		BUG_ON(!w->io);

		closure_init(&w->io->cl, NULL);

		bio = &w->io->bio.bio;
		bio_init(bio);
		bio->bi_io_vec = bio->bi_inline_vecs;
		bio->bi_max_vecs = BIO_MAX_PAGES;

		bch_data_insert_op_init(&w->io->op, w->c, bio,
					hash_long((unsigned long) current, 16),
					true, false, false,
					&KEY(w->inum, 0, 0), NULL);
	}

	if (bch_bio_add_page(&w->io->bio.bio, page)) {
		bch_writepage_do_io(w->io);
		w->io = NULL;
		goto again;
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	return 0;
}

static int bch_writepages(struct address_space *mapping,
			  struct writeback_control *wbc)
{
	int ret;
	struct bch_writepage w = {
		.c	= mapping->host->i_sb->s_fs_info,
		.inum	= mapping->host->i_ino,
		.io	= NULL,
	};

	pr_debug("writing some stuff");

	ret = write_cache_pages(mapping, wbc, __bch_writepage, &w);

	if (w.io)
		bch_writepage_do_io(w.io);

	return ret;
}

static int bch_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_writepage_io *io;
	struct bio *bio;

	io = kzalloc(sizeof(struct bch_writepage_io) +
			sizeof(struct bio_vec) * BIO_MAX_PAGES,
			GFP_NOFS);
	BUG_ON(!io);

	closure_init(&io->cl, NULL);

	bio = &io->bio.bio;
	bio_init(bio);
	bio->bi_io_vec = bio->bi_inline_vecs;
	bio->bi_max_vecs = 1;

	bch_data_insert_op_init(&io->op, c, bio,
				hash_long((unsigned long) current, 16),
				true, false, false,
				&KEY(inode->i_ino, 0, 0), NULL);

	bch_bio_add_page(bio, page);

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	bch_writepage_do_io(io);

	return 0;
}

static void bch_read_single_page_end_io(struct bio *bio, int err)
{
	complete(bio->bi_private);
}

static int bch_read_single_page(struct page *page, struct address_space *mapping)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(done);

	bio = bio_alloc(GFP_NOFS, 1);
	bio->bi_rw = READ_SYNC;
	bio->bi_private = &done;
	bio->bi_end_io = bch_read_single_page_end_io;
	bch_bio_add_page(bio, page);

	ret = bch_read(c, bio, inode->i_ino);
	bio_endio(bio, 0);
	wait_for_completion(&done);

	if (!bio_flagged(bio, BIO_UPTODATE))
		ret = -EIO;
	bio_put(bio);

	if (ret < 0)
		return ret;

	SetPageUptodate(page);

	return 0;
}

static int bch_write_begin(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned flags,
			   struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int ret = 0;

	BUG_ON(inode_unhashed(mapping->host));

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	if (PageUptodate(page))
		goto out;

	if (len == PAGE_CACHE_SIZE)
		goto out;

	/* XXX: no need to try to read past i_size */
	ret = bch_read_single_page(page, mapping);
out:
	*pagep = page;
	return ret;
}

static int bch_write_end(struct file *filp, struct address_space *mapping,
			 loff_t pos, unsigned len, unsigned copied,
			 struct page *page, void *fsdata)
{
	loff_t last_pos = pos + copied;
	struct inode *inode = page->mapping->host;
	int i_size_changed = 0;

	if (unlikely(copied < len)) {
		/*
		 * zero out the rest of the area
		 */
		unsigned from = pos & (PAGE_CACHE_SIZE - 1);

		zero_user(page, from + copied, len - copied);
		flush_dcache_page(page);
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (last_pos > inode->i_size) {
		inode_add_bytes(inode, last_pos - inode->i_size);
		i_size_write(inode, last_pos);
		i_size_changed = 1;
	}

	__set_page_dirty_nobuffers(page);
	unlock_page(page);
	page_cache_release(page);

	if (i_size_changed)
		mark_inode_dirty(inode);

	return copied;
}

static const struct address_space_operations bch_address_space_operations = {
	.writepage		= bch_writepage,
	.readpage		= bch_readpage,
	.writepages		= bch_writepages,
	.readpages		= bch_readpages,

	.set_page_dirty		= __set_page_dirty_nobuffers,

	.write_begin		= bch_write_begin,
	.write_end		= bch_write_end,

//	.direct_IO		= bch_direct_IO,

	.migratepage		= buffer_migrate_page,
	.is_partially_uptodate	= block_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
};

static void bch_inode_init(struct bch_inode_info *ei)
{
	struct inode *inode = &ei->vfs_inode;
	struct bch_inode *bi = &ei->inode;

	pr_debug("init inode %llu with mode %o",
		 KEY_INODE(&bi->i_key), bi->i_mode);

	inode->i_mode	= bi->i_mode;
	i_uid_write(inode, bi->i_uid);
	i_gid_write(inode, bi->i_gid);

	inode->i_ino	= KEY_INODE(&bi->i_key);
	set_nlink(inode, bi->i_nlink);
	inode->i_rdev	= bi->i_dev;
	inode->i_size	= bi->i_size;
	inode->i_atime	= ns_to_timespec(bi->i_atime);
	inode->i_mtime	= ns_to_timespec(bi->i_mtime);
	inode->i_ctime	= ns_to_timespec(bi->i_ctime);

	inode->i_mapping->a_ops = &bch_address_space_operations;

	switch (inode->i_mode & S_IFMT) {
	default:
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	case S_IFREG:
		inode->i_op = &bch_file_inode_operations;
		inode->i_fop = &bch_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &bch_dir_inode_operations;
		inode->i_fop = &bch_dir_file_operations;
		break;
	case S_IFLNK:
		inode->i_op = &page_symlink_inode_operations;
		break;
	}
}

static struct inode *bch_alloc_inode(struct super_block *sb)
{
	struct bch_inode_info *ei;

	ei = kmem_cache_alloc(bch_inode_cache, GFP_NOFS);
	if (!ei)
		return NULL;

	pr_debug("allocated %p", &ei->vfs_inode);

	inode_init_once(&ei->vfs_inode);

	return &ei->vfs_inode;
}

static void bch_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(bch_inode_cache, to_bch_ei(inode));
}

static void bch_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, bch_i_callback);
}

static int bch_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return __bch_write_inode(inode);
}

static void bch_evict_inode(struct inode *inode)
{
	struct cache_set *c = inode->i_sb->s_fs_info;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);

	/* drop any reservation */

	if (!inode->i_nlink)
		bch_inode_rm(c, inode->i_ino);
}

struct count_inodes_op {
	struct btree_op op;
	u64 inodes;
};

static int bch_count_inodes_fn(struct btree_op *b_op, struct btree *b,
			       struct bkey *k)
{
	struct count_inodes_op *op = container_of(b_op,
					struct count_inodes_op, op);

	op->inodes++;
	return MAP_CONTINUE;
}

static u64 bch_count_inodes(struct cache_set *c)
{
	struct count_inodes_op op;

	bch_btree_op_init(&op.op, BTREE_ID_INODES, -1);
	op.inodes = 0;

	bch_btree_map_keys(&op.op, c, NULL, bch_count_inodes_fn, 0);

	return op.inodes;
}

static int bch_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct cache_set *c = sb->s_fs_info;
	unsigned bucket_to_block_shift = c->bucket_bits - (PAGE_SHIFT - 9);

	buf->f_type	= BCACHE_SB_MAGIC;
	buf->f_bsize	= sb->s_blocksize;
	buf->f_blocks	= ((u64) c->nbuckets)		<< bucket_to_block_shift;
	buf->f_bfree	= ((u64) buckets_available(c))	<< bucket_to_block_shift;
	buf->f_bavail	= buf->f_bfree;
	buf->f_files	= bch_count_inodes(c);
	buf->f_namelen	= NAME_MAX;

	return 0;
}

static const struct super_operations bch_super_operations = {
	.alloc_inode	= bch_alloc_inode,
	.destroy_inode	= bch_destroy_inode,
	.write_inode	= bch_write_inode,
	.evict_inode	= bch_evict_inode,
	.statfs		= bch_statfs,
	.show_options	= generic_show_options,
#if 0
	.put_super	= bch_put_super,
	.sync_fs	= bch_sync_fs,
	.freeze_fs	= bch_freeze,
	.unfreeze_fs	= bch_unfreeze,
	.remount_fs	= bch_remount,
#endif
};

static struct dentry *bch_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	struct cache_set *c;
	struct super_block *sb;
	struct inode *inode;
	uuid_le uuid;
	int ret;

	if (uuid_parse(skip_spaces(dev_name), &uuid))
		return ERR_PTR(-EINVAL);

	c = bch_cache_set_open_by_uuid(&uuid);
	if (!c)
		return ERR_PTR(-ENOENT);

	sb = sget(fs_type, NULL, set_anon_super, flags, NULL);
	if (IS_ERR(sb)) {
		ret = PTR_ERR(sb);
		goto err;
	}

	//sb->s_blocksize	= c->sb.block_size << 9;
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= ilog2(sb->s_blocksize);
	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_op		= &bch_super_operations;
	sb->s_xattr		= bch_xattr_handlers;
	sb->s_magic		= BCACHE_SB_MAGIC;
	sb->s_time_gran		= 1;
	sb->s_fs_info		= c;
	sb->s_bdi		= &bdev_get_queue(c->cache[0]->bdev)->backing_dev_info;

	inode = bch_vfs_inode_get(sb, BCACHE_ROOT_INO);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_put_super;
	}

	sb->s_flags |= MS_ACTIVE;
	return dget(sb->s_root);

err_put_super:
	deactivate_locked_super(sb);
err:
	closure_put(&c->cl);
	return ERR_PTR(ret);
}

static void bch_kill_sb(struct super_block *sb)
{
	struct cache_set *c = sb->s_fs_info;

	generic_shutdown_super(sb);
	closure_put(&c->cl);
}

static struct file_system_type bcache_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bcachefs",
	.mount		= bch_mount,
	.kill_sb	= bch_kill_sb,
};

//MODULE_ALIAS_FS("bcachefs");

void bch_fs_exit(void)
{
	unregister_filesystem(&bcache_fs_type);
	if (bch_inode_cache)
		kmem_cache_destroy(bch_inode_cache);
}

int __init bch_fs_init(void)
{
	int ret;

	bch_inode_cache = KMEM_CACHE(bch_inode_info, 0);
	if (!bch_inode_cache)
		return -ENOMEM;

	ret = register_filesystem(&bcache_fs_type);
	if (ret) {
		kmem_cache_destroy(bch_inode_cache);
		return ret;
	}

	return 0;
}
