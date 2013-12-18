
#include "bcache.h"
#include "btree.h"
#include "dirent.h"
#include "inode.h"
#include "request.h"

#include "linux/buffer_head.h"
#include "linux/statfs.h"

struct bch_read_op {
	struct btree_op		op;
	struct cache_set	*c;
	struct bio		*bio;
	u64			inode;
};

static int bch_read_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct bch_read_op *op = container_of(b_op,
			struct bch_read_op, op);
	struct bio *n, *bio = op->bio;
	BKEY_PADDED(k) user;
	unsigned ptr = 0;

	if (bkey_cmp(k, &KEY(op->inode, bio->bi_iter.bi_sector, 0)) <= 0)
		return MAP_CONTINUE;

	if (KEY_INODE(k) != op->inode ||
	    KEY_START(k) >= bio_end_sector(bio)) {
		/* Completely missed */
		zero_fill_bio(bio);
		return MAP_DONE;
	}

	if (KEY_START(k) > bio->bi_iter.bi_sector) {
		unsigned bytes = (KEY_START(k) - bio->bi_iter.bi_sector) << 9;

		swap(bytes, bio->bi_iter.bi_size);
		zero_fill_bio(bio);
		swap(bytes, bio->bi_iter.bi_size);

		bio_advance(bio, bytes);
	}

	if (!KEY_SIZE(k))
		return MAP_CONTINUE;

	n = bio_next_split(bio, min_t(uint64_t, INT_MAX,
				      KEY_OFFSET(k) - bio->bi_iter.bi_sector),
			   GFP_NOIO, b->c->bio_split);

	bch_bkey_copy_single_ptr(&user.k, k, ptr);

	/* Trim the key to match what we're actually reading */
	bch_cut_front(&KEY(op->inode, n->bi_iter.bi_sector, 0), &user.k);
	bch_cut_back(&KEY(op->inode, bio_end_sector(n), 0), &user.k);

	n->bi_iter.bi_sector	= PTR_OFFSET(&user.k, 0);
	n->bi_bdev		= PTR_CACHE(b->c, &user.k, 0)->bdev;

	if (n != bio)
		bio_chain(n, bio);
	else
		atomic_inc(&bio->bi_remaining);

	BUG_ON(!n->bi_end_io);

	submit_bio(0, n);

	return n == bio ? MAP_DONE : MAP_CONTINUE;
}

static ssize_t bch_read(struct cache_set *c, struct bio *bio, u64 inode)
{
	struct bch_read_op op;
	int ret;

	bch_btree_op_init(&op.op, -1);
	op.c = c;
	op.bio = bio;
	op.inode = inode;

	ret = bch_btree_map_keys(&op.op, c, BTREE_ID_EXTENTS,
				 &KEY(inode,
				      bio->bi_iter.bi_sector, 0),
				 bch_read_fn, 0);
	return ret < 0 ? ret : 0;
}

struct bch_inode_info {
	struct bch_inode	inode;
	struct inode		vfs_inode;
};

#define to_bch_ei(i)	container_of(inode, struct bch_inode_info, vfs_inode)

static struct kmem_cache *bch_inode_cache;

static void bch_inode_init(struct bch_inode_info *);

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

	memset(bi, 0, sizeof(*bi));
	bi->i_key = KEY(0, 0, 0);
	SET_KEY_U64s(&bi->i_key, sizeof(*bi) / sizeof(u64));

	bi->i_mode	= mode;
	bi->i_atime	= now;
	bi->i_mtime	= now;
	bi->i_ctime	= now;
	bi->i_nlink	= S_ISDIR(mode) ? 2 : 1;
	/* XXX: init bch_inode */

	ret = bch_inode_create(c, bi, BLOCKDEV_INODE_MAX, UINT_MAX,
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

static int bch_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int ret;

	pr_debug("i_size was %llu update has %llu",
		 inode->i_size, iattr->ia_size);

	ret = inode_change_ok(inode, iattr);
	if (ret)
		return ret;

	if (iattr->ia_valid & ATTR_SIZE && iattr->ia_size != inode->i_size) {
		truncate_setsize(inode, iattr->ia_size);
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	}

	setattr_copy(inode, iattr);

	__bch_write_inode(inode);
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

static int bch_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return 0;
}

const struct file_operations bch_file_operations = {
	.llseek		= generic_file_llseek,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
//	.release	= bch_release_file,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};

const struct inode_operations bch_file_inode_operations = {
	.setattr	= bch_setattr,
//	.get_acl	= bch_get_acl,
//	.fiemap		= bch_fiemap,
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
//	.get_acl	= bch_get_acl,
	.tmpfile	= bch_tmpfile,
};

static const struct file_operations bch_dir_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= bch_readdir,
	.fsync		= bch_fsync,
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

	pr_debug("reading %u pages", nr_pages);

	while (nr_pages) {
		struct bio *bio;
		struct page *page;
		ssize_t ret;

		bio = bio_alloc(GFP_KERNEL,
				min_t(unsigned, nr_pages, BIO_MAX_PAGES));

		while (nr_pages) {
			page = list_entry(pages->prev, struct page, lru);
			prefetchw(&page->flags);

			if (bch_bio_add_page(bio, page))
				break;

			list_del(&page->lru);
			nr_pages--;

			if (add_to_page_cache_lru(page, mapping,
						  page->index, GFP_KERNEL)) {
				bio->bi_vcnt--;
				bio->bi_iter.bi_size -= PAGE_SIZE;
			}
			page_cache_release(page);
		}

		bio->bi_end_io = bch_readpages_end_io;

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

	bio = bio_alloc(GFP_KERNEL, 1);
	bio->bi_rw = READ_SYNC;
	bio->bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(bio, page);

	ret = bch_read(c, bio, inode->i_ino);
	bio_endio(bio, 0);

	if (ret < 0)
		return ret;

	return 0;
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
	struct bch_writepage *w = data;
	struct bio *bio;

again:
	if (!w->io) {
		w->io = kzalloc(sizeof(struct bch_writepage_io) +
				sizeof(struct bio_vec) * BIO_MAX_PAGES,
				GFP_NOFS);
		BUG_ON(!w->io);

		closure_init(&w->io->cl, NULL);
		w->io->op.c = w->c;
		w->io->op.insert_key = KEY(w->inum, 0, 0);

		bio = &w->io->bio.bio;
		bio_init(bio);
		bio->bi_io_vec = bio->bi_inline_vecs;
		bio->bi_max_vecs = BIO_MAX_PAGES;
		w->io->op.bio = bio;
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
	struct bch_writepage_io *io;
	struct bio *bio;

	io = kzalloc(sizeof(struct bch_writepage_io) +
			sizeof(struct bio_vec) * BIO_MAX_PAGES,
			GFP_NOFS);
	BUG_ON(!io);

	closure_init(&io->cl, NULL);
	io->op.c = inode->i_sb->s_fs_info;
	io->op.insert_key = KEY(inode->i_ino, 0, 0);

	bio = &io->bio.bio;
	bio_init(bio);
	bio->bi_io_vec = bio->bi_inline_vecs;
	bio->bi_max_vecs = 1;
	io->op.bio = bio;

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

	bio = bio_alloc(GFP_KERNEL, 1);
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
	}

	__set_page_dirty_nobuffers(page);
	unlock_page(page);
	page_cache_release(page);

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

//	.bmap			= bch_bmap,
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

	ei = kmem_cache_alloc(bch_inode_cache, GFP_KERNEL);
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

	bch_btree_op_init(&op.op, -1);
	op.inodes = 0;

	bch_btree_map_keys(&op.op, c, BTREE_ID_INODES, NULL,
			   bch_count_inodes_fn, 0);

	return op.inodes;
}

static int bch_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct cache_set *c = sb->s_fs_info;
	struct cache *ca;
	unsigned i;

	buf->f_type	= BCACHE_SB_MAGIC;
	buf->f_bsize	= sb->s_blocksize;

	buf->f_blocks	= 0;
	buf->f_bfree	= 0;

	for_each_cache(ca, c, i)
		buf->f_blocks += (ca->sb.nbuckets *
				  ca->sb.bucket_size) >> (PAGE_SHIFT - 9);

	buf->f_bfree	= c->gc_stats.sectors_available >> (PAGE_SHIFT - 9);
	buf->f_bavail	= c->gc_stats.sectors_available >> (PAGE_SHIFT - 9);
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

static struct file_system_type bcache_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bcachefs",
	.mount		= bch_mount,
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
