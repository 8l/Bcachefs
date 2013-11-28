/*
 * fs/direct-io.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * O_DIRECT
 *
 * 04Jul2002	Andrew Morton
 *		Initial version
 * 11Sep2002	janetinc@us.ibm.com
 *		added readv/writev support.
 * 29Oct2002	Andrew Morton
 *		rewrote bio_add_page() support.
 * 30Oct2002	pbadari@us.ibm.com
 *		added support for non-aligned IO.
 * 06Nov2002	pbadari@us.ibm.com
 *		added asynchronous IO support.
 * 21Jul2003	nathans@sgi.com
 *		added IO completion notifier.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/bio.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/rwsem.h>
#include <linux/uio.h>
#include <linux/atomic.h>
#include <linux/prefetch.h>
#include <linux/aio.h>

/* dio_state communicated between submission path and end_io */
struct dio {
	int		flags;		/* doesn't change */
	int		rw;
	struct inode	*inode;
	loff_t		i_size;		/* i_size when submitted */
	unsigned	i_blkbits;

	/* BIO completion state */
	int		page_error;	/* errno from get_user_pages() */
	int		io_error;	/* IO error in completion path */
	bool		async;
	bool defer_completion;		/* defer AIO completion to workqueue? */

	dio_iodone_t	*end_io;	/* IO completion function */
	void		*private;	/* copy from map_bh.b_private */
	struct task_struct *waiter;	/* waiting task (NULL if none) */

	/* AIO related stuff */
	struct kiocb	*iocb;		/* kiocb */
	ssize_t		result;		/* IO result */
	struct work_struct complete_work;/* deferred AIO completion */

	struct bio	bio;
};

#define DIO_WAKEUP	(1U << 31)

struct dio_mapping {
	/* Low bit for READ|WRITE */
	enum {
		MAP_MAPPED	= 0,
		MAP_NEW		= 2,
		MAP_UNMAPPED	= 4,
	} state;

	struct block_device	*bdev;
	loff_t			offset;
	size_t			size;
};

static struct bio_set *dio_pool __read_mostly;

/**
 * dio_complete() - called when all DIO BIO I/O has been completed
 * @offset: the byte offset in the file of the completed operation
 *
 * This drops i_dio_count, lets interested parties know that a DIO operation
 * has completed, and calculates the resulting return code for the operation.
 *
 * It lets the filesystem know if it registered an interest earlier via
 * get_block.  Pass the private field of the map buffer_head so that
 * filesystems can use it to hold additional state between get_block calls and
 * dio_complete.
 */
static ssize_t dio_complete(struct dio *dio, loff_t offset,
			    ssize_t ret, bool is_async)
{
	if (ret == 0)
		ret = dio->page_error;
	if (ret == 0)
		ret = dio->io_error;
	if (ret == 0)
		ret = dio->result;

	if (dio->end_io && dio->result)
		dio->end_io(dio->iocb, offset, dio->result, dio->private);

	inode_dio_done(dio->inode);
	if (is_async) {
		if (dio->rw & WRITE) {
			int err;

			err = generic_write_sync(dio->iocb->ki_filp, offset,
						 dio->result);
			if (err < 0 && ret > 0)
				ret = err;
		}

		aio_complete(dio->iocb, ret, 0);
	}

	bio_put(&dio->bio);
	return ret;
}

static void dio_aio_complete_work(struct work_struct *work)
{
	struct dio *dio = container_of(work, struct dio, complete_work);

	dio_complete(dio, dio->iocb->ki_pos, 0, true);
}

/**
 * dio_end_io - handle the end io action for the given bio
 * @bio: The direct io bio thats being completed
 * @error: Error if there was one
 *
 * This is meant to be called by any filesystem that uses their own dio_submit_t
 * so that the DIO specific endio actions are dealt with after the filesystem
 * has done it's completion work.
 */
void dio_end_io(struct bio *bio, int error)
{
	struct dio *dio = bio->bi_private;

	if (error)
		dio->io_error = -EIO;

	if (dio->rw == READ) {
		bio_check_pages_dirty(bio);	/* transfers ownership */
	} else {
		struct bio_vec *bv;
		int i;

		bio_for_each_segment_all(bv, bio, i)
			page_cache_release(bv->bv_page);
	}

	if (!dio->async) {
		wake_up_process(dio->waiter);
	} else if (dio->defer_completion) {
		INIT_WORK(&dio->complete_work, dio_aio_complete_work);
		queue_work(dio->inode->i_sb->s_dio_done_wq,
			   &dio->complete_work);
	} else {
		dio_complete(dio, dio->iocb->ki_pos, 0, true);
	}
}
EXPORT_SYMBOL_GPL(dio_end_io);

static void dio_wait_completion(struct dio *dio)
{
	if (atomic_add_return(DIO_WAKEUP - 1, &dio->refcount) == DIO_WAKEUP)
		return;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (atomic_read(&dio->refcount) == DIO_WAKEUP)
			break;

		io_schedule();
	}
	__set_current_state(TASK_RUNNING);
}

/*
 * Clean any dirty buffers in the blockdev mapping which alias newly-created
 * file blocks.  Only called for S_ISREG files - blockdevs do not set buffer_new
 */
static void clean_blockdev_aliases(struct dio *dio, struct buffer_head *map_bh)
{
	unsigned i;
	unsigned nblocks;

	nblocks = map_bh->b_size >> dio->i_blkbits;

	for (i = 0; i < nblocks; i++)
		unmap_underlying_metadata(map_bh->b_bdev,
					  map_bh->b_blocknr + i);
}

/*
 * Create workqueue for deferred direct IO completions. We allocate the
 * workqueue when it's first needed. This avoids creating workqueue for
 * filesystems that don't need it and also allows us to create the workqueue
 * late enough so the we can include s_id in the name of the workqueue.
 */
static int sb_init_dio_done_wq(struct super_block *sb)
{
	struct workqueue_struct *old;
	struct workqueue_struct *wq = alloc_workqueue("dio/%s",
						      WQ_MEM_RECLAIM, 0,
						      sb->s_id);
	if (!wq)
		return -ENOMEM;
	/*
	 * This has to be atomic as more DIOs can race to create the workqueue
	 */
	old = cmpxchg(&sb->s_dio_done_wq, NULL, wq);
	/* Someone created workqueue before us? Free ours... */
	if (old)
		destroy_workqueue(wq);
	return 0;
}

static int dio_set_defer_completion(struct dio *dio)
{
	struct super_block *sb = dio->inode->i_sb;

	if (dio->defer_completion)
		return 0;
	dio->defer_completion = true;
	if (!sb->s_dio_done_wq)
		return sb_init_dio_done_wq(sb);
	return 0;
}

static int get_blocks(struct dio *dio, loff_t offset, size_t size,
		      struct dio_mapping *map, get_block_t *get_block)
{
	struct buffer_head map_bh = { 0, };
	int ret, create;
	unsigned i_mask = (1 << dio->i_blkbits) - 1;
	unsigned fs_offset = offset & i_mask;
	sector_t fs_blocknr = offset >> dio->i_blkbits;

	/*
	 * For writes inside i_size on a DIO_SKIP_HOLES filesystem we
	 * forbid block creations: only overwrites are permitted.
	 * We will return early to the caller once we see an
	 * unmapped buffer head returned, and the caller will fall
	 * back to buffered I/O.
	 *
	 * Otherwise the decision is left to the get_blocks method,
	 * which may decide to handle it or also return an unmapped
	 * buffer head.
	 */
	create = dio->rw & WRITE;
	if (dio->flags & DIO_SKIP_HOLES) {
		if (fs_blocknr < dio->i_size >> dio->i_blkbits)
			create = 0;
	}

	/* fs expects units of fs_blocks */
	map_bh.b_size = size + fs_offset;
	map_bh.b_size = round_up(map_bh.b_size, 1 << dio->i_blkbits);

	ret = get_block(dio->inode, fs_blocknr, &map_bh, create);
	if (ret)
		return ret;

	/* Store for completion */
	dio->private = map_bh.b_private;

	if (ret == 0 && buffer_defer_completion(&map_bh))
		ret = dio_set_defer_completion(dio);

	if (buffer_new(&map_bh))
		clean_blockdev_aliases(dio, &map_bh);

	if (!buffer_mapped(&map_bh))
		map->state = MAP_UNMAPPED;
	else if (buffer_new(&map_bh))
		map->state = MAP_NEW;
	else
		map->state = MAP_MAPPED;

#if 0
	/* Previous DIO code only handled holes one block at a time */
	if (map->state == MAP_UNMAPPED)
		map_bh.b_size = 1 << dio->i_blkbits;

#endif
	BUG_ON(map_bh.b_size <= fs_offset);

	map->bdev = map_bh.b_bdev;
	map->offset = (map_bh.b_blocknr << dio->i_blkbits) +
		fs_offset;
	map->size = min(map_bh.b_size - fs_offset, size);

	return ret;
}

static void __dio_bio_submit(struct dio *dio, struct bio *bio,
			     loff_t offset, dio_submit_t *submit_io)
{
	/*
	 * Read accounting is performed in submit_bio()
	 */
	if (dio->rw & WRITE)
		task_io_account_write(bio->bi_iter.bi_size);

	if (submit_io)
		submit_io(dio->rw, bio, dio->inode,
			  offset >> dio->i_blkbits);
	else
		submit_bio(dio->rw, bio);
}

/*
 * For reads we speculatively dirty the pages before starting IO. During IO
 * completion, any of these pages which happen to have been written back will be
 * redirtied by bio_check_pages_dirty().
 *
 * bios hold a dio reference between submit_bio and ->end_io.
 */
static int dio_bio_submit(struct dio *dio, struct bio *bio,
			  struct dio_mapping *map,
			  loff_t offset, dio_submit_t *submit_io)
{
	struct bio *split;

	split = bio_next_split(bio, map->size >> 9,
			       GFP_KERNEL, fs_bio_set);

	if (split != bio)
		bio_chain(split, bio);
	else
		atomic_inc(&bio->bi_remaining);

	split->bi_bdev = map->bdev;
	split->bi_iter.bi_sector = map->offset >> 9;

	dio->result += map->size;

	__dio_bio_submit(dio, bio, offset, submit_io);

	return split == bio;
}

static int dio_write_hole(struct dio *dio, struct bio *bio,
			  struct dio_mapping *map,
			  struct file *file, loff_t offset)
{
	while (map->size) {
		struct bio_vec bv = bio_iovec(bio);
		unsigned bytes = min_t(size_t, map->size, bv.bv_len);
		ssize_t ret;

		ret = file->f_op->write(file,
				       page_address(bv.bv_page) + bv.bv_offset,
				       bytes, &offset);
		if (ret != bytes) {
			bio_endio(bio, -EIO);
			return 1;
		}

		bio_advance(bio, bytes);
		offset += bytes;
		map->size -= bytes;
	}

	if (!bio->bi_iter.bi_size) {
		bio_endio(bio, 0);
		return 1;
	}

	return 0;
}

static void dio_write_zeroes(struct dio *dio, struct bio *parent,
			     struct block_device *bdev,
			     sector_t sector, size_t size,
			     loff_t offset, dio_submit_t *submit_io)
{
	unsigned pages = DIV_ROUND_UP(size, PAGE_SIZE);
	struct bio *bio = bio_alloc(GFP_KERNEL, pages);

	while (pages--) {
		bio->bi_io_vec[pages].bv_page = ZERO_PAGE(0);
		bio->bi_io_vec[pages].bv_len = PAGE_SIZE;
		bio->bi_io_vec[pages].bv_offset = 0;
	}

	bio->bi_bdev = bdev;
	bio->bi_iter.bi_sector = sector;
	bio->bi_iter.bi_size = size;

	bio_chain(bio, parent);
	__dio_bio_submit(dio, bio, offset, submit_io);
}

static void dio_zero_partial_block_front(struct dio *dio, struct bio *bio,
					 struct dio_mapping *map, loff_t offset,
					 dio_submit_t *submit_io)
{
	unsigned blksize = 1 << dio->i_blkbits;
	unsigned blkmask = blksize - 1;
	unsigned front = offset & blkmask;

	if (front)
		dio_write_zeroes(dio, bio, map->bdev,
				 (map->offset - front) >> 9,
				 front, offset, submit_io);
}

static void dio_zero_partial_block_back(struct dio *dio, struct bio *bio,
					struct dio_mapping *map, loff_t offset,
					dio_submit_t *submit_io)
{
	unsigned blksize = 1 << dio->i_blkbits;
	unsigned blkmask = blksize - 1;
	unsigned back = (offset + map->size) & blkmask;

	if (back)
		dio_write_zeroes(dio, bio, map->bdev,
				 (map->offset + map->size) >> 9,
				 blksize - back, offset, submit_io);
}

static int dio_read_zeroes(struct dio *dio, struct bio *bio,
			   struct dio_mapping *map)
{
	swap(bio->bi_iter.bi_size, map->size);
	zero_fill_bio(bio);
	swap(bio->bi_iter.bi_size, map->size);

	dio->result += map->size;
	bio_advance(bio, map->size);

	return !bio->bi_iter.bi_size;
}

static int dio_is_aligned(struct dio *dio, struct dio_mapping *map)
{
	/*
	 * XXX: have to make sure we're at least sector aligned, but maybe leave
	 * the rest to generic_make_request()?
	 */

	unsigned blocksize_mask =
		roundup_pow_of_two(bdev_logical_block_size(map->bdev)) - 1;

	return !(map->offset & blocksize_mask) &&
		!(map->size & blocksize_mask);
}

static void __dio_send_bio(struct dio *dio, struct bio *bio,
			   struct file *file, loff_t offset,
			   get_block_t *get_block, dio_submit_t *submit_io)
{
	struct dio_mapping map;
	int ret = 0, rw = dio->rw & WRITE;
	bool done;

	if (rw == READ)
		bio_set_pages_dirty(bio);

	while (1) {
		if (rw == READ && offset >= dio->i_size)
			break;

		ret = get_blocks(dio, offset, bio->bi_iter.bi_size,
				 &map, get_block);
		if (ret) {
			bio_endio(bio, ret);
			return;
		}

		switch (map.state|rw) {
		case MAP_MAPPED|READ:
		case MAP_MAPPED|WRITE:
			if (!dio_is_aligned(dio, &map)) {
				bio_endio(bio, -EINVAL);
				return;
			}

			if (dio_bio_submit(dio, bio, &map, offset, submit_io))
				goto out;
			break;
		case MAP_NEW|READ:
		case MAP_UNMAPPED|READ:
			if (dio_read_zeroes(dio, bio, &map))
				goto out;

			break;
		case MAP_NEW|WRITE:
			if (!dio_is_aligned(dio, &map)) {
				bio_endio(bio, -EINVAL);
				return;
			}

			dio_zero_partial_block_front(dio, bio, &map,
						     offset, submit_io);

			done = dio_bio_submit(dio, bio, &map, offset, submit_io);

			dio_zero_partial_block_back(dio, bio, &map,
						    offset, submit_io);

			if (done)
				goto out;

			break;
		case MAP_UNMAPPED|WRITE:
			if (dio_write_hole(dio, bio, &map, file, offset))
				return;

			break;
		}

		offset += map.size;
	}
out:
	if (rw == READ && offset + dio->result > dio->i_size) {
		BUG_ON(offset > dio->i_size ||
		       (offset == dio->i_size && dio->result));
		dio->result = dio->i_size - offset;
	}

	bio_endio(bio, 0);
}

static void dio_send_bio(struct dio *dio, struct bio *bio,
			struct file *file, loff_t offset,
			get_block_t *get_block, dio_submit_t *submit_io)
{
	if (dio->flags & DIO_LOCKING) {
		struct address_space *mapping = file->f_mapping;
		int ret;

		mutex_lock(&dio->inode->i_mutex);

		ret = filemap_write_and_wait_range(mapping, offset,
					offset + bio->bi_iter.bi_size - 1);
		if (ret) {
			mutex_unlock(&dio->inode->i_mutex);
			bio_endio(bio, ret);
		}
	}

	__dio_send_bio(dio, bio, file, offset, get_block, submit_io);

	if (dio->flags & DIO_LOCKING)
		mutex_unlock(&dio->inode->i_mutex);
}

/*
 * This is a library function for use by filesystem drivers.
 *
 * The locking rules are governed by the flags parameter:
 *  - if the flags value contains DIO_LOCKING we use a fancy locking
 *    scheme for dumb filesystems.
 *    For writes this function is called under i_mutex and returns with
 *    i_mutex held, for reads, i_mutex is not held on entry, but it is
 *    taken and dropped again before returning.
 *  - if the flags value does NOT contain DIO_LOCKING we don't use any
 *    internal locking but rather rely on the filesystem to synchronize
 *    direct I/O reads/writes versus each other and truncate.
 *
 * To help with locking against truncate we incremented the i_dio_count
 * counter before starting direct I/O, and decrement it once we are done.
 * Truncate can wait for it to reach zero to provide exclusion.  It is
 * expected that filesystem provide exclusion between new direct I/O
 * and truncates.  For DIO_LOCKING filesystems this is done by i_mutex,
 * but other filesystems need to take care of this on their own.
 */
static inline ssize_t
do_blockdev_direct_IO(int rw, struct kiocb *iocb, struct inode *inode,
	struct block_device *bdev, struct iov_iter *iter, loff_t offset, 
	get_block_t get_block, dio_iodone_t end_io,
	dio_submit_t submit_io,	int flags)
{
	unsigned nr_pages = 0, i_blkbits;
	size_t size = iocb->ki_nbytes;
	ssize_t ret = 0;
	struct blk_plug plug;

	BUG_ON((flags & DIO_LOCKING) && (rw & WRITE));

	if (rw & WRITE)
		rw = WRITE_ODIRECT;

	i_blkbits = ACCESS_ONCE(inode->i_blkbits);

	/* watch out for a 0 len io from a tricksy fs */
	if (rw == READ && !size)
		return 0;

	nr_pages = iov_count_pages(iter, 511);
	if (nr_pages < 0)
		return nr_pages;

	atomic_inc(&inode->i_dio_count);

	blk_start_plug(&plug);

	while (iov_iter_count(iter)) {
		struct bio *bio;
		struct dio *dio;

		BUG_ON(!nr_pages);

		bio = bio_alloc_bioset(GFP_KERNEL,
			min_t(unsigned, BIO_MAX_PAGES, nr_pages), dio_pool);

		dio = container_of(bio, struct dio, bio);
		dio->flags	= flags;
		dio->rw		= rw;
		dio->inode	= inode;
		dio->i_size	= i_size_read(inode);
		dio->i_blkbits	= i_blkbits;
		dio->end_io	= end_io;
		dio->private	= NULL;
		dio->page_error	= 0;
		dio->io_error	= 0;
		dio->waiter	= current;
		dio->iocb	= iocb;
		dio->result	= 0;

		bio->bi_private	= dio;
		bio->bi_end_io	= dio_end_io;

		ret = bio_get_user_pages(bio, iter, dio->rw == READ);
		if (ret) {
			bio_put(bio);
			break;
		}

		nr_pages -= bio->bi_vcnt;

		dio_send_bio(dio, bio, iocb->ki_filp, offset + dio->result,
			     get_block, submit_io);
	}

	blk_finish_plug(&plug);

	/*
	 * For file extending writes updating i_size before data
	 * writeouts complete can expose uninitialized blocks. So
	 * even for AIO, we need to wait for i/o to complete before
	 * returning in this case.
	 */
	if (!is_sync_kiocb(iocb) &&
	    ret == 0 && dio->result &&
	    ((rw == READ) ||
	     (offset + size <= dio->i_size &&
	      dio->result == size))) {
		if (atomic_dec_and_test(&dio->refcount))
			ret = dio_complete(dio, offset, ret, false);
		else
			ret = -EIOCBQUEUED;
	} else {
		dio_wait_completion(dio);
		ret = dio_complete(dio, offset, ret, false);
		BUG_ON(ret == -EIOCBQUEUED);
	}

	return ret;
}

ssize_t
__blockdev_direct_IO(int rw, struct kiocb *iocb, struct inode *inode,
	struct block_device *bdev, struct iov_iter *iter, loff_t offset,
	get_block_t get_block, dio_iodone_t end_io,
	dio_submit_t submit_io,	int flags)
{
	/*
	 * The block device state is needed in the end to finally
	 * submit everything.  Since it's likely to be cache cold
	 * prefetch it here as first thing to hide some of the
	 * latency.
	 *
	 * Attempt to prefetch the pieces we likely need later.
	 */
	prefetch(&bdev->bd_disk->part_tbl);
	prefetch(bdev->bd_queue);
	prefetch((char *)bdev->bd_queue + SMP_CACHE_BYTES);

	return do_blockdev_direct_IO(rw, iocb, inode, bdev, iter, offset,
				     get_block, end_io, submit_io, flags);
}
EXPORT_SYMBOL(__blockdev_direct_IO);

static __init int dio_init(void)
{
	/*
	 * First argument to bioset_create() is completely arbitrary - it just
	 * has to be nonzero to always make forward progress.
	 */

	dio_pool = bioset_create(4, offsetof(struct dio, bio));
	if (!dio_pool)
		panic("dio: can't allocate bios\n");

	return 0;
}
subsys_initcall(dio_init);
