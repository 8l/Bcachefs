/*
 * Functions related to generic helpers functions
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"

/**
 * blkdev_issue_discard - queue a discard
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	BLKDEV_IFL_* flags to control behaviour
 *
 * Description:
 *    Issue a discard request for the sectors in question.
 */
int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned long flags)
{
	struct request_queue *q = bdev_get_queue(bdev);
	int type = REQ_WRITE | REQ_DISCARD;
	struct bio *bio;
	int ret = 0;

	if (!q)
		return -ENXIO;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	if (flags & BLKDEV_DISCARD_SECURE) {
		if (!blk_queue_secdiscard(q))
			return -EOPNOTSUPP;
		type |= REQ_SECURE;
	}

	while (nr_sects) {
		bio = bio_alloc(gfp_mask, 1);
		if (!bio)
			return -ENOMEM;

		bio->bi_bdev = bdev;
		bio->bi_iter.bi_sector = sector;
		bio->bi_iter.bi_size = min_t(sector_t, nr_sects, 1 << 20) << 9;

		sector += bio_sectors(bio);
		nr_sects -= bio_sectors(bio);

		ret = submit_bio_wait(type, bio);
		if (ret)
			break;

		/*
		 * We can loop for a long time in here, if someone does
		 * full device discards (like mkfs). Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_discard);

/**
 * blkdev_issue_write_same - queue a write same operation
 * @bdev:	target blockdev
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @page:	page containing data to write
 *
 * Description:
 *    Issue a write same request for the sectors in question.
 */
int blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
			    sector_t nr_sects, gfp_t gfp_mask,
			    struct page *page)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio *bio;
	int ret = 0;

	if (!q)
		return -ENXIO;

	if (!q->limits.max_write_same_sectors)
		return -EOPNOTSUPP;

	while (nr_sects) {
		bio = bio_alloc(gfp_mask, 1);
		if (!bio)
			return -ENOMEM;

		bio->bi_bdev = bdev;
		bio->bi_iter.bi_sector = sector;
		bio->bi_iter.bi_size = min_t(sector_t, nr_sects, 1 << 20) << 9;
		bio->bi_vcnt = 1;
		bio->bi_io_vec->bv_page = page;
		bio->bi_io_vec->bv_offset = 0;
		bio->bi_io_vec->bv_len = bdev_logical_block_size(bdev);

		sector += bio_sectors(bio);
		nr_sects -= bio_sectors(bio);

		ret = submit_bio_wait(REQ_WRITE | REQ_WRITE_SAME, bio);
		if (ret)
			break;
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_write_same);

/**
 * blkdev_issue_zeroout - generate number of zero filed write bios
 * @bdev:	blockdev to issue
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * Description:
 *  Generate and issue number of bios with zerofiled pages.
 */
static int __blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
				  sector_t nr_sects, gfp_t gfp_mask)
{
	int ret = 0;
	struct bio *bio;
	unsigned int sz;

	while (nr_sects) {
		bio = bio_alloc(gfp_mask,
				min(nr_sects / (PAGE_SIZE >> 9),
				    (sector_t)BIO_MAX_PAGES));
		if (!bio)
			return -ENOMEM;

		bio->bi_iter.bi_sector = sector;
		bio->bi_bdev   = bdev;

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE >> 9 , nr_sects);
			ret = bio_add_page(bio, ZERO_PAGE(0), sz << 9, 0);
			nr_sects -= ret >> 9;
			sector += ret >> 9;
			if (ret < (sz << 9))
				break;
		}

		ret = submit_bio_wait(WRITE, bio);
		if (ret)
			break;
	}

	return ret;
}

/**
 * blkdev_issue_zeroout - zero-fill a block range
 * @bdev:	blockdev to write
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * Description:
 *  Generate and issue number of bios with zerofiled pages.
 */
int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
			 sector_t nr_sects, gfp_t gfp_mask)
{
	if (bdev_write_same(bdev)) {
		unsigned char bdn[BDEVNAME_SIZE];

		if (!blkdev_issue_write_same(bdev, sector, nr_sects, gfp_mask,
					     ZERO_PAGE(0)))
			return 0;

		bdevname(bdev, bdn);
		pr_err("%s: WRITE SAME failed. Manually zeroing.\n", bdn);
	}

	return __blkdev_issue_zeroout(bdev, sector, nr_sects, gfp_mask);
}
EXPORT_SYMBOL(blkdev_issue_zeroout);
