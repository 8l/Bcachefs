#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "util.h"

#define CREATE_TRACE_POINTS
#include <trace/events/bcache.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(bcache_start_closure_wait);
EXPORT_TRACEPOINT_SYMBOL_GPL(bcache_end_closure_wait);

#define STRTO_H(name, type)					\
int name ## _h(const char *cp, type *res)		        \
{								\
	int u = 0;						\
	char *e;						\
	type i = simple_ ## name(cp, &e, 10);			\
								\
	switch (tolower(*e)) {					\
	default:						\
		return -EINVAL;					\
	case 'y':						\
	case 'z':						\
		u++;						\
	case 'e':						\
		u++;						\
	case 'p':						\
		u++;						\
	case 't':						\
		u++;						\
	case 'g':						\
		u++;						\
	case 'm':						\
		u++;						\
	case 'k':						\
		u++;						\
		if (e++ == cp)					\
			return -EINVAL;				\
	case '\n':						\
	case '\0':						\
		if (*e == '\n')					\
			e++;					\
	}							\
								\
	if (*e)							\
		return -EINVAL;					\
								\
	while (u--) {						\
		if ((type) ~0 > 0 &&				\
		    (type) ~0 / 1024 <= i)			\
			return -EINVAL;				\
		if ((i > 0 && ANYSINT_MAX(type) / 1024 < i) ||	\
		    (i < 0 && -ANYSINT_MAX(type) / 1024 > i))	\
			return -EINVAL;				\
		i *= 1024;					\
	}							\
								\
	*res = i;						\
	return 0;						\
}								\
EXPORT_SYMBOL_GPL(name ## _h);

STRTO_H(strtol, long)
STRTO_H(strtoll, long long)
STRTO_H(strtoul, unsigned long)
STRTO_H(strtoull, unsigned long long)

ssize_t hprint(char *buf, int64_t v)
{
	static const char units[] = "\0kMGTPEZY";
	char dec[3] = "";
	int u, t = 0;

	for (u = 0; v >= 1024 || v <= -1024; u++)
		t = do_div(v, 1024);

	if (u && v < 100 && v > -100)
		sprintf(dec, ".%i", t / 100);

	return sprintf(buf, "%lli%s%c", v, dec, units[u]);
}
EXPORT_SYMBOL_GPL(hprint);

bool is_zero(const char *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i])
			return false;
	return true;
}
EXPORT_SYMBOL_GPL(is_zero);

int parse_uuid(const char *s, char *uuid)
{
	size_t i, j, x;
	memset(uuid, 0, 16);

	for (i = 0, j = 0;
	     i < strspn(s, "-0123456789:ABCDEFabcdef") && j < 32;
	     i++) {
		x = s[i] | 32;

		switch (x) {
		case '0'...'9':
			x -= '0';
			break;
		case 'a'...'f':
			x -= 'a' - 10;
			break;
		default:
			continue;
		}

		if (!(j & 1))
			x <<= 4;
		uuid[j++ >> 1] |= x;
	}
	return i;
}
EXPORT_SYMBOL_GPL(parse_uuid);

#ifdef CONFIG_BCACHE_LATENCY_DEBUG
unsigned latency_warn_ms;
#endif

#ifdef CONFIG_BCACHE_EDEBUG

static void check_bio(struct bio *bio)
{
	int i, size = 0;
	struct bio_vec *bv;
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	BUG_ON(!bio->bi_vcnt);
	BUG_ON(!bio->bi_size);

	bio_for_each_segment(bv, bio, i)
		size += bv->bv_len;

	BUG_ON(size != bio->bi_size);
	BUG_ON(size > queue_max_sectors(q) << 9);

	blk_recount_segments(q, bio);
	BUG_ON(bio->bi_phys_segments > queue_max_segments(q));
}

#else /* EDEBUG */

#define check_bio(bio)		do {} while (0)

#endif

void bio_reset(struct bio *bio)
{
	struct bio_vec *bv = bio->bi_io_vec;
	unsigned max_vecs = bio->bi_max_vecs;
	bio_destructor_t *destructor = bio->bi_destructor;

	bio_init(bio);
	atomic_set(&bio->bi_cnt, 2);
	bio->bi_max_vecs	= max_vecs;
	bio->bi_io_vec		= bv;
	bio->bi_destructor	= destructor;
}
EXPORT_SYMBOL_GPL(bio_reset);

void bio_map(struct bio *bio, void *base)
{
	size_t size = bio->bi_size;
	struct bio_vec *bv = bio->bi_inline_vecs;

	BUG_ON(!bio->bi_size);
	bio->bi_vcnt	= 0;
	bio->bi_io_vec	= bv;

	bv->bv_offset = base ? ((unsigned long) base) % PAGE_SIZE : 0;
	goto start;

	for (; size; bio->bi_vcnt++, bv++) {
		bv->bv_offset	= 0;
start:		bv->bv_len	= min_t(size_t, PAGE_SIZE - bv->bv_offset,
					size);
		if (base) {
			bv->bv_page = is_vmalloc_addr(base)
				? vmalloc_to_page(base)
				: virt_to_page(base);

			base += bv->bv_len;
		}

		size -= bv->bv_len;
	}
}
EXPORT_SYMBOL_GPL(bio_map);

#undef bio_alloc_pages
int bio_alloc_pages(struct bio *bio, gfp_t gfp)
{
	int i;
	struct bio_vec *bv;
	bio_for_each_segment(bv, bio, i) {
		bv->bv_page = alloc_page(gfp);
		if (!bv) {
			while (bv-- != bio->bi_io_vec + bio->bi_idx)
				__free_page(bv->bv_page);
			return -ENOMEM;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(bio_alloc_pages);

struct bio *bio_split_front(struct bio *bio, int sectors, bio_alloc_fn *_alloc,
			    gfp_t gfp, struct bio_set *bs)
{
	unsigned idx, vcnt = 0, nbytes = sectors << 9;
	struct bio_vec *bv;
	struct bio *ret = NULL;

	struct bio *alloc(int n)
	{
		if (bs)
			return bio_alloc_bioset(gfp, n, bs);
		else if (_alloc)
			return _alloc(gfp, n);
		else
			return bio_kmalloc(gfp, n);
	}

	if (current->bio_list)
		bs = NULL;

	BUG_ON(sectors <= 0);

	if (nbytes >= bio->bi_size)
		return bio;

	bio_for_each_segment(bv, bio, idx) {
		vcnt = idx - bio->bi_idx;

		if (!nbytes) {
			ret = alloc(0);
			if (!ret)
				return NULL;

			ret->bi_io_vec = bio_iovec(bio);
			ret->bi_flags |= 1 << BIO_CLONED;
			break;
		} else if (nbytes < bv->bv_len) {
			ret = alloc(++vcnt);
			if (!ret)
				return NULL;

			memcpy(ret->bi_io_vec, bio_iovec(bio),
			       sizeof(struct bio_vec) * vcnt);

			ret->bi_io_vec[vcnt - 1].bv_len = nbytes;
			bv->bv_offset	+= nbytes;
			bv->bv_len	-= nbytes;
			break;
		}

		nbytes -= bv->bv_len;
	}

	ret->bi_bdev	= bio->bi_bdev;
	ret->bi_sector	= bio->bi_sector;
	ret->bi_size	= sectors << 9;
	ret->bi_rw	= bio->bi_rw;
	ret->bi_vcnt	= vcnt;
	ret->bi_max_vecs = vcnt;
	ret->bi_end_io	= bio->bi_end_io;
	ret->bi_private	= bio->bi_private;

	if (ret && ret != bio && bs) {
		ret->bi_flags |= 1 << BIO_HAS_POOL;
		ret->bi_destructor = (void *) bs;
	}

	bio->bi_sector	+= sectors;
	bio->bi_size	-= sectors << 9;
	bio->bi_idx	 = idx;

	return ret;
}
EXPORT_SYMBOL_GPL(bio_split_front);

unsigned __bio_max_sectors(struct bio *bio, struct block_device *bdev,
			   sector_t sector)
{
	unsigned ret = bio_sectors(bio);
	struct request_queue *q = bdev_get_queue(bdev);
	struct bio_vec *end = bio_iovec(bio) +
		min_t(int, bio_segments(bio), queue_max_segments(q));

	struct bvec_merge_data bvm = {
		.bi_bdev	= bdev,
		.bi_sector	= sector,
		.bi_size	= 0,
		.bi_rw		= bio->bi_rw,
	};

	if (bio_segments(bio) > queue_max_segments(q) ||
	    q->merge_bvec_fn) {
		ret = 0;

		for (struct bio_vec *bv = bio_iovec(bio); bv < end; bv++) {
			if (q->merge_bvec_fn &&
			    q->merge_bvec_fn(q, &bvm, bv) < (int) bv->bv_len)
				break;

			ret		+= bv->bv_len >> 9;
			bvm.bi_size	+= bv->bv_len;
		}
	}

	ret = min(ret, queue_max_sectors(q));

	WARN_ON(!ret);
	ret = max_t(int, ret, bio_iovec(bio)->bv_len >> 9);

	return ret;
}
EXPORT_SYMBOL_GPL(__bio_max_sectors);

int bio_submit_split(struct bio *bio, atomic_t *i, struct bio_set *bs)
{
	struct bio *n;

	do {
		n = bio_split_front(bio, bio_max_sectors(bio),
				    NULL, GFP_NOIO, bs);
		if (!n)
			return -ENOMEM;
		else if (n != bio)
			atomic_inc(i);

		check_bio(n);
		generic_make_request(n);
	} while (n != bio);

	return 0;
}
EXPORT_SYMBOL_GPL(bio_submit_split);

/* Closure like things
 * XXX: Documentation should go here.
 */

#ifdef CONFIG_BCACHE_CLOSURE_DEBUG

LIST_HEAD(closures);
spinlock_t closure_lock;
EXPORT_SYMBOL(closure_lock);

#define SET_WAITING(s, f)	((s)->waiting_on = f)
#else
#define SET_WAITING(s, f)	do {} while (0)
#endif

void __closure_init(struct closure *c, struct closure *parent, bool onstack)
{
	memset(c, 0, sizeof(struct closure));
	__INIT_WORK(&c->w, NULL, onstack);
	atomic_set(&c->remaining, 1);
	set_wait(c);
	c->parent = parent;
	if (parent)
		closure_get(parent);

#ifdef CONFIG_BCACHE_CLOSURE_DEBUG
	if (!onstack) {
		spin_lock_irq(&closure_lock);
		list_add(&c->all, &closures);
		spin_unlock_irq(&closure_lock);
	}
#endif
}
EXPORT_SYMBOL_GPL(__closure_init);

void closure_put(struct closure *c, struct workqueue_struct *wq)
{
	bool sleeping;
	int r;
again:
	pr_latency(c->wait_time, "%pf", c->fn);

	sleeping = test_bit(__CLOSURE_SLEEPING, &c->flags);
	r = atomic_dec_return(&c->remaining);
	smp_mb__after_atomic_dec();

	BUG_ON(r < 0);
	if (r == 1 && sleeping)
		wake_up_process(c->p);
	if (r)
		return;

	BUG_ON(test_bit(__CLOSURE_STACK, &c->flags));
	BUG_ON(test_bit(__CLOSURE_WAITING, &c->flags));
	BUG_ON(test_bit(__CLOSURE_SLEEPING, &c->flags));

	if (!c->fn) {
		closure_del(c);

		c = c->parent;
		if (c)
			goto again;
		return;
	}

	atomic_set(&c->remaining, 1);
	set_wait(c);

	if (!wq || test_bit(CLOSURE_NOQUEUE, &c->flags)) {
		clear_bit(CLOSURE_NOQUEUE, &c->flags);
		c->fn(c);
	} else {
		INIT_LIST_HEAD(&c->w.entry);
		BUG_ON(!queue_work(wq, &c->w));
	}
}
EXPORT_SYMBOL_GPL(closure_put);

void closure_run_wait(closure_list_t *list, struct workqueue_struct *wq)
{
	struct closure *c, *next;
	smp_mb();
	for (c = xchg(&list->head, NULL); c; c = next) {
		next = c->next;
		trace_bcache_end_closure_wait(c, _THIS_IP_);
		SET_WAITING(c, 0);

		clear_bit(__CLOSURE_WAITING, &c->flags);
		closure_put(c, wq);
	}
}
EXPORT_SYMBOL_GPL(closure_run_wait);

bool closure_wait(closure_list_t *list, struct closure *c)
{
	smp_rmb(); /* for __CLOSURE_WAITING */

	if (!test_bit(__CLOSURE_WAITING, &c->flags)) {
		SET_WAITING(c, _RET_IP_);
		trace_bcache_start_closure_wait(c, _RET_IP_);

		set_bit(__CLOSURE_WAITING, &c->flags);
		closure_get(c);
		smp_mb__after_atomic_inc(); /* for __CLOSURE_WAITING */
		lockless_list_push(c, list->head, next);
		return true;
	} else
		return false;
}
EXPORT_SYMBOL_GPL(closure_wait);

void __closure_sleep(struct closure *c)
{
	c->p = current;
	set_current_state(TASK_UNINTERRUPTIBLE);
	smp_wmb();
	set_bit(__CLOSURE_SLEEPING, &c->flags);
}
EXPORT_SYMBOL_GPL(__closure_sleep);

void closure_sync(struct closure *c)
{
	while (1) {
		__closure_sleep(c);

		if (atomic_read(&c->remaining) == 1)
			break;

		schedule();
	}
	__set_current_state(TASK_RUNNING);
	clear_bit(__CLOSURE_SLEEPING, &c->flags);

	smp_rmb(); /* for __CLOSURE_WAITING */
	BUG_ON(test_bit(__CLOSURE_WAITING, &c->flags));
}
EXPORT_SYMBOL_GPL(closure_sync);

#ifdef CONFIG_BCACHE_CLOSURE_DEBUG

static struct dentry *debug;

static int debug_seq_show(struct seq_file *f, void *data)
{
	struct closure *cl;

	spin_lock_irq(&closure_lock);

	list_for_each_entry(cl, &closures, all)
		seq_printf(f, "%pf -> %p remaining %i "
			   "waiting on %pf for %i ms\n",
			   cl->fn, cl->parent, atomic_read(&cl->remaining),
			   (void *) cl->waiting_on, latency_ms(cl->wait_time));

	spin_unlock_irq(&closure_lock);
	return 0;
}

static int debug_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, debug_seq_show, NULL);
}

static const struct file_operations debug_ops = {
	.owner		= THIS_MODULE,
	.open		= debug_seq_open,
	.read		= seq_read,
	.release	= single_release
};

static int __init closure_debug_init(void)
{
	spin_lock_init(&closure_lock);
	debug = debugfs_create_file("closures", 0400, NULL, NULL, &debug_ops);
	return 0;
}

static void closure_debug_exit(void)
{
	debugfs_remove(debug);
}

module_init(closure_debug_init);
module_exit(closure_debug_exit);

#endif

/*
 * Portions Copyright (c) 1996-2001, PostgreSQL Global Development Group (Any
 * use permitted, subject to terms of PostgreSQL license; see.)

 * If we have a 64-bit integer type, then a 64-bit CRC looks just like the
 * usual sort of implementation. (See Ross Williams' excellent introduction
 * A PAINLESS GUIDE TO CRC ERROR DETECTION ALGORITHMS, available from
 * ftp://ftp.rocksoft.com/papers/crc_v3.txt or several other net sites.)
 * If we have no working 64-bit type, then fake it with two 32-bit registers.
 *
 * The present implementation is a normal (not "reflected", in Williams'
 * terms) 64-bit CRC, using initial all-ones register contents and a final
 * bit inversion. The chosen polynomial is borrowed from the DLT1 spec
 * (ECMA-182, available from http://www.ecma.ch/ecma1/STAND/ECMA-182.HTM):
 *
 * x^64 + x^62 + x^57 + x^55 + x^54 + x^53 + x^52 + x^47 + x^46 + x^45 +
 * x^40 + x^39 + x^38 + x^37 + x^35 + x^33 + x^32 + x^31 + x^29 + x^27 +
 * x^24 + x^23 + x^22 + x^21 + x^19 + x^17 + x^13 + x^12 + x^10 + x^9 +
 * x^7 + x^4 + x + 1
*/

static const uint64_t crc_table[256] = {
	0x0000000000000000, 0x42F0E1EBA9EA3693, 0x85E1C3D753D46D26,
	0xC711223CFA3E5BB5, 0x493366450E42ECDF, 0x0BC387AEA7A8DA4C,
	0xCCD2A5925D9681F9, 0x8E224479F47CB76A, 0x9266CC8A1C85D9BE,
	0xD0962D61B56FEF2D, 0x17870F5D4F51B498, 0x5577EEB6E6BB820B,
	0xDB55AACF12C73561, 0x99A54B24BB2D03F2, 0x5EB4691841135847,
	0x1C4488F3E8F96ED4, 0x663D78FF90E185EF, 0x24CD9914390BB37C,
	0xE3DCBB28C335E8C9, 0xA12C5AC36ADFDE5A, 0x2F0E1EBA9EA36930,
	0x6DFEFF5137495FA3, 0xAAEFDD6DCD770416, 0xE81F3C86649D3285,
	0xF45BB4758C645C51, 0xB6AB559E258E6AC2, 0x71BA77A2DFB03177,
	0x334A9649765A07E4, 0xBD68D2308226B08E, 0xFF9833DB2BCC861D,
	0x388911E7D1F2DDA8, 0x7A79F00C7818EB3B, 0xCC7AF1FF21C30BDE,
	0x8E8A101488293D4D, 0x499B3228721766F8, 0x0B6BD3C3DBFD506B,
	0x854997BA2F81E701, 0xC7B97651866BD192, 0x00A8546D7C558A27,
	0x4258B586D5BFBCB4, 0x5E1C3D753D46D260, 0x1CECDC9E94ACE4F3,
	0xDBFDFEA26E92BF46, 0x990D1F49C77889D5, 0x172F5B3033043EBF,
	0x55DFBADB9AEE082C, 0x92CE98E760D05399, 0xD03E790CC93A650A,
	0xAA478900B1228E31, 0xE8B768EB18C8B8A2, 0x2FA64AD7E2F6E317,
	0x6D56AB3C4B1CD584, 0xE374EF45BF6062EE, 0xA1840EAE168A547D,
	0x66952C92ECB40FC8, 0x2465CD79455E395B, 0x3821458AADA7578F,
	0x7AD1A461044D611C, 0xBDC0865DFE733AA9, 0xFF3067B657990C3A,
	0x711223CFA3E5BB50, 0x33E2C2240A0F8DC3, 0xF4F3E018F031D676,
	0xB60301F359DBE0E5, 0xDA050215EA6C212F, 0x98F5E3FE438617BC,
	0x5FE4C1C2B9B84C09, 0x1D14202910527A9A, 0x93366450E42ECDF0,
	0xD1C685BB4DC4FB63, 0x16D7A787B7FAA0D6, 0x5427466C1E109645,
	0x4863CE9FF6E9F891, 0x0A932F745F03CE02, 0xCD820D48A53D95B7,
	0x8F72ECA30CD7A324, 0x0150A8DAF8AB144E, 0x43A04931514122DD,
	0x84B16B0DAB7F7968, 0xC6418AE602954FFB, 0xBC387AEA7A8DA4C0,
	0xFEC89B01D3679253, 0x39D9B93D2959C9E6, 0x7B2958D680B3FF75,
	0xF50B1CAF74CF481F, 0xB7FBFD44DD257E8C, 0x70EADF78271B2539,
	0x321A3E938EF113AA, 0x2E5EB66066087D7E, 0x6CAE578BCFE24BED,
	0xABBF75B735DC1058, 0xE94F945C9C3626CB, 0x676DD025684A91A1,
	0x259D31CEC1A0A732, 0xE28C13F23B9EFC87, 0xA07CF2199274CA14,
	0x167FF3EACBAF2AF1, 0x548F120162451C62, 0x939E303D987B47D7,
	0xD16ED1D631917144, 0x5F4C95AFC5EDC62E, 0x1DBC74446C07F0BD,
	0xDAAD56789639AB08, 0x985DB7933FD39D9B, 0x84193F60D72AF34F,
	0xC6E9DE8B7EC0C5DC, 0x01F8FCB784FE9E69, 0x43081D5C2D14A8FA,
	0xCD2A5925D9681F90, 0x8FDAB8CE70822903, 0x48CB9AF28ABC72B6,
	0x0A3B7B1923564425, 0x70428B155B4EAF1E, 0x32B26AFEF2A4998D,
	0xF5A348C2089AC238, 0xB753A929A170F4AB, 0x3971ED50550C43C1,
	0x7B810CBBFCE67552, 0xBC902E8706D82EE7, 0xFE60CF6CAF321874,
	0xE224479F47CB76A0, 0xA0D4A674EE214033, 0x67C58448141F1B86,
	0x253565A3BDF52D15, 0xAB1721DA49899A7F, 0xE9E7C031E063ACEC,
	0x2EF6E20D1A5DF759, 0x6C0603E6B3B7C1CA, 0xF6FAE5C07D3274CD,
	0xB40A042BD4D8425E, 0x731B26172EE619EB, 0x31EBC7FC870C2F78,
	0xBFC9838573709812, 0xFD39626EDA9AAE81, 0x3A28405220A4F534,
	0x78D8A1B9894EC3A7, 0x649C294A61B7AD73, 0x266CC8A1C85D9BE0,
	0xE17DEA9D3263C055, 0xA38D0B769B89F6C6, 0x2DAF4F0F6FF541AC,
	0x6F5FAEE4C61F773F, 0xA84E8CD83C212C8A, 0xEABE6D3395CB1A19,
	0x90C79D3FEDD3F122, 0xD2377CD44439C7B1, 0x15265EE8BE079C04,
	0x57D6BF0317EDAA97, 0xD9F4FB7AE3911DFD, 0x9B041A914A7B2B6E,
	0x5C1538ADB04570DB, 0x1EE5D94619AF4648, 0x02A151B5F156289C,
	0x4051B05E58BC1E0F, 0x87409262A28245BA, 0xC5B073890B687329,
	0x4B9237F0FF14C443, 0x0962D61B56FEF2D0, 0xCE73F427ACC0A965,
	0x8C8315CC052A9FF6, 0x3A80143F5CF17F13, 0x7870F5D4F51B4980,
	0xBF61D7E80F251235, 0xFD913603A6CF24A6, 0x73B3727A52B393CC,
	0x31439391FB59A55F, 0xF652B1AD0167FEEA, 0xB4A25046A88DC879,
	0xA8E6D8B54074A6AD, 0xEA16395EE99E903E, 0x2D071B6213A0CB8B,
	0x6FF7FA89BA4AFD18, 0xE1D5BEF04E364A72, 0xA3255F1BE7DC7CE1,
	0x64347D271DE22754, 0x26C49CCCB40811C7, 0x5CBD6CC0CC10FAFC,
	0x1E4D8D2B65FACC6F, 0xD95CAF179FC497DA, 0x9BAC4EFC362EA149,
	0x158E0A85C2521623, 0x577EEB6E6BB820B0, 0x906FC95291867B05,
	0xD29F28B9386C4D96, 0xCEDBA04AD0952342, 0x8C2B41A1797F15D1,
	0x4B3A639D83414E64, 0x09CA82762AAB78F7, 0x87E8C60FDED7CF9D,
	0xC51827E4773DF90E, 0x020905D88D03A2BB, 0x40F9E43324E99428,
	0x2CFFE7D5975E55E2, 0x6E0F063E3EB46371, 0xA91E2402C48A38C4,
	0xEBEEC5E96D600E57, 0x65CC8190991CB93D, 0x273C607B30F68FAE,
	0xE02D4247CAC8D41B, 0xA2DDA3AC6322E288, 0xBE992B5F8BDB8C5C,
	0xFC69CAB42231BACF, 0x3B78E888D80FE17A, 0x7988096371E5D7E9,
	0xF7AA4D1A85996083, 0xB55AACF12C735610, 0x724B8ECDD64D0DA5,
	0x30BB6F267FA73B36, 0x4AC29F2A07BFD00D, 0x08327EC1AE55E69E,
	0xCF235CFD546BBD2B, 0x8DD3BD16FD818BB8, 0x03F1F96F09FD3CD2,
	0x41011884A0170A41, 0x86103AB85A2951F4, 0xC4E0DB53F3C36767,
	0xD8A453A01B3A09B3, 0x9A54B24BB2D03F20, 0x5D45907748EE6495,
	0x1FB5719CE1045206, 0x919735E51578E56C, 0xD367D40EBC92D3FF,
	0x1476F63246AC884A, 0x568617D9EF46BED9, 0xE085162AB69D5E3C,
	0xA275F7C11F7768AF, 0x6564D5FDE549331A, 0x279434164CA30589,
	0xA9B6706FB8DFB2E3, 0xEB46918411358470, 0x2C57B3B8EB0BDFC5,
	0x6EA7525342E1E956, 0x72E3DAA0AA188782, 0x30133B4B03F2B111,
	0xF7021977F9CCEAA4, 0xB5F2F89C5026DC37, 0x3BD0BCE5A45A6B5D,
	0x79205D0E0DB05DCE, 0xBE317F32F78E067B, 0xFCC19ED95E6430E8,
	0x86B86ED5267CDBD3, 0xC4488F3E8F96ED40, 0x0359AD0275A8B6F5,
	0x41A94CE9DC428066, 0xCF8B0890283E370C, 0x8D7BE97B81D4019F,
	0x4A6ACB477BEA5A2A, 0x089A2AACD2006CB9, 0x14DEA25F3AF9026D,
	0x562E43B4931334FE, 0x913F6188692D6F4B, 0xD3CF8063C0C759D8,
	0x5DEDC41A34BBEEB2, 0x1F1D25F19D51D821, 0xD80C07CD676F8394,
	0x9AFCE626CE85B507
};

uint64_t crc64_update(uint64_t crc, const void *_data, size_t len)
{
	const unsigned char *data = _data;

	while (len--) {
		int i = ((int) (crc >> 56) ^ *data++) & 0xFF;
		crc = crc_table[i] ^ (crc << 8);
	}

	return crc;
}
EXPORT_SYMBOL(crc64_update);

uint64_t crc64(const void *data, size_t len)
{
	uint64_t crc = 0xffffffffffffffff;

	crc = crc64_update(crc, data, len);

	return crc ^ 0xffffffffffffffff;
}
EXPORT_SYMBOL(crc64);

unsigned popcount_64(uint64_t x)
{
	static const uint64_t m1  = 0x5555555555555555LLU;
	static const uint64_t m2  = 0x3333333333333333LLU;
	static const uint64_t m4  = 0x0f0f0f0f0f0f0f0fLLU;
	static const uint64_t h01 = 0x0101010101010101LLU;

	x -= (x >> 1) & m1;
	x = (x & m2) + ((x >> 2) & m2);
	x = (x + (x >> 4)) & m4;
	return (x * h01) >> 56;
}
EXPORT_SYMBOL(popcount_64);

unsigned popcount_32(uint32_t x)
{
	static const uint32_t m1  = 0x55555555;
	static const uint32_t m2  = 0x33333333;
	static const uint32_t m4  = 0x0f0f0f0f;
	static const uint32_t h01 = 0x01010101;

	x -= (x >> 1) & m1;
	x = (x & m2) + ((x >> 2) & m2);
	x = (x + (x >> 4)) & m4;
	return (x * h01) >> 24;
}
EXPORT_SYMBOL(popcount_32);
