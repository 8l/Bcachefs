/*
 * Assorted bcache debug code
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "extents.h"

#include <linux/console.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/seq_file.h>

static struct dentry *debug;

#ifdef CONFIG_BCACHE_DEBUG

static void dump_bset(struct btree_keys *b, struct bset *i)
{
	struct bkey *k, *next;

	for (k = i->start; k < bset_bkey_last(i); k = next) {
		next = bkey_next(k);

		printk(KERN_ERR "block %u key %zi/%u: ",
		       bset_sector_offset(b, i),
		       (uint64_t *) k - i->d, i->keys);

		if (b->ops->key_dump)
			b->ops->key_dump(b, k);
		else
			printk("%llu:%llu\n", KEY_INODE(k), KEY_OFFSET(k));

		if (next < bset_bkey_last(i) &&
		    bkey_cmp(k, b->ops->is_extents ?
			     &START_KEY(next) : next) > 0)
			printk(KERN_ERR "Key skipped backwards\n");
	}
}

void bch_dump_bucket(struct btree_keys *b)
{
	unsigned i;

	console_lock();
	for (i = 0; i <= b->nsets; i++)
		dump_bset(b, b->set[i].data);
	console_unlock();
}

void bch_data_verify(struct cached_dev *dc, struct bio *bio)
{
	char name[BDEVNAME_SIZE];
	struct bio *check;
	struct bio_vec *bv;
	struct bvec_iter iter1, iter2;
	int i;

	check = bio_alloc(GFP_NOIO,
			  DIV_ROUND_UP(bio->bi_iter.bi_size, PAGE_SIZE));

	check->bi_bdev		= bio->bi_bdev;
	check->bi_iter.bi_sector = bio->bi_iter.bi_sector;
	check->bi_iter.bi_size	= bio->bi_iter.bi_size;
	bch_bio_map(check, NULL);

	if (bio_alloc_pages(check, GFP_NOIO))
		goto out_put;

	iter1 = bio->bi_iter;
	iter2 = check->bi_iter;

	submit_bio_wait(READ_SYNC, check);

	while (iter1.bi_size) {
		struct bio_vec bv1 = bio_iter_iovec(bio, iter1);
		struct bio_vec bv2 = bio_iter_iovec(check, iter2);
		void *p1 = kmap_atomic(bv1.bv_page);
		void *p2 = page_address(bv2.bv_page);
		unsigned bytes = min(bv1.bv_len, bv2.bv_len);

		cache_set_err_on(memcmp(p1 + bv1.bv_offset,
					p2 + bv2.bv_offset,
					bytes),
				 dc->disk.c,
				 "verify failed at dev %s sector %llu",
				 bdevname(dc->bdev, name),
				 (uint64_t) iter1.bi_sector);

		kunmap_atomic(p1);

		bio_advance_iter(bio, &iter1, bytes);
		bio_advance_iter(check, &iter2, bytes);
	}

	bio_for_each_segment_all(bv, check, i)
		__free_page(bv->bv_page);
out_put:
	bio_put(check);
}

int __bch_count_data(struct btree_keys *b)
{
	unsigned ret = 0;
	struct btree_iter iter;
	struct bkey *k;

	if (b->ops->is_extents)
		for_each_key(b, k, &iter)
			ret += KEY_SIZE(k);
	return ret;
}

void __bch_check_keys(struct btree_keys *b, const char *fmt, ...)
{
	va_list args;
	struct bkey *k, *p = NULL;
	struct btree_iter iter;
	const char *err;

	for_each_key(b, k, &iter) {
		if (b->ops->is_extents) {
			err = "Keys out of order";
			if (p && bkey_cmp(&START_KEY(p), &START_KEY(k)) > 0)
				goto bug;

			if (bch_ptr_invalid(b, k))
				continue;

			err =  "Overlapping keys";
			if (p && bkey_cmp(p, &START_KEY(k)) > 0)
				goto bug;
		} else {
			if (bch_ptr_bad(b, k))
				continue;

			err = "Duplicate keys";
			if (p && !bkey_cmp(p, k))
				goto bug;
		}
		p = k;
	}
#if 0
	err = "Key larger than btree node key";
	if (p && bkey_cmp(p, &b->key) > 0)
		goto bug;
#endif
	return;
bug:
	bch_dump_bucket(b);

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	panic("bch_check_keys error:  %s:\n", err);
}

void bch_btree_iter_next_check(struct btree_iter *iter)
{
	struct bkey *k = iter->data->k, *next = bkey_next(k);

	if (next < iter->data->end &&
	    bkey_cmp(k, iter->b->ops->is_extents ?
		     &START_KEY(next) : next) > 0) {
		bch_dump_bucket(iter->b);
		panic("Key skipped backwards\n");
	}
}

#endif

#ifdef CONFIG_DEBUG_FS

/* XXX: cache set refcounting */

struct dump_iterator {
	char			buf[PAGE_SIZE];
	size_t			bytes;
	struct cache_set	*c;
	struct keybuf		keys;
};

static bool dump_pred(struct keybuf *buf, struct bkey *k)
{
	return true;
}

static ssize_t bch_dump_read(struct file *file, char __user *buf,
			     size_t size, loff_t *ppos)
{
	struct dump_iterator *i = file->private_data;
	ssize_t ret = 0;
	char kbuf[80];

	while (size) {
		struct keybuf_key *w;
		unsigned bytes = min(i->bytes, size);

		int err = copy_to_user(buf, i->buf, bytes);
		if (err)
			return err;

		ret	 += bytes;
		buf	 += bytes;
		size	 -= bytes;
		i->bytes -= bytes;
		memmove(i->buf, i->buf + bytes, i->bytes);

		if (i->bytes)
			break;

		w = bch_keybuf_next_rescan(i->c, &i->keys, &MAX_KEY, dump_pred);
		if (!w)
			break;

		bch_bkey_to_text(kbuf, sizeof(kbuf), &w->key);
		i->bytes = snprintf(i->buf, PAGE_SIZE, "%s\n", kbuf);
		bch_keybuf_del(&i->keys, w);
	}

	return ret;
}

static int bch_dump_open(struct inode *inode, struct file *file)
{
	struct cache_set *c = inode->i_private;
	struct dump_iterator *i;

	i = kzalloc(sizeof(struct dump_iterator), GFP_KERNEL);
	if (!i)
		return -ENOMEM;

	file->private_data = i;
	i->c = c;
	bch_keybuf_init(&i->keys);
	i->keys.last_scanned = KEY(0, 0, 0);

	return 0;
}

static int bch_dump_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct file_operations cache_set_debug_ops = {
	.owner		= THIS_MODULE,
	.open		= bch_dump_open,
	.read		= bch_dump_read,
	.release	= bch_dump_release
};

void bch_debug_init_cache_set(struct cache_set *c)
{
	if (!IS_ERR_OR_NULL(debug)) {
		char name[50];
		snprintf(name, 50, "bcache-%pU", c->sb.set_uuid);

		c->debug = debugfs_create_file(name, 0400, debug, c,
					       &cache_set_debug_ops);
	}
}

#endif

void bch_debug_exit(void)
{
	if (!IS_ERR_OR_NULL(debug))
		debugfs_remove_recursive(debug);
}

int __init bch_debug_init(struct kobject *kobj)
{
	int ret = 0;

	debug = debugfs_create_dir("bcache", NULL);
	return ret;
}
