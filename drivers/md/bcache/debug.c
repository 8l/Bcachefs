/*
 * Assorted bcache debug code
 *
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree.h"
#include "buckets.h"
#include "debug.h"
#include "extents.h"
#include "io.h"
#include "super.h"

#include <linux/console.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/seq_file.h>

static struct dentry *bch_debug;

#ifdef CONFIG_BCACHE_DEBUG

#define for_each_written_bset(b, start, i)				\
	for (i = (start);						\
	     (void *) i < (void *) (start) + btree_bytes(b->c) &&\
	     i->seq == (start)->seq;					\
	     i = (void *) i + set_blocks(i, block_bytes(b->c)) *	\
		 block_bytes(b->c))

static void btree_verify_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

void bch_btree_verify(struct btree *b)
{
	const struct bkey_i_extent *e = bkey_i_to_extent_c(&b->key);
	struct btree *v = b->c->verify_data;
	struct bset *ondisk, *sorted, *inmemory;
	struct cache *ca;
	struct bio *bio;
	struct closure cl;

	if (!b->c->verify || !b->c->verify_ondisk)
		return;

	closure_init_stack(&cl);

	down(&b->io_mutex);
	mutex_lock(&b->c->verify_lock);

	ondisk = b->c->verify_ondisk;
	sorted = b->c->verify_data->keys.set->data;
	inmemory = b->keys.set->data;

	bkey_copy(&v->key, &b->key);
	v->written = 0;
	v->level = b->level;
	v->keys.ops = b->keys.ops;

	rcu_read_lock();
	ca = PTR_CACHE(b->c, &e->v.ptr[0]);
	percpu_ref_get(&ca->ref);
	rcu_read_unlock();
	bio = bch_bbio_alloc(b->c);
	bio->bi_rw		= REQ_META|READ_SYNC;
	bio->bi_bdev		= ca->disk_sb.bdev;
	bio->bi_iter.bi_sector	= PTR_OFFSET(&e->v.ptr[0]);
	bio->bi_iter.bi_size	= btree_bytes(b->c);
	bio->bi_private		= &cl;
	bio->bi_end_io		= btree_verify_endio;
	bch_bio_map(bio, sorted);

	closure_bio_submit_punt(bio, &cl, b->c);
	closure_sync(&cl);

	bch_bbio_free(bio, b->c);

	memcpy(ondisk, sorted, btree_bytes(b->c));

	bch_btree_node_read_done(v, ca, 0);
	sorted = v->keys.set->data;

	percpu_ref_put(&ca->ref);

	if (inmemory->u64s != sorted->u64s ||
	    memcmp(inmemory->start,
		   sorted->start,
		   (void *) bset_bkey_last(inmemory) - (void *) inmemory->start)) {
		struct bset *i;
		unsigned j;

		console_lock();

		printk(KERN_ERR "*** in memory:\n");
		bch_dump_bset(&b->keys, inmemory, 0);

		printk(KERN_ERR "*** read back in:\n");
		bch_dump_bset(&v->keys, sorted, 0);

		for_each_written_bset(b, ondisk, i) {
			unsigned block = ((void *) i - (void *) ondisk) /
				block_bytes(b->c);

			printk(KERN_ERR "*** on disk block %u:\n", block);
			bch_dump_bset(&b->keys, i, block);
		}

		printk(KERN_ERR "*** block %zu not written\n",
		       ((void *) i - (void *) ondisk) / block_bytes(b->c));

		for (j = 0; j < inmemory->u64s; j++)
			if (inmemory->_data[j] != sorted->_data[j])
				break;

		printk(KERN_ERR "b->written %u\n", b->written);

		console_unlock();
		panic("verify failed at %u\n", j);
	}

	mutex_unlock(&b->c->verify_lock);
	up(&b->io_mutex);
}

void bch_data_verify(struct cached_dev *dc, struct bio *bio)
{
	char name[BDEVNAME_SIZE];
	struct bio *check;
	struct bio_vec bv, *bv2;
	struct bvec_iter iter;
	int i;

	check = bio_clone(bio, GFP_NOIO);
	if (!check)
		return;

	if (bio_alloc_pages(check, GFP_NOIO))
		goto out_put;

	submit_bio_wait(READ_SYNC, check);

	bio_for_each_segment(bv, bio, iter) {
		void *p1 = kmap_atomic(bv.bv_page);
		void *p2 = page_address(check->bi_io_vec[iter.bi_idx].bv_page);

		cache_set_err_on(memcmp(p1 + bv.bv_offset,
					p2 + bv.bv_offset,
					bv.bv_len),
				 dc->disk.c,
				 "verify failed at dev %s sector %llu",
				 bdevname(dc->disk_sb.bdev, name),
				 (uint64_t) bio->bi_iter.bi_sector);

		kunmap_atomic(p1);
	}

	bio_for_each_segment_all(bv2, check, i)
		__free_page(bv2->bv_page);
out_put:
	bio_put(check);
}

#endif

#ifdef CONFIG_DEBUG_FS

/* XXX: cache set refcounting */

struct dump_iter {
	struct bpos		from;
	struct cache_set	*c;
	enum btree_id		id;

	char			buf[PAGE_SIZE];
	size_t			bytes;	/* what's currently in buf */

	char __user		*ubuf;	/* destination user buffer */
	size_t			size;	/* size of requested read */
	ssize_t			ret;	/* bytes read so far */
};

static int flush_buf(struct dump_iter *i)
{
	if (i->bytes) {
		size_t bytes = min(i->bytes, i->size);

		int err = copy_to_user(i->ubuf, i->buf, bytes);
		if (err)
			return err;

		i->ret	 += bytes;
		i->ubuf	 += bytes;
		i->size	 -= bytes;
		i->bytes -= bytes;
		memmove(i->buf, i->buf + bytes, i->bytes);
	}

	return 0;
}

static int bch_dump_open(struct inode *inode, struct file *file)
{
	struct btree_debug *bd = inode->i_private;
	struct dump_iter *i;

	i = kzalloc(sizeof(struct dump_iter), GFP_KERNEL);
	if (!i)
		return -ENOMEM;

	file->private_data = i;
	i->from = POS_MIN;
	i->c	= container_of(bd, struct cache_set, btree_debug[bd->id]);
	i->id	= bd->id;

	return 0;
}

static int bch_dump_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static ssize_t bch_read_btree(struct file *file, char __user *buf,
			      size_t size, loff_t *ppos)
{
	struct dump_iter *i = file->private_data;
	struct btree_iter iter;
	struct bkey_s_c k;
	int err;

	i->ubuf = buf;
	i->size	= size;
	i->ret	= 0;

	err = flush_buf(i);
	if (err)
		return err;

	if (!i->size)
		return i->ret;

	bch_btree_iter_init(&iter, i->c, i->id, i->from);

	while ((k = bch_btree_iter_peek(&iter)).k) {
		bch_bkey_val_to_text(iter.nodes[0], i->buf, sizeof(i->buf), k);
		i->bytes = strlen(i->buf);
		BUG_ON(i->bytes >= PAGE_SIZE);
		i->buf[i->bytes] = '\n';
		i->bytes++;

		bch_btree_iter_advance_pos(&iter);
		i->from = iter.pos;

		err = flush_buf(i);
		if (err)
			break;

		if (!i->size)
			break;
	}
	bch_btree_iter_unlock(&iter);

	return err < 0 ? err : i->ret;
}

static const struct file_operations btree_debug_ops = {
	.owner		= THIS_MODULE,
	.open		= bch_dump_open,
	.release	= bch_dump_release,
	.read		= bch_read_btree,
};

static ssize_t bch_read_btree_formats(struct file *file, char __user *buf,
				      size_t size, loff_t *ppos)
{
	struct dump_iter *i = file->private_data;
	struct btree_iter iter;
	struct btree *b;
	int err;

	i->ubuf = buf;
	i->size	= size;
	i->ret	= 0;

	err = flush_buf(i);
	if (err)
		return err;

	if (!i->size || !bkey_cmp(POS_MAX, i->from))
		return i->ret;

	for_each_btree_node(&iter, i->c, i->id, b, i->from) {
		const struct bkey_format *f = &b->keys.format;
		struct bset_stats stats = { 0 };

		bch_btree_keys_stats(&b->keys, &stats);

		i->bytes = scnprintf(i->buf, sizeof(i->buf),
				     "l %u %llu:%llu - %llu:%llu:\n"
				     "\tformat: u64s %u fields %u %u %u %u %u\n"
				     "\tpacked %u unpacked %u u64s %u\n"
				     "\tfloats %zu failed %zu\n",
				     b->level,
				     b->data->min_key.inode,
				     b->data->min_key.offset,
				     b->data->max_key.inode,
				     b->data->max_key.offset,
				     f->key_u64s,
				     f->bits_per_field[0],
				     f->bits_per_field[1],
				     f->bits_per_field[2],
				     f->bits_per_field[3],
				     f->bits_per_field[4],
				     b->keys.nr_packed_keys,
				     b->keys.nr_unpacked_keys,
				     b->keys.nr_live_u64s,
				     stats.floats,
				     stats.failed);

		err = flush_buf(i);
		if (err)
			break;

		/*
		 * can't easily correctly restart a btree node traversal across
		 * all nodes, meh
		 */
		i->from = bkey_cmp(POS_MAX, b->key.k.p)
			? bkey_successor(b->key.k.p)
			: b->key.k.p;

		if (!i->size)
			break;
	}
	bch_btree_iter_unlock(&iter);

	return err < 0 ? err : i->ret;
}

static const struct file_operations btree_format_debug_ops = {
	.owner		= THIS_MODULE,
	.open		= bch_dump_open,
	.release	= bch_dump_release,
	.read		= bch_read_btree_formats,
};

void bch_debug_exit_cache_set(struct cache_set *c)
{
	if (!IS_ERR_OR_NULL(c->debug))
		debugfs_remove(c->debug);
}

void bch_debug_init_cache_set(struct cache_set *c)
{
	struct btree_debug *bd;
	char name[50];

	if (IS_ERR_OR_NULL(bch_debug))
		return;

	snprintf(name, sizeof(name), "%pU", c->sb.set_uuid.b);
	c->debug = debugfs_create_dir(name, bch_debug);
	if (IS_ERR_OR_NULL(c->debug))
		return;

	for (bd = c->btree_debug;
	     bd < c->btree_debug + ARRAY_SIZE(c->btree_debug);
	     bd++) {
		bd->id = bd - c->btree_debug;
		bd->btree = debugfs_create_file(bch_btree_id_names[bd->id],
						0400, c->debug, bd,
						&btree_debug_ops);

		snprintf(name, sizeof(name), "%s-formats",
			 bch_btree_id_names[bd->id]);

		bd->btree_format = debugfs_create_file(name, 0400, c->debug, bd,
						       &btree_format_debug_ops);
	}
}

#endif

void bch_debug_exit(void)
{
	if (!IS_ERR_OR_NULL(bch_debug))
		debugfs_remove_recursive(bch_debug);
}

int __init bch_debug_init(void)
{
	int ret = 0;

	bch_debug = debugfs_create_dir("bcache", NULL);
	return ret;
}
