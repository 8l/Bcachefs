
#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "request.h"

#include <linux/console.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/seq_file.h>

static struct dentry *debug;

/* Various debug code */

const char *ptr_status(struct cache_set *c, const struct bkey *k)
{
	for (unsigned i = 0; i < KEY_PTRS(k); i++)
		if (ptr_available(c, k, i)) {
			struct cache *ca = PTR_CACHE(c, k, i);
			size_t bucket = PTR_BUCKET_NR(c, k, i);
			size_t r = bucket_remainder(c, PTR_OFFSET(k, i));

			if (KEY_SIZE(k) + r > c->sb.bucket_size)
				return "bad, length too big";
			if (bucket <  ca->sb.first_bucket)
				return "bad, short offset";
			if (bucket >= ca->sb.nbuckets)
				return "bad, offset past end of device";
			if (ptr_stale(c, k, i))
				return "stale";
		}

	if (!bkey_cmp(k, &ZERO_KEY))
		return "bad, null key";
	if (!KEY_PTRS(k))
		return "bad, no pointers";
	if (!KEY_SIZE(k))
		return "zeroed key";
	return "";
}

static bool skipped_backwards(struct btree *b, struct bkey *k)
{
	return bkey_cmp(k, (!b->level) ? &START_KEY(next(k)) : next(k)) > 0;
}

static void dump_bset(struct btree *b, struct bset *i)
{
	for (struct bkey *k = i->start; k < end(i); k = next(k)) {
		printk(KERN_ERR "block %zu key %zu/%i: %s", index(i, b),
		       (uint64_t *) k - i->d, i->keys, pkey(k));

		for (unsigned j = 0; j < KEY_PTRS(k); j++) {
			size_t n = PTR_BUCKET_NR(b->c, k, j);
			printk(" bucket %zu", n);

			if (n >= b->c->sb.first_bucket && n < b->c->sb.nbuckets)
				printk(" prio %i",
				       PTR_BUCKET(b->c, k, j)->prio);
		}

		printk(" %s\n", ptr_status(b->c, k));

		if (next(k) < end(i) &&
		    skipped_backwards(b, k))
			printk(KERN_ERR "Key skipped backwards\n");
	}
}

static void vdump_bucket_and_panic(struct btree *b, const char *m, va_list args)
{
	struct bset *i;

	console_lock();

	for_each_sorted_set(b, i)
		dump_bset(b, i);

	vprintk(m, args);

	console_unlock();

	panic("at %s\n", pbtree(b));
}

static void dump_bucket_and_panic(struct btree *b, const char *m, ...)
{
	va_list args;
	va_start(args, m);
	vdump_bucket_and_panic(b, m, args);
	va_end(args);
}

static void __maybe_unused
dump_key_and_panic(struct btree *b, struct bset *i, int j)
{
	long bucket = PTR_BUCKET_NR(b->c, node(i, j), 0);
	long r = PTR_OFFSET(node(i, j), 0) & ~(~0 << b->c->bucket_bits);

	printk(KERN_ERR "level %i block %zu key %i/%i: %s "
	       "bucket %llu offset %li into bucket\n",
	       b->level, index(i, b), j, i->keys, pkey(node(i, j)),
	       (uint64_t) bucket, r);
	dump_bucket_and_panic(b, "");
}

struct keyprint_hack bcache_pkey(const struct bkey *k)
{
	unsigned i = 0;
	struct keyprint_hack r;
	char *out = r.s, *end = r.s + KEYHACK_SIZE;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("%llu:%llu len %llu -> [", KEY_DEV(k), k->key, KEY_SIZE(k));

	if (KEY_PTRS(k))
		while (1) {
			p("%llu:%llu gen %llu",
			  PTR_DEV(k, i), PTR_OFFSET(k, i), PTR_GEN(k, i));

			if (++i == KEY_PTRS(k))
				break;

			p(", ");
		}

	p("]");

	if (KEY_DIRTY(k))
		p(" dirty");
	if (KEY_CSUM(k))
		p(" cs%llu %llx", KEY_CSUM(k), k->ptr[1]);
#undef p
	return r;
}

struct keyprint_hack bcache_pbtree(const struct btree *b)
{
	struct keyprint_hack r;

	snprintf(r.s, 40, "%li level %i/%i", PTR_BUCKET_NR(b->c, &b->key, 0),
		 b->level, b->c->root ? b->c->root->level : -1);
	return r;
}

#ifdef CONFIG_BCACHE_DEBUG

void btree_verify(struct btree *b, struct bset *new)
{
	struct btree *v = b->c->verify_data;
	struct closure cl;
	closure_init_stack(&cl);

	if (!b->c->verify)
		return;

	closure_wait_event(&b->io.wait, &cl,
			   atomic_read(&b->io.cl.remaining) == -1);

	mutex_lock(&b->c->verify_lock);

	bkey_copy(&v->key, &b->key);
	v->written = 0;
	v->level = b->level;

	btree_read(v);
	closure_wait_event(&v->io.wait, &cl,
			   atomic_read(&b->io.cl.remaining) == -1);

	if (new->keys != v->sets[0].data->keys ||
	    memcmp(new->start,
		   v->sets[0].data->start,
		   (void *) end(new) - (void *) new->start)) {
		struct bset *i;
		unsigned j;

		console_lock();

		printk(KERN_ERR "*** original memory node:\n");
		for_each_sorted_set(b, i)
			dump_bset(b, i);

		printk(KERN_ERR "*** sorted memory node:\n");
		dump_bset(b, new);

		printk(KERN_ERR "*** on disk node:\n");
		dump_bset(v, v->sets[0].data);

		for (j = 0; j < new->keys; j++)
			if (new->d[j] != v->sets[0].data->d[j])
				break;

		console_unlock();
		panic("verify failed at %u\n", j);
	}

	mutex_unlock(&b->c->verify_lock);
}

static void data_verify_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

void data_verify(struct search *s)
{
	char name[BDEVNAME_SIZE];
	struct cached_dev *dc = container_of(s->op.d, struct cached_dev, disk);
	struct closure *cl = &s->cl;
	struct bio *check;
	struct bio_vec *bv;
	int i;

	if (!s->unaligned_bvec)
		bio_for_each_segment(bv, s->orig_bio, i)
			bv->bv_offset = 0, bv->bv_len = PAGE_SIZE;

	check = bio_clone(s->orig_bio, GFP_NOIO);
	if (!check)
		return;

	if (bio_alloc_pages(check, GFP_NOIO))
		goto out_put;

	check->bi_rw		= READ_SYNC;
	check->bi_private	= cl;
	check->bi_end_io	= data_verify_endio;

	closure_bio_submit(check, cl, s->op.d->c->bio_split);
	closure_sync(cl);

	bio_for_each_segment(bv, s->orig_bio, i) {
		void *p1 = kmap(bv->bv_page);
		void *p2 = kmap(check->bi_io_vec[i].bv_page);

		if (memcmp(p1 + bv->bv_offset,
			   p2 + bv->bv_offset,
			   bv->bv_len))
			printk(KERN_ERR "bcache (%s): verify failed"
			       " at sector %llu\n",
			       bdevname(dc->bdev, name),
			       (uint64_t) s->orig_bio->bi_sector);

		kunmap(bv->bv_page);
		kunmap(check->bi_io_vec[i].bv_page);
	}

	__bio_for_each_segment(bv, check, i, 0)
		__free_page(bv->bv_page);
out_put:
	bio_put(check);
}

#endif

#ifdef CONFIG_BCACHE_EDEBUG

unsigned count_data(struct btree *b)
{
	unsigned ret = 0;
	struct bkey *k;

	if (!b->level)
		for_each_key(b, k)
			ret += KEY_SIZE(k);
	return ret;
}

void check_key_order_msg(struct btree *b, struct bset *i, const char *m, ...)
{
	if (!i->keys)
		return;

	for (struct bkey *k = i->start; next(k) < end(i); k = next(k))
		if (skipped_backwards(b, k)) {
			va_list args;
			va_start(args, m);

			vdump_bucket_and_panic(b, m, args);
			va_end(args);
		}
}

void check_keys(struct btree *b, const char *m, ...)
{
	va_list args;
	struct bkey *k, *p;
	struct btree_iter iter;

	if (b->level)
		return;

	btree_iter_init(b, &iter, NULL);

	do
		p = btree_iter_next(&iter);
	while (p && ptr_invalid(b, p));

	while ((k = btree_iter_next(&iter))) {
		if (bkey_cmp(&START_KEY(p), &START_KEY(k)) > 0) {
			printk(KERN_ERR "Keys out of order:\n");
			goto bug;
		}

		if (ptr_invalid(b, k))
			continue;

		if (bkey_cmp(p, &START_KEY(k)) > 0) {
			printk(KERN_ERR "Overlapping keys:\n");
			goto bug;
		}
		p = k;
	}
	return;
bug:
	va_start(args, m);
	vdump_bucket_and_panic(b, m, args);
	va_end(args);
}

#endif

#ifdef CONFIG_DEBUG_FS

static int btree_dump(struct btree *b, struct btree_op *op, struct seq_file *f,
		      const char *tabs, uint64_t *prev, uint64_t *sectors)
{
	struct bkey *k;
	char buf[30];
	uint64_t last, biggest = 0;

	for_each_key(b, k) {
		int j = (uint64_t *) k - _t->data->d;
		if (!j)
			last = *prev;

		if (last > k->key)
			seq_printf(f, "Key skipped backwards\n");

		if (!b->level && j &&
		    last != KEY_START(k))
			seq_printf(f, "<hole>\n");
		else if (b->level && !ptr_bad(b, k))
			btree(dump, k, b, op, f, tabs - 1, &last, sectors);

		seq_printf(f, "%s%zi %4i: %s %s\n",
			   tabs, _t - b->sets, j, pkey(k), buf);

		if (!b->level && !buf[0])
			*sectors += KEY_SIZE(k);

		last = k->key;
		biggest = max(biggest, last);
	}
	*prev = biggest;

	return 0;
}

static int debug_seq_show(struct seq_file *f, void *data)
{
	static const char *tabs = "\t\t\t\t\t";
	uint64_t last = 0, sectors = 0;
	struct cache *ca = f->private;
	struct cache_set *c = ca->set;

	struct btree_op op;
	btree_op_init_stack(&op);

	btree_root(dump, c, &op, f, &tabs[4], &last, &sectors);

	seq_printf(f, "%s\n" "%llu Mb found\n",
		   pkey(&c->root->key), sectors / 2048);

	closure_sync(&op.cl);
	return 0;
}

static int debug_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, debug_seq_show, inode->i_private);
}

static const struct file_operations cache_debug_ops = {
	.owner		= THIS_MODULE,
	.open		= debug_seq_open,
	.read		= seq_read,
	.release	= single_release
};

void bcache_debug_init_cache(struct cache *c)
{
	if (!IS_ERR_OR_NULL(debug)) {
		char b[BDEVNAME_SIZE];
		bdevname(c->bdev, b);

		c->debug = debugfs_create_file(b, 0400, debug, c,
					       &cache_debug_ops);
	}
}

#endif

#ifdef CONFIG_BCACHE_DEBUG
static ssize_t btree_fuzz(struct kobject *k, struct kobj_attribute *a,
		      const char *buffer, size_t size)
{
	void dump(struct btree *b)
	{
		for (struct bset *i = b->sets[0].data;
		     index(i, b) < btree_blocks(b) &&
		     i->seq == b->sets[0].data->seq;
		     i = ((void *) i) + set_blocks(i, b->c) * block_bytes(b->c))
			dump_bset(b, i);
	}

	struct cache_sb *sb;
	struct cache_set *c;
	struct btree *all[3], *b, *fill, *orig;

	struct btree_op op;
	btree_op_init_stack(&op);

	sb = kzalloc(sizeof(struct cache_sb), GFP_KERNEL);
	if (!sb)
		return -ENOMEM;

	sb->bucket_size = 128;
	sb->block_size = 4;

	c = cache_set_alloc(sb);
	if (!c)
		return -ENOMEM;

	for (int i = 0; i < 3; i++) {
		BUG_ON(list_empty(&c->btree_cache));
		all[i] = list_first_entry(&c->btree_cache, struct btree, list);
		list_del_init(&all[i]->list);

		all[i]->key = KEY(0, 0, c->sb.bucket_size);
		bkey_copy_key(&all[i]->key, &MAX_KEY);
	}

	b = all[0];
	fill = all[1];
	orig = all[2];

	while (1) {
		for (int i = 0; i < 3; i++)
			all[i]->written = all[i]->nsets = 0;

		bset_init_next(b);

		while (1) {
			struct bset *i = write_block(b);
			struct bkey *k = op.keys.top;

			k->key = get_random_int();

			op.insert_type = k->key & 1
				? INSERT_WRITE
				: INSERT_READ;
			k->key >>= 1;

			k->header = KEY_HEADER(bucket_remainder(c, k->key), 0);
			k->key >>= c->bucket_bits;
			k->key &= 1024 * 512 - 1;
			k->key += c->sb.bucket_size;
#if 0
			SET_KEY_PTRS(k, 1);
#endif
			keylist_push(&op.keys);
			bcache_btree_insert_keys(b, &op);

			if (should_split(b) ||
			    set_blocks(i, b->c) !=
			    __set_blocks(i, i->keys + 15, b->c)) {
				i->csum = csum_set(i);

				memcpy(write_block(fill),
				       i, set_bytes(i));

				b->written += set_blocks(i, b->c);
				fill->written = b->written;
				if (b->written == btree_blocks(b))
					break;

				btree_sort_lazy(b);
				bset_init_next(b);
			}
		}

		memcpy(orig->sets[0].data,
		       fill->sets[0].data,
		       btree_bytes(c));

		btree_sort(b);
		fill->written = 0;
		btree_read_done(&fill->io.cl);

		if (b->sets[0].data->keys != fill->sets[0].data->keys ||
		    memcmp(b->sets[0].data->start,
			   fill->sets[0].data->start,
			   b->sets[0].data->keys * sizeof(uint64_t))) {
			struct bset *i = b->sets[0].data;

			for (struct bkey *k = i->start,
			     *j = fill->sets[0].data->start;
			     k < end(i);
			     k = next(k), j = next(j))
				if (bkey_cmp(k, j) ||
				    KEY_SIZE(k) != KEY_SIZE(j))
					printk(KERN_ERR "key %zi differs: %s "
					       "!= %s\n", (uint64_t *) k - i->d,
					       pkey(k), pkey(j));

			for (int i = 0; i < 3; i++) {
				printk(KERN_ERR "**** Set %i ****\n", i);
				dump(all[i]);
			}
			panic("\n");
		}

		printk(KERN_DEBUG "bcache: fuzz complete: %i keys\n",
		       b->sets[0].data->keys);
	}
}

kobj_attribute_write(fuzz, btree_fuzz);
#endif

#ifdef CONFIG_BCACHE_LATENCY_DEBUG
static ssize_t show(struct kobject *k, struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%i\n", latency_warn_ms);
}

static ssize_t store(struct kobject *k, struct kobj_attribute *attr,
		     const char *buffer, size_t size)
{
	return strtoul_safe(buffer, latency_warn_ms) ?: (ssize_t) size;
}

kobj_attribute_rw(latency_warn_ms, show, store);
#endif

void bcache_debug_exit(void)
{
	if (!IS_ERR_OR_NULL(debug))
		debugfs_remove_recursive(debug);
}

int __init bcache_debug_init(struct kobject *kobj)
{
	int ret = 0;
#ifdef CONFIG_BCACHE_DEBUG
	ret = sysfs_create_file(kobj, &ksysfs_fuzz.attr);
	if (ret)
		return ret;
#endif

#ifdef CONFIG_BCACHE_LATENCY_DEBUG
	ret = sysfs_create_file(kobj, &ksysfs_latency_warn_ms.attr);
	if (ret)
		return ret;
#endif

	debug = debugfs_create_dir("bcache", NULL);
	return ret;
}
