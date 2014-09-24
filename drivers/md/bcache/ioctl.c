
#include "bcache.h"
#include "btree.h"
#include "extents.h"
#include "inode.h"
#include "request.h"

#include <linux/aio.h>
#include <linux/bcache-ioctl.h>
#include <linux/bio.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/hash.h>
#include <linux/idr.h>
#include <linux/ioctl.h>

static struct class *bch_extent_class;
static int bch_extent_major;
DEFINE_IDR(bch_cache_set_minor);

/* read ioctl */

static void bch_cache_read_endio(struct bio *bio, int error)
{
	struct kiocb *req = bio->bi_private;
	atomic_t *ref = (atomic_t *) &req->ki_nbytes;
	struct bio_vec *bv;
	int i;

	if (error)
		req->ki_pos = error;

	if (atomic_dec_and_test(ref))
		aio_complete(req, req->ki_pos, 0);

	bio_for_each_segment_all(bv, bio, i)
		page_cache_release(bv->bv_page);
	bio_put(bio);
}

static void bch_ioctl_read(struct kiocb *req, struct cache_set *c,
			   unsigned long arg)
{
	atomic_t *ref = (atomic_t *) &req->ki_nbytes;
	struct bch_ioctl_read i, __user *user_read = (void __user *) arg;
	struct bio *bio;
	size_t bytes, pages;
	ssize_t ret = 0;

	if (copy_from_user(&i, user_read, sizeof(i))) {
		aio_complete(req, -EFAULT, 0);
		return;
	}

	/*
	 * Hack: may need multiple bios, so I'm using spare fields in the kiocb
	 * for refcount/return code
	 */
	atomic_set(ref, 1);
	req->ki_pos = 0;

	while (i.sectors && !ret) {
		bytes = i.sectors << 9;
		pages = min_t(size_t, BIO_MAX_PAGES,
			      DIV_ROUND_UP(bytes, PAGE_SIZE));

		bio = bio_alloc(GFP_NOIO, pages);
		bio->bi_iter.bi_sector	= i.offset;
		bio->bi_end_io		= bch_cache_read_endio;
		bio->bi_private		= req;
		atomic_inc(ref);

		ret = bio_get_user_pages(bio, i.buf, bytes, 1);
		if (ret < 0) {
			bio_endio(bio, ret);
			break;
		}

		i.offset += bio_sectors(bio);
		i.buf += bio_sectors(bio) << 9;
		i.sectors -= bio_sectors(bio);

		ret = bch_read(c, bio, i.inode);
		bio_endio(bio, ret);
	}

	if (atomic_dec_and_test(ref))
		aio_complete(req, req->ki_pos, 0);
}

struct bch_ioctl_write_op {
	struct closure		cl;
	struct kiocb		*req;
	struct bch_write_op	iop;
	struct bbio		bio;
};

/* write ioctl */

static void bch_ioctl_write_done(struct closure *cl)
{
	struct bch_ioctl_write_op *op = container_of(cl,
					struct bch_ioctl_write_op, cl);
	atomic_t *ref = (atomic_t *) &op->req->ki_nbytes;
	struct bio_vec *bv;
	int i;

	if (op->iop.error)
		op->req->ki_pos = op->iop.error;

	if (atomic_dec_and_test(ref))
		aio_complete(op->req, op->req->ki_pos, 0);

	bio_for_each_segment_all(bv, &op->bio.bio, i)
		page_cache_release(bv->bv_page);
	kfree(op);
}

static void bch_ioctl_write(struct kiocb *req, struct cache_set *c,
			    unsigned long arg)
{
	atomic_t *ref = (atomic_t *) &req->ki_nbytes;
	struct bch_ioctl_write __user *user_write = (void __user *) arg;
	struct bch_ioctl_write i;
	struct bch_ioctl_write_op *op;
	struct bio *bio;
	size_t bytes, pages;
	ssize_t ret;

	if (copy_from_user(&i, user_write, sizeof(i))) {
		aio_complete(req, -EFAULT, 0);
		return;
	}

	bch_set_extent_ptrs(&i.extent, 0);
	SET_KEY_DELETED(&i.extent, 0);
	SET_KEY_CSUM(&i.extent, 0);

	/*
	 * Hack: may need multiple bios, so I'm using spare fields in the kiocb
	 * for refcount/return code
	 */
	atomic_set(ref, 1);
	req->ki_pos = 0;

	while (KEY_SIZE(&i.extent)) {
		bytes = KEY_SIZE(&i.extent) << 9;
		pages = DIV_ROUND_UP(bytes, PAGE_SIZE);

		op = kmalloc(sizeof(*op) + sizeof(struct bio_vec) * pages,
			     GFP_NOIO);
		if (!op) {
			aio_complete(req, -ENOMEM, 0);
			return;
		}

		closure_init(&op->cl, NULL);
		op->req = req;
		atomic_inc(ref);

		bio = &op->bio.bio;
		bio_init(bio);
		bio->bi_iter.bi_sector	= KEY_START(&i.extent);
		bio->bi_max_vecs	= pages;
		bio->bi_io_vec		= bio->bi_inline_vecs;

		bch_write_op_init(&op->iop, c, bio, NULL,
				  true, false, false,
				  &i.extent, NULL);

		ret = bio_get_user_pages(bio, i.buf,
					 KEY_SIZE(&i.extent) << 9, 0);
		if (ret < 0) {
			op->iop.error = ret;
			closure_return_with_destructor_noreturn(&op->cl,
						bch_ioctl_write_done);
			break;
		}

		SET_KEY_SIZE(&i.extent,
			     KEY_SIZE(&i.extent) - bio_sectors(bio));
		i.buf += bio_sectors(bio) << 9;

		closure_call(&op->iop.cl, bch_write, NULL, &op->cl);
		closure_return_with_destructor_noreturn(&op->cl,
							bch_ioctl_write_done);
	}

	if (atomic_dec_and_test(ref))
		aio_complete(req, req->ki_pos, 0);
}

/* list_keys ioctl */

struct bch_ioctl_list_keys_op {
	struct bch_ioctl_list_keys	i;
	struct btree_op			op;

	BKEY_PADDED(prev_key);
};

static int bch_ioctl_list_keys_fn(struct btree_op *b_op, struct btree *b,
				  struct bkey *k)
{
	struct bch_ioctl_list_keys_op *op = container_of(b_op,
				struct bch_ioctl_list_keys_op, op);
	BKEY_PADDED(k) tmp;

	if (bkey_cmp(&START_KEY(k), &op->i.end) >= 0)
		return MAP_DONE;

	if (!(op->i.flags & BCH_IOCTL_LIST_VALUES)) {
		tmp.k = *k;
		k = &tmp.k;
		bch_set_val_u64s(k, 0);
	}

	if (b->keys.ops->is_extents) {
		if (k != &tmp.k) {
			bkey_copy(&tmp.k, k);
			k = &tmp.k;
		}

		if (bkey_cmp(&op->i.start, &START_KEY(k)) > 0)
			bch_cut_front(&op->i.start, k);

		if (bkey_cmp(&op->i.end, k) <= 0)
			bch_cut_back(&op->i.end, k);

		if (!KEY_SIZE(k))
			return MAP_CONTINUE;

		if (op->i.keys_found &&
		    bch_bkey_try_merge(&b->keys, &op->prev_key, k)) {
			op->i.keys_found -= KEY_U64s(&op->prev_key);
			k = &op->prev_key;
		} else {
			bkey_copy(&op->prev_key, k);
		}
	}

	if (op->i.keys_found + KEY_U64s(k) >
	    op->i.buf_size / sizeof(u64))
		return -ENOSPC;

	if (copy_to_user((u64 __user *) op->i.buf + op->i.keys_found,
			 k, bkey_bytes(k)))
		return -EFAULT;

	op->i.keys_found += KEY_U64s(k);
	return MAP_CONTINUE;
}

static int __bch_list_keys(struct cache_set *c,
			   struct bch_ioctl_list_keys_op *op)
{
	int ret;

	if (op->i.btree_id != BTREE_ID_EXTENTS &&
	    op->i.btree_id != BTREE_ID_INODES)
		return -EINVAL;

	bch_btree_op_init(&op->op, op->i.btree_id, -1);
	ret = bch_btree_map_keys(&op->op, c, &op->i.start,
				 bch_ioctl_list_keys_fn, 0);

	return ret < 0 ? ret : 0;
}

int bch_list_keys(struct cache_set *c, unsigned btree_id,
		  struct bkey *start, struct bkey *end,
		  struct bkey *buf, size_t buf_size,
		  unsigned flags, unsigned *keys_found)
{
	struct bch_ioctl_list_keys_op op;
	mm_segment_t fs;
	int ret;

	fs = get_fs();
	set_fs(KERNEL_DS);

	memset(&op, 0, sizeof(op));

	op.i.btree_id	= btree_id;
	op.i.flags	= flags;
	op.i.start	= *start;
	op.i.end	= *end;
	op.i.buf	= (unsigned long) buf;
	op.i.buf_size	= buf_size;

	ret = __bch_list_keys(c, &op);
	*keys_found = op.i.keys_found;

	set_fs(fs);

	return ret;
}
EXPORT_SYMBOL(bch_list_keys);

static long bch_ioctl_list_keys(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_list_keys __user *user_i = (void __user *) arg;
	struct bch_ioctl_list_keys_op op;
	int ret;

	memset(&op, 0, sizeof(op));

	if (copy_from_user(&op.i, user_i, sizeof(op.i)))
		return -EFAULT;

	op.i.keys_found = 0;

	ret = __bch_list_keys(c, &op);
	if (put_user(op.i.keys_found, &user_i->keys_found))
		return -EFAULT;

	return ret;
}

/* Inodes */

static long bch_ioctl_inode_update(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_inode_update __user *user_i =
		(void __user *) arg;
	struct bch_ioctl_inode_update i;

	if (copy_from_user(&i, user_i, sizeof(i)))
		return -EFAULT;

	if (bch_inode_invalid(&i.inode.i_inode.i_key)) {
		char status[80];

		bch_inode_status(status, sizeof(status), &i.inode.i_inode.i_key);
		pr_err("invalid inode: %s", status);
		return -EINVAL;
	}

	bch_inode_update(c, &i.inode.i_inode);
	return 0;
}

static long bch_ioctl_inode_create(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_inode_create __user *user_i =
		(void __user *) arg;
	struct bch_ioctl_inode_create i;
	int ret;

	if (copy_from_user(&i, user_i, sizeof(i)))
		return -EFAULT;

	ret = bch_inode_create(c, &i.inode.i_inode, 0, BLOCKDEV_INODE_MAX,
			       &c->unused_inode_hint);
	if (ret)
		return ret;

	if (copy_to_user(&user_i->inode, &i.inode, sizeof(i.inode))) {
		bch_inode_rm(c, KEY_INODE(&i.inode.i_inode.i_key));
		return -EFAULT;
	}

	return 0;
}

struct inode_delete_work {
	struct work_struct	work;
	struct kiocb		*req;
	struct cache_set	*c;
	u64			inum;
};

static void bch_ioctl_inode_delete_work(struct work_struct *work)
{
	struct inode_delete_work *w =
		container_of(work, struct inode_delete_work, work);

	bch_inode_rm(w->c, w->inum);
	aio_complete(w->req, 0, 0);
	kfree(w);
}

/* XXX: doesn't return errors */
static void bch_ioctl_inode_delete(struct kiocb *req, struct cache_set *c,
				   unsigned long arg)
{
	struct bch_ioctl_inode_delete __user *user_i =
		(void __user *) arg;
	struct bch_ioctl_inode_delete i;
	struct inode_delete_work *w;

	if (copy_from_user(&i, user_i, sizeof(i))) {
		aio_complete(req, -EFAULT, 0);
		return;
	}

	w = kzalloc(sizeof(*w), GFP_NOIO);
	if (!w) {
		aio_complete(req, -ENOMEM, 0);
		return;
	}

	INIT_WORK(&w->work, bch_ioctl_inode_delete_work);
	w->req = req;
	w->c = c;
	w->inum = i.inum;
	queue_work(system_long_wq, &w->work);
}

static long bch_ioctl_blockdev_find_by_uuid(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_blockdev_find_by_uuid __user *user_i =
		(void __user *) arg;
	uuid_le uuid;
	struct bch_inode_blockdev inode;

	if (copy_from_user(&uuid, user_i->uuid, sizeof(user_i->uuid)))
		return -EFAULT;

	if (bch_blockdev_inode_find_by_uuid(c, &uuid, &inode))
		return -ENOENT;

	if (copy_to_user(&user_i->inode, &inode, sizeof(inode)))
		return -EFAULT;

	return 0;
}

static long bch_query_uuid(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_query_uuid __user *user_i = (void __user *) arg;

	if (copy_to_user(&user_i->uuid,
			 &c->sb.set_uuid,
			 sizeof(user_i->uuid)))
		return -EFAULT;

	return 0;
}

/* copy ioctl */

struct bch_copy_op {
	struct btree_op		op;
	struct keylist		keys;

	struct bkey		src_loc;
	struct bkey		src_end;
	u64			dst_inode;
	u64			dst_shift;
};

static int bch_copy_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct bch_copy_op *op = container_of(b_op, struct bch_copy_op, op);
	struct bkey *copy;

	/* XXX: on hole, make this delete stuff in destination */

	BUG_ON(bkey_cmp(k, &op->src_loc) <= 0);

	if (bkey_cmp(&START_KEY(k), &op->src_end) >= 0) {
		op->src_loc = *k;
		return MAP_DONE;
	}

	/* If memory alloc fails, just insert what we've slurped up so far */
	if (bch_keylist_realloc(&op->keys, KEY_U64s(k)))
		return MAP_DONE;

	/* cut pointers to size */
	copy = op->keys.top;
	bkey_copy(copy, k);
	bch_cut_front(&op->src_loc, copy);
	bch_cut_back(&op->src_end, copy);

	/* modify copy to reference destination */
	SET_KEY_INODE(copy, op->dst_inode);
	SET_KEY_OFFSET(copy, KEY_OFFSET(copy) + op->dst_shift);

	bch_keylist_push(&op->keys);
	op->src_loc = *k;

	return MAP_CONTINUE;
}

/* bch_copy - copy a range of size @sectors beginning @src_begin
 *	      to a destination beginning @dst_begin.
 * @c		cache set
 * @src_start	pointer to start location the copy source
 * @dst_start	pointer to start location of the copy destination
 *		NOTE: both starts begin at KEY_START(begin)
 * @sectors	how many sectors to copy
 *
 * Returns:
 *	 0 on success
 *	<0 on error
 *
 * XXX: this needs to be moved to generic io code
 */
int bch_copy(struct cache_set *c, struct bkey *src_start, struct bkey *dst_start,
	     unsigned long sectors)
{
	struct bch_copy_op op;
	int ret = 0;

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, -1);
	bch_keylist_init(&op.keys);
	op.src_loc = START_KEY(src_start);
	op.src_end = KEY(KEY_INODE(src_start), KEY_START(src_start) + sectors, 0);
	op.dst_inode = KEY_INODE(dst_start);
	op.dst_shift = KEY_START(dst_start) - KEY_START(src_start);

	/* XXX: probably deserves input validation and errors here */

	/*
	 * We can't use just a single map call because keylists have a finite
	 * size, so we loop until the full range is covered. op->src_loc keeps
	 * track of our current location in the copy operation.
	 */
	while (bkey_cmp(&op.src_loc, &op.src_end) < 0) {
		ret = bch_btree_map_keys(&op.op, c, &op.src_loc, bch_copy_fn, 0);

		if (ret < 0)
			break;

		/*
		 * when MAP_CONTINUE is returned from bch_btree_map_keys, we know the
		 * map function was expecting more keys where there weren't any.
		 */
		if (ret == MAP_CONTINUE)
			op.src_loc = op.src_end;

		ret = bch_btree_insert(c, BTREE_ID_EXTENTS, &op.keys, NULL);
		if (ret < 0)
			break;

		BUG_ON(!bch_keylist_empty(&op.keys));
	}

	bch_keylist_free(&op.keys);

	if (ret < 0)
		return ret;

	return 0;
}

struct bch_ioctl_copy_op {
	struct work_struct	work;
	struct kiocb		*req;
	struct cache_set	*c;
	struct bch_ioctl_copy	i;
};

static void bch_ioctl_copy_work(struct work_struct *work)
{
	struct bch_ioctl_copy_op *op =
		container_of(work, struct bch_ioctl_copy_op, work);
	struct bkey src_start = KEY(op->i.src_inode, op->i.src_offset, 0);
	struct bkey dst_start = KEY(op->i.dst_inode, op->i.dst_offset, 0);

	int ret = bch_copy(op->c, &src_start, &dst_start, op->i.sectors);

	aio_complete(op->req, ret < 0 ? ret : 0, 0);
	kfree(op);
}

static void bch_ioctl_copy(struct kiocb *req, struct cache_set *c,
			   unsigned long arg)
{
	struct bch_ioctl_copy __user *user_i = (void __user *) arg;
	struct bch_ioctl_copy_op *op;

	op = kzalloc(sizeof(*op), GFP_NOIO);
	if (!op) {
		aio_complete(req, -ENOMEM, 0);
		return;
	}

	INIT_WORK(&op->work, bch_ioctl_copy_work);
	op->req = req;
	op->c = c;

	if (copy_from_user(&op->i, user_i, sizeof(op->i))) {
		aio_complete(req, -EFAULT, 0);
		kfree(op);
		return;
	}

	if (op->i.sectors + op->i.src_offset < op->i.sectors ||
	    op->i.sectors + op->i.dst_offset < op->i.sectors) {
		aio_complete(req, -EINVAL, 0);
		kfree(op);
		return;
	}

	queue_work(system_long_wq, &op->work);
}

/* discard ioctl */

struct bch_discard_op {
	struct btree_op	op;
	struct bkey *start_key;
	struct bkey *end_key;
};

static int bch_discard_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct bch_discard_op *op = container_of(b_op, struct bch_discard_op, op);
	struct bkey erase_key;
	int ret;

	BUG_ON(bkey_cmp(k, &START_KEY(op->start_key)) <= 0);

	/* TODO replace with extent overlap. maybe? */
	if (bkey_cmp(&START_KEY(k), op->end_key) >= 0)
		return MAP_DONE;

	/* create the biggest key we can, to minimize writes */
	erase_key = KEY(KEY_INODE(k), KEY_START(k) + KEY_SIZE_MAX, KEY_SIZE_MAX);
	bch_cut_front(&START_KEY(op->start_key), &erase_key);
	bch_cut_back(op->end_key, &erase_key);
	SET_KEY_DELETED(&erase_key, true);

	ret = bch_btree_insert_node(b, b_op, &keylist_single(&erase_key), NULL, NULL);

	return ret ?: MAP_CONTINUE;
}

/* bch_discard - discard a range of keys from start_key to end_key.
 * @c		cache set
 * @start_key	pointer to start location
 *		NOTE: discard starts at KEY_START(start_key)
 * @end_key	pointer to end location
 *		NOTE: discard ends at KEY_OFFSET(end_key)
 *
 * Returns:
 *	 0 on success
 *	<0 on error
 *
 * XXX: this needs to be refactored with inode_truncate, or more
 *	appropriately inode_truncate should call this
 */
int bch_discard(struct cache_set *c, struct bkey *start_key,
		struct bkey *end_key)
{
	struct bch_discard_op op;
	int ret;

	bch_btree_op_init(&op.op, BTREE_ID_EXTENTS, 0);
	op.start_key = start_key;
	op.end_key = end_key;

	ret = bch_btree_map_keys(&op.op, c, start_key, bch_discard_fn, 0);
	if (ret < 0)
		return ret;

	return 0;
}

struct bch_ioctl_discard_op {
	struct work_struct	work;
	struct kiocb		*req;
	struct cache_set	*c;
	u64			inum;
	u64			offset;
	u64			sectors;
};

static void bch_ioctl_discard_work(struct work_struct *work)
{
	struct bch_ioctl_discard_op *op =
		container_of(work, struct bch_ioctl_discard_op, work);
	struct bkey start_key = KEY(op->inum, op->offset, 0);
	struct bkey end_key = KEY(op->inum, op->offset + op->sectors, 0);

	int ret = bch_discard(op->c, &start_key, &end_key);

	aio_complete(op->req, ret, 0);
	kfree(op);
}

static void bch_ioctl_discard(struct kiocb *req, struct cache_set *c,
			      unsigned long arg)
{
	struct bch_ioctl_discard __user *user_i = (void __user *) arg;
	struct bch_ioctl_discard i;
	struct bch_ioctl_discard_op *op;

	if (copy_from_user(&i, user_i, sizeof(i))) {
		aio_complete(req, -EFAULT, 0);
		return;
	}

	op = kzalloc(sizeof(*op), GFP_NOIO);
	if (!op) {
		aio_complete(req, -ENOMEM, 0);
		return;
	}

	INIT_WORK(&op->work, bch_ioctl_discard_work);
	op->req = req;
	op->c = c;
	op->inum = i.inode;
	op->offset = i.offset;
	op->sectors = i.sectors;

	queue_work(system_long_wq, &op->work);
}

/* ioctl dispatch */

static long bch_aio_ioctl(struct kiocb *req, unsigned int cmd,
			  unsigned long arg)
{
	struct cache_set *c = req->ki_filp->private_data;

	switch (cmd) {
	case BCH_IOCTL_READ:
		bch_ioctl_read(req, c, arg);
		return -EIOCBQUEUED;
	case BCH_IOCTL_WRITE:
		bch_ioctl_write(req, c, arg);
		return -EIOCBQUEUED;
	case BCH_IOCTL_LIST_KEYS:
		return bch_ioctl_list_keys(c, arg);
	case BCH_IOCTL_INODE_UPDATE:
		return bch_ioctl_inode_update(c, arg);
	case BCH_IOCTL_INODE_CREATE:
		return bch_ioctl_inode_create(c, arg);
	case BCH_IOCTL_INODE_DELETE:
		bch_ioctl_inode_delete(req, c, arg);
		return -EIOCBQUEUED;
	case BCH_IOCTL_BLOCKDEV_FIND_BY_UUID:
		return bch_ioctl_blockdev_find_by_uuid(c, arg);
	case BCH_IOCTL_COPY:
		bch_ioctl_copy(req, c, arg);
		return -EIOCBQUEUED;
	case BCH_IOCTL_QUERY_UUID:
		return bch_query_uuid(c, arg);
	case BCH_IOCTL_DISCARD:
		bch_ioctl_discard(req, c, arg);
		return -EIOCBQUEUED;
	}

	return -ENOSYS;
}

static long bch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct kiocb req;
	long ret;

	init_sync_kiocb(&req, file);

	ret = bch_aio_ioctl(&req, cmd, arg);
	if (ret == -EIOCBQUEUED)
		ret = wait_on_sync_kiocb(&req);

	return ret;
}

/* Char device */

static int bch_extent_release(struct inode *inode, struct file *file)
{
	struct cache_set *c = file->private_data;
	bch_cache_set_close(c);
	return 0;
}

static int bch_extent_open(struct inode *inode, struct file *file)
{
	struct cache_set *c;

	c = bch_cache_set_open(iminor(inode));
	if (!c)
		return -ENXIO;

	file->private_data = c;
	return 0;
}

static struct file_operations bch_extent_store = {
	.owner		= THIS_MODULE,
	.aio_ioctl	= bch_aio_ioctl,
	.unlocked_ioctl = bch_ioctl,
	.open		= bch_extent_open,
	.release	= bch_extent_release,
};

int bch_extent_store_init_cache_set(struct cache_set *c)
{
	c->minor = idr_alloc(&bch_cache_set_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	pr_info("creating dev %u", c->minor);

	c->extent_device = device_create(
			bch_extent_class, NULL,
			MKDEV(bch_extent_major, c->minor), NULL,
			"bcache_extent%d", c->minor);
	if (IS_ERR(c->extent_device))
		return PTR_ERR(c->extent_device);
	return 0;
}

void bch_extent_store_exit_cache_set(struct cache_set *c)
{
	if (!IS_ERR_OR_NULL(c->extent_device))
		device_unregister(c->extent_device);
	if (c->minor >= 0)
		idr_remove(&bch_cache_set_minor, c->minor);
}

void bch_extent_store_exit(void)
{
	if (bch_extent_major)
		unregister_chrdev(bch_extent_major, "bcache_extent_store");
}

int bch_extent_store_init(void)
{
	bch_extent_major = register_chrdev(0, "bcache_extent_store",
					   &bch_extent_store);
	if (bch_extent_major < 0)
		return bch_extent_major;

	bch_extent_class = class_create(THIS_MODULE, "bcache_extent_store");
	if (IS_ERR(bch_extent_class)) {
		unregister_chrdev(bch_extent_major, "bcache_extent_store");
		return PTR_ERR(bch_extent_class);
	}

	return 0;
}
