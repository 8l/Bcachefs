/*
 * Quick and dirty write buffering, to reduce write latency when using a flash
 * device that doesn't have a write buffer.
 *
 * It doesn't yet support cache flushes, though that shouldn't be too hard to
 * add. Provided the underlying device doesn't reorder writes it shouldn't be
 * too a big deal though.
 *
 * We maintain a fixed sized buffer of pages in a fifo. We only buffer
 * individual pages; to enable write buffering we require that the block size of
 * the cache device be at least 4k.
 *
 * (This code does implicitly depend on PAGE_SIZE being 4k. Should fix that.)
 *
 * WRITES:
 *
 * As mentioned, we use a fifo for the buffer, and the struct
 * write_buffer_entries are in another matching fifo. If the buffer is full, we
 * just sleep (may change that to sticking the bio on a queue later).
 *
 * When there's room in the fifo, we allocate some space, clone the bio, and
 * copy the data into the buffer. Then we complete the original bio and submit
 * the clone. When the clone finishes, we mark its write_buffer_entries as done,
 * and pop entries marked as done off the tail of the fifo.
 *
 * READS:
 *
 * The struct write_buffer_entries are indexed in a hash table, by sector.
 *
 * When we get a read, we look up all the individiual pages in the bio in said
 * hash table.
 *
 * If we find all of them, we're done - complete the bio. If we find none of
 * them - we can just pass the bio through unchanged. If we only find some of
 * them, we still need to do the read but we also need the newer data in the
 * write buffer.
 *
 * So we clone the bio, and when our clone finishes we recheck the buffer,
 * overwriting the data we read with whatever (newer) data is currently in the
 * write buffer.
 */

#include "bcache.h"

#include <linux/hash.h>

struct write_buffer_entry {
	struct hlist_node	node;

	sector_t		sector;
	bool			done;
};

static void *entry_data(struct write_buffer *w, struct write_buffer_entry *e)
{
	unsigned offset = e - w->entries;

	return w->buffer + PAGE_SIZE * offset;
}

static struct hlist_head *entry_hash(struct write_buffer *w, sector_t sector)
{
	return &w->hash[hash_64(sector, w->buffer_bits)];
}

static struct write_buffer_entry *entry_find(struct write_buffer *w,
					     sector_t sector)
{
	struct write_buffer_entry *e;
	struct hlist_node *pos;

	hlist_for_each_entry(e, pos, entry_hash(w, sector), node)
		if (sector == e->sector)
			return e;

	return NULL;
}

struct write_buffer_bio {
	struct write_buffer	*w;
	unsigned		offset;
	unsigned		pages;

	struct bio		bio;
};

static void buffer_write_endio(struct bio *bio, int error)
{
	unsigned long flags;
	struct write_buffer_bio *wb =
		container_of(bio, struct write_buffer_bio, bio);
	struct write_buffer *w = wb->w;

	spin_lock_irqsave(&w->wait.lock, flags);

	while (wb->pages) {
		w->entries[wb->offset].done = true;

		wb->pages--;
		wb->offset++;
		wb->offset &= w->mask;
	}

	while (w->head != w->tail &&
	       w->entries[w->tail].done) {
		w->tail++;
		w->tail &= w->mask;
	}

	wake_up_locked(&w->wait);
	spin_unlock_irqrestore(&w->wait.lock, flags);

	bio_put(bio);
}

static void buffer_write(struct cache *ca, struct bio *bio)
{
	struct write_buffer *w = &ca->write_buffer;
	struct write_buffer_bio *wb;
	sector_t sector = bio->bi_sector;
	struct bio *clone;
	struct bio_vec *bv;
	int i;

	clone = bio_clone_bioset(bio, GFP_NOIO, w->bs);
	clone->bi_end_io = buffer_write_endio;

	wb = container_of(clone, struct write_buffer_bio, bio);
	wb->w = w;
	wb->pages = bio->bi_size >> PAGE_SHIFT;

	spin_lock_irq(&w->wait.lock);
	wait_event_locked_irq(w->wait,
			      ((w->tail - w->head - 1) & w->mask) > wb->pages);

	wb->offset = w->head;

	bio_for_each_segment(bv, clone, i) {
		struct write_buffer_entry *e;
		void *vaddr;

		e = entry_find(w, sector);
		if (e)
			hlist_del_init(&e->node);

		e = w->entries + w->head;

		e->done = false;
		e->sector = sector;

		vaddr = kmap_atomic(bv->bv_page);
		memcpy(entry_data(w, e), vaddr, PAGE_SIZE);
		kunmap_atomic(vaddr);

		bv->bv_page = vmalloc_to_page(entry_data(w, e));

		hlist_del_init(&e->node);
		hlist_add_head(&e->node, entry_hash(w, e->sector));

		w->head++;
		w->head &= w->mask;
		sector += PAGE_SIZE >> 9;
	}

	spin_unlock_irq(&w->wait.lock);

	bio_endio(bio, 0);
	generic_make_request(clone);
}

struct read_buffer_bio {
	struct write_buffer	*w;
	struct bio		*orig;

	struct bio		bio;
};

#define FOUND_ALL	1
#define FOUND_NONE	2
#define FOUND_SOME	3

static int buffer_copy(struct write_buffer *w, struct bio *bio)
{
	unsigned long flags;
	sector_t sector = bio->bi_sector;
	struct bio_vec *bv;
	int i, ret = 0;

	spin_lock_irqsave(&w->wait.lock, flags);

	bio_for_each_segment(bv, bio, i) {
		struct write_buffer_entry *e;

		e = entry_find(w, sector);
		if (e) {
			void *vaddr = kmap_atomic(bv->bv_page);
			memcpy(vaddr, entry_data(w, e), PAGE_SIZE);
			kunmap_atomic(vaddr);

			ret |= FOUND_ALL;
		} else {
			ret |= FOUND_NONE;
		}

		sector += PAGE_SIZE >> 9;
	}

	spin_unlock_irqrestore(&w->wait.lock, flags);

	return ret;
}

static void buffer_read_endio(struct bio *bio, int error)
{
	struct read_buffer_bio *rb =
		container_of(bio, struct read_buffer_bio, bio);
	struct write_buffer *w = rb->w;

	buffer_copy(w, rb->orig);

	bio_endio(rb->orig, error);
	bio_put(bio);
}

static void buffer_read(struct cache *ca, struct bio *bio)
{
	struct write_buffer *w = &ca->write_buffer;
	struct read_buffer_bio *rb;
	struct bio *clone;

	switch (buffer_copy(w, bio)) {
	case FOUND_ALL:
		bio_endio(bio, 0);
		break;

	case FOUND_NONE:
		generic_make_request(bio);
		break;

	case FOUND_SOME:
		clone = bio_clone_bioset(bio, GFP_NOIO, w->bs);
		clone->bi_end_io = buffer_read_endio;

		rb = container_of(clone, struct read_buffer_bio, bio);
		rb->w = w;
		rb->orig = bio;
		generic_make_request(clone);
		break;
	}
}

static void bch_write_buffer_submit(struct cache *ca, struct bio *bio)
{
	if (!bio_has_data(bio) || (bio->bi_rw & REQ_DISCARD))
		generic_make_request(bio);
	else if (bio->bi_rw & REQ_WRITE)
		buffer_write(ca, bio);
	else
		buffer_read(ca, bio);
}

void bch_write_buffer_exit(struct cache *ca)
{
	struct write_buffer *w = &ca->write_buffer;

	kfree(w->hash);
	kfree(w->entries);
	vfree(w->buffer);
	if (w->bs)
		bioset_free(w->bs);
}

int bch_write_buffer_init(struct cache *ca)
{
	struct write_buffer *w = &ca->write_buffer;

	init_waitqueue_head(&w->wait);

	w->buffer_bits = 11;

	w->mask = (1 << w->buffer_bits) - 1;
	w->head = w->tail = 0;

	w->bs = bioset_create(16, max(offsetof(struct read_buffer_bio, bio),
				      offsetof(struct write_buffer_bio, bio)));
	if (!w->bs)
		goto err;

	w->buffer = vmalloc(PAGE_SIZE << w->buffer_bits);
	if (!w->buffer)
		goto err;

	w->entries = kzalloc(sizeof(*w->entries) << w->buffer_bits, GFP_KERNEL);
	if (!w->entries)
		goto err;

	w->hash = kzalloc(sizeof(*w->hash) << w->buffer_bits, GFP_KERNEL);
	if (!w->hash)
		goto err;

	ca->submit_fn = bch_write_buffer_submit;
	return 0;
err:
	bch_write_buffer_exit(ca);
	return -ENOMEM;
}
