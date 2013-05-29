#ifndef _LINUX_BATCH_COMPLETE_H
#define _LINUX_BATCH_COMPLETE_H

/*
 * Common stuff to the aio and block code for batch completion. Everything
 * important is elsewhere:
 */

struct bio;
struct kiocb;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct batch_complete {
	struct bio_list		bio;
	struct kiocb		*kiocb;
};

#endif
