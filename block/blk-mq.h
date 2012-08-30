#ifndef INT_BLK_MQ_H
#define INT_BLK_MQ_H

struct blk_mq_ctx_queue {
	spinlock_t		lock;
	struct list_head	rq_list;
};

struct blk_mq_ctx {
	struct blk_mq_ctx_queue ____cacheline_aligned_in_smp q;

	unsigned int		index;
	unsigned int		index_hw;
	unsigned int		ipi_redirect;

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];
	unsigned long		rq_merged;

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];

	struct kobject		kobj;
};

#endif
