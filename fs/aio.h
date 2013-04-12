

enum kioctx_versions {
	KIOCTX_VERSION_1,
	KIOCTX_VERSION_2,
	KIOCTX_VERSION_ACALL,
};

struct kioctx {
	enum kioctx_versions	version;
	struct tag_pool		kiocb_tags;
	struct page		**kiocb_pages;
	unsigned		nr_kiocbs;

	struct {
		/*
		 * This is the canonical copy of the tail pointer, updated by
		 * aio_complete(). But aio_complete() also uses it as a lock, so
		 * other code can't use it; for consuming events ring->tail
		 * should be used.
		 */
		unsigned	tail;
	} ____cacheline_aligned_in_smp;

	struct {
		wait_queue_head_t wait;
	} ____cacheline_aligned_in_smp;
};

void ioctx_free(struct kioctx *);
void cancel_all_kiocbs(struct kioctx *);
int ioctx_init(struct kioctx *, unsigned);

void kiocb_free(struct kiocb *);
struct kiocb *aio_get_req(struct kioctx *);

ssize_t aio_run_iocb(struct kiocb *, unsigned, char __user *, bool);
struct kiocb *lookup_kiocb(struct kioctx *, struct iocb __user *, u32);
void kiocb_cancel(struct kiocb *);

static const struct kioctx acall_ctx = {
	.version = KIOCTX_VERSION_ACALL,
};

#define KIOCBS_PER_PAGE	(PAGE_SIZE / sizeof(struct kiocb))

static inline unsigned kioctx_ring_lock(struct kioctx *ctx)
{
	unsigned tail = 0;

	switch (ctx->version) {
	case KIOCTX_VERSION_1:
	case KIOCTX_VERSION_2:
		/*
		 * ctx->tail is both our lock and the canonical version of the tail
		 * pointer.
		 */
		while ((tail = xchg(&ctx->tail, UINT_MAX)) == UINT_MAX)
			cpu_relax();
		break;
	case KIOCTX_VERSION_ACALL:
		/* Nothing */
		break;
	}

	return tail;
}

/* Compat ABI */

unsigned ioctx_v1_ring_put(struct kioctx *, struct kiocb *, unsigned);
void ioctx_v1_ring_unlock(struct kioctx *, unsigned);
void ioctx_v1_exit_aio(struct mm_struct *);

/* V2 ABI */

unsigned ioctx_v2_ring_put(struct batch_complete *, struct kioctx *,
			   struct kiocb *, unsigned);
void ioctx_v2_ring_unlock(struct kioctx *, unsigned);
void ioctx_v2_exit_aio(struct mm_struct *);
