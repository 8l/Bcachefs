#ifndef __LINUX_ACALL_H
#define __LINUX_ACALL_H

/*
 * The kernel makes a private copy of this during sys_acall_submit().  Once
 * that call returns userspace does not need to keep it around.
 *
 * The flags field will be used to indicate the presence of fields which
 * are added to the end of the struct over time.  To support this the
 * submission call must refuse submission for structs which contain flags
 * which it doesn't recognize.
 */
struct acall_submission {
	u32 nr;
	u32 flags;
	u64 cookie;
	u64 completion_ring_pointer;
	u64 completion_pointer;
	u64 id_pointer;
	u64 args[6];
};

#define ACALL_SUBMIT_THREAD_POOL 1

/*
 * This is used by userspace to specify an operation for cancelation or
 * waiting.  The data here only has significance to the kernel.
 */
struct acall_id {
	unsigned char opaque[16];
};

struct acall_completion {
	u64 return_code;
	u64 cookie;
};

/*
 * 'nr' is read by the kernel each time it tries to store an event in
 * the ring.
 *
 * 'head' is written by the kernel as it adds events.  Once it changes than
 * the kernel will be writing an acall_completion struct into the ring.
 * A non-zero cookie field of the completion struct indicates that the
 * completion has been written.  Once it is non-zero then the return_code
 * can be loaded after issuing a read memory barrier.
 */
struct acall_completion_ring {
	u32 head;
	u32 nr;
	struct acall_completion comps[0];
};

#endif
