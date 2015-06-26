#include "bcache.h"
#include "blockdev_types.h"
#include "buckets.h"
#include "btree_types.h"
#include "keylist.h"

#include <linux/blktrace_api.h>

#define CREATE_TRACE_POINTS
#include <trace/events/bcache.h>
