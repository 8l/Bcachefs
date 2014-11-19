#ifndef _BCACHE_BKEY_H
#define _BCACHE_BKEY_H

#include <linux/bcache.h>

int bch_bkey_to_text(char *, size_t, const struct bkey *);

#endif /* _BCACHE_BKEY_H */
