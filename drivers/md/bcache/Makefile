
obj-$(CONFIG_BCACHE)	+= bcache.o

bcache-y		:= alloc.o bkey.o bkey_methods.o blockdev.o bset.o\
	btree.o buckets.o closure.o debug.o extents.o gc.o inode.o io.o\
	journal.o keybuf.o keylist.o move.o movinggc.o request.o six.o stats.o\
	super.o sysfs.o tier.o trace.o util.o writeback.o

ccflags-y		:= -Werror
