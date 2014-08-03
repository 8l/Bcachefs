
obj-$(CONFIG_BCACHE)	+= bcache.o

bcache-y		:= alloc.o bset.o btree.o buckets.o closure.o debug.o\
	extents.o inode.o io.o journal.o keybuf.o move.o movinggc.o request.o\
	six.o stats.o super.o sysfs.o tier.o trace.o util.o writeback.o

CFLAGS_request.o	+= -Iblock
