
obj-$(CONFIG_BCACHE)	+= bcache.o

bcache-y		:= alloc.o bset.o btree.o buckets.o debug.o dirent.o extents.o\
	fs.o inode.o io.o ioctl.o journal.o keybuf.o move.o movinggc.o\
	request.o stats.o super.o sysfs.o tier.o trace.o util.o writeback.o\
	xattr.o

CFLAGS_request.o	+= -Iblock
