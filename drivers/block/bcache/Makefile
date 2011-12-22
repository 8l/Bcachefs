
ccflags-y		+= -std=gnu99
obj-$(CONFIG_BCACHE)	+= bcache.o

bcache-y		:= alloc.o btree.o bset.o io.o journal.o\
	writeback.o request.o super.o debug.o util.o trace.o

CFLAGS_request.o	+= -Iblock
