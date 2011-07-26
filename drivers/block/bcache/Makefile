
ccflags-y		+= -std=gnu99
obj-$(CONFIG_BCACHE)	+= bcache.o

bcache-y		:= btree.o bset.o journal.o writeback.o\
	request.o super.o debug.o util.o

CFLAGS_super.o		+= -Iblock
