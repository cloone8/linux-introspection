obj-m+= peekfs.o

peekfs-y+= peekfs_main.o process.o memutil.o
peekfs-y+= peek_ops/common.o peek_ops/single.o peek_ops/array.o peek_ops/lib.o
peekfs-y+= isdata/parse.o isdata/primitive.o isdata/struct.o isdata/moddir.o

ccflags-y+=-Wall -Werror -I$(src)/include

# Remove this line if debugging should be turned off
# ccflags-y+= -DPEEKFS_DEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
