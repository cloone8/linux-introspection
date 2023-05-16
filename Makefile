obj-m+= peekfs.o
peekfs-y+= peekfs_main.o process.o isdata.o memutil.o peek_ops.o
ccflags-y+=-Wall -Werror -I$(src)/include

# Remove this line if debugging should be turned off
ccflags-y+= -DPEEKFS_DEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
