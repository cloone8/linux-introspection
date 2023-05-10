obj-m+= peekfs.o
peekfs-y+= peekfs_main.o process.o isdata.o util.o peek_ops.o
ccflags-y+=-Wall -Werror -I$(src)/include

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
