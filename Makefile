EXTRA_CFLAGS=-Wall -Werror -I$(src)/include

obj-m+= peekfs.o
peekfs-y+= peekfs_main.o process.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
