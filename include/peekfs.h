#ifndef __PEEKFS_H__
#define __PEEKFS_H__

#include <linux/atomic.h>

#define PEEKFS_MAIN_DIR ("peek")

#define PEEKFS_SMALLBUFSIZE (32)
#define PEEKFS_BUFSIZE (256)
#define PEEKFS_BIGBUFSIZE (512)
#define PEEKFS_HUGEBUFSIZE (PAGE_SIZE)

extern struct proc_dir_entry* proc_main;
extern atomic64_t active_handlers;

#endif
