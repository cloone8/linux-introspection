#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <peek_ops.h>

#include "internal.h"

static ssize_t single_read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    return peekfs_read_handler(file, buf, count, offset, pde_data(file_inode(file)), 0);
}

static ssize_t single_write_handler(struct file* file, const char __user* buf, size_t count, loff_t* offset) {
    return peekfs_write_handler(file, buf, count, offset, pde_data(file_inode(file)), 0);
}

struct proc_ops peek_ops_single = {
    .proc_read = single_read_handler,
    .proc_write = single_write_handler,
    .proc_open = open_handler,
    .proc_release = close_handler,
    .proc_lseek = default_llseek
};
