#include <linux/proc_fs.h>
#include <peek_ops.h>

#include "internal.h"

static ssize_t struct_read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    return peekfs_read_handler(file, buf, count, offset, pde_data(file_inode(file)), 0);
}

static ssize_t struct_write_handler(struct file* file, const char __user* buf, size_t count, loff_t* offset) {
    return peekfs_write_handler(file, buf, count, offset, pde_data(file_inode(file)), 0);
}

struct proc_ops peek_ops_struct = {
    .proc_read = struct_read_handler,
    .proc_write = struct_write_handler,
    .proc_open = open_handler,
    .proc_release = close_handler,
};
