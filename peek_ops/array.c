#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <peek_ops.h>

#include "internal.h"

static ssize_t array_read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    return peekfs_read_handler(file, buf, count, offset, proc_get_parent_data(file_inode(file)), (size_t)pde_data(file_inode(file)));
}

static ssize_t array_write_handler(struct file* file, const char __user* buf, size_t count, loff_t* offset) {
    return peekfs_write_handler(file, buf, count, offset, proc_get_parent_data(file_inode(file)), (size_t)pde_data(file_inode(file)));
}

struct proc_ops peek_ops_array = {
    .proc_read = array_read_handler,
    .proc_write = array_write_handler,
    .proc_open = open_handler,
    .proc_release = close_handler,
    .proc_lseek = default_llseek
};
