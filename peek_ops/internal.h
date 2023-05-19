#ifndef __PEEKFS_PEEK_OPS_INTERNAL_H__
#define __PEEKFS_PEEK_OPS_INTERNAL_H__

struct peekable_global;

ssize_t peekfs_write_handler(
    // Start of normal proc_write handler params
    struct file* file,
    const char __user* buf,
    size_t count,
    loff_t* offset,
    // End of normal proc_write handler params, custom params here
    struct peekable_global* entry,
    size_t elem
);

ssize_t peekfs_read_handler(
    // Start of normal proc_read handler params
    struct file* file,
    char __user* buf,
    size_t count,
    loff_t* offset,
    // End of normal proc_read handler params, custom params here
    struct peekable_global* entry,
    size_t elem
);

#endif
