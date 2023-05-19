#ifndef __PEEKFS_PEEK_OPS_COMMON_H__
#define __PEEKFS_PEEK_OPS_COMMON_H__

int open_handler(struct inode *inode, struct file *file);
int close_handler(struct inode *inode, struct file *file);

#endif
