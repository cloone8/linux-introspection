#ifndef __PEEKFS_UTIL_H__
#define __PEEKFS_UTIL_H__

long copy_data_from_userspace(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked);

#endif
