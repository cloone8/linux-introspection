#ifndef __PEEKFS_MEMUTIL_H__
#define __PEEKFS_MEMUTIL_H__

#include <linux/kernel.h>

long copy_data_from_userspace(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked);
long copy_data_to_userspace(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked);

#endif
