#ifndef __PEEKFS_ISDATA_PRIMITIVE_H__
#define __PEEKFS_ISDATA_PRIMITIVE_H__

#include <linux/kernel.h>

long parse_isdata_primitive_array_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, size_t num_elems, umode_t perms, struct mm_struct* mm, int* mm_locked);
long parse_isdata_primitive_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, umode_t perms, struct mm_struct* mm, int* mm_locked);

#endif
