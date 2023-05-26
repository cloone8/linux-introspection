#ifndef __PEEKFS_ISDATA_STRUCT_H__
#define __PEEKFS_ISDATA_STRUCT_H__

#include <linux/kernel.h>

long parse_isdata_struct_entry(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    char* name,
    void __user* addr,
    void __user* structdef,
    size_t num_elems,
    umode_t perms,
    struct mm_struct* mm, int* mm_locked
);

long parse_isdata_struct_fields(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    void __user* addr,
    umode_t perms,
    struct isdata_structdef* structdef,
    struct mm_struct* mm, int* mm_locked
);

#endif
