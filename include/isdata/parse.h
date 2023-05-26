#ifndef __PEEKFS_ISDATA_PARSE_H__
#define __PEEKFS_ISDATA_PARSE_H__

#include <linux/kernel.h>

struct peekable_module;
struct peekable_process;
struct mm_struct;
struct isdata_module;

struct peekable_module* parse_isdata_header(
    struct peekable_process* owner,
    void __user* isdata_header,
    struct mm_struct* mm,
    struct isdata_module* mod_hdr,
    int *mm_locked
);

long parse_isdata_entries(
    struct peekable_process* owner,
    struct peekable_module* module,
    struct mm_struct* mm,
    struct isdata_module* mod_hdr,
    int* mm_locked
);

#endif
