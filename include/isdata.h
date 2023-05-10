#ifndef __PEEKFS_ISDATA_H__
#define __PEEKFS_ISDATA_H__

#include <linux/kernel.h>
#include <isdata-headers/isdata_meta.h>

DEFINE_ISDATA_MAGIC_BYTES(isdata_magic_bytes);
#define ISDATA_MAGIC_BYTES_LEN (sizeof(isdata_magic_bytes))

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
