#ifndef __PEEKFS_ISDATA_H__
#define __PEEKFS_ISDATA_H__

#include <linux/kernel.h>

static const u8 isdata_magic_bytes[] = {'_', 'I', 'S', 'D', 'A', 'T', 'A', '_', 'M', 'O', 'D', '_', 'H', 'D', 'R', '_'};
#define ISDATA_MAGIC_BYTES_LEN (sizeof(isdata_magic_bytes))

struct isdata_entry {
    uint16_t name_len;
    char* name;
    uint64_t size;
    uint32_t flags;
    void* addr;
};

struct isdata_module {
    uint8_t magic[16];
    uint16_t version;
    uint16_t name_len;
    char* name;
    uint64_t num_entries;
    struct isdata_entry* entries;
};

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
