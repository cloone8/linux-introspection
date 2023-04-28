#ifndef __ISDATA_H__
#define __ISDATA_H__

#include <linux/kernel.h>
#include <linux/elf.h>

#ifdef CONFIG_64BIT

#else

#endif

static inline int is_elf_header(void* maybe_hdr) {
    return memcmp(((Elf64_Ehdr*) maybe_hdr)->e_ident, ELFMAG, SELFMAG) == 0;
}

void __user* peekfs_get_isdata_section_start(struct mm_struct* mm, Elf64_Ehdr* ehdr);

#endif
