#ifndef __PEEKFS_ISDATA_H__
#define __PEEKFS_ISDATA_H__

#include <linux/kernel.h>
#include <linux/elf.h>
#include <linux/list.h>

#include <debug.h>

struct peekable_process;

#if ELF_CLASS == ELFCLASS64
    typedef Elf64_Ehdr elf_ehdr_t;
    typedef Elf64_Shdr elf_shdr_t;
    typedef Elf64_Off elf_off_t;
    typedef Elf64_Half elf_half_t;
#else
    typedef Elf32_Ehdr elf_ehdr_t;
    typedef Elf32_Shdr elf_shdr_t;
    typedef Elf32_Off elf_off_t;
    typedef Elf32_Half elf_half_t;
#endif

static inline int is_elf_header(void* maybe_hdr) {
    return memcmp(((elf_ehdr_t*) maybe_hdr)->e_ident, ELFMAG, SELFMAG) == 0;
}

static inline int ehdr_arch_compatible(elf_ehdr_t* ehdr) {
    peekfs_assert(is_elf_header(ehdr));
    return ehdr->e_ident[EI_CLASS] == ELF_CLASS && ehdr->e_ident[EI_DATA] == ELF_DATA;
}

void __user* peekfs_get_isdata_section_start(struct mm_struct* mm, elf_ehdr_t* ehdr, void __user* file_base, int* mm_locked);
int peekfs_parse_isdata_sections(struct peekable_process* peekable, struct list_head* isdata_sections, struct mm_struct* mm);

#endif
