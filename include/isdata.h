#ifndef __ISDATA_H__
#define __ISDATA_H__

#include <linux/kernel.h>
#include <linux/elf.h>
#include <linux/list.h>

#include <debug.h>

struct peekable_process;

#ifdef CONFIG_64BIT
    typedef Elf64_Ehdr elf_ehdr;
    #define ELF_CUR_ARCH_CLASS ELFCLASS64
#else
    typedef Elf32_Ehdr elf_ehdr;
    #define ELF_CUR_ARCH_CLASS ELFCLASS32
#endif

#ifdef CONFIG_CPU_BIG_ENDIAN
    #define ELF_CUR_ARCH_ENDIAN ELFDATA2MSB
#else
    #define ELF_CUR_ARCH_ENDIAN ELFDATA2LSB
#endif

static inline int is_elf_header(void* maybe_hdr) {
    return memcmp(((elf_ehdr*) maybe_hdr)->e_ident, ELFMAG, SELFMAG) == 0;
}

static inline int ehdr_arch_compatible(elf_ehdr* ehdr) {
    peekfs_assert(is_elf_header(ehdr));
    return ehdr->e_ident[EI_CLASS] == ELF_CUR_ARCH_CLASS && ehdr->e_ident[EI_DATA] == ELF_CUR_ARCH_ENDIAN;
}

void __user* peekfs_get_isdata_section_start(struct mm_struct* mm, elf_ehdr* ehdr);
int peekfs_parse_isdata_sections(struct peekable_process* peekable, struct list_head* isdata_sections, struct mm_struct* mm);

#endif
