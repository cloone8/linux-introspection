#include <linux/kernel.h>

#include <isdata.h>
#include <process.h>
#include <peekfs.h>

void __user* peekfs_get_isdata_section_start(struct mm_struct* mm, elf_ehdr* ehdr) {
    //TODO: Implement this function
    printk(KERN_INFO "Inside get_isdata_section_start\n");
    return (void*) 1;
}

int peekfs_parse_isdata_sections(struct peekable_process* peekable, struct list_head* isdata_sections, struct mm_struct* mm) {
    //TODO: Implement this function
    printk(KERN_INFO "Inside parse_isdata_sections\n");
    return 0;
}
