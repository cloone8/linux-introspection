#include <linux/kernel.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>
#include <linux/delay.h>
#include <linux/slab.h>

#include <isdata.h>
#include <process.h>
#include <peekfs.h>
#include <debug.h>
#include <log.h>

static void put_pages(struct page** pages, size_t num) {
    size_t i;

    for(i = 0; i < num; i++) {
        put_page(pages[i]);
    }
}

void __user* peekfs_get_isdata_section_start(struct mm_struct* mm, elf_ehdr_t* ehdr, void __user* file_base, int* mm_locked) {
    elf_off_t section_headers_offset;
    elf_half_t num_section_headers;
    void __user* elf_sec_start_page, __user* elf_sec_end_page;
    elf_shdr_t* elf_sec_headers;
    size_t elf_sec_page_num;
    long gup_retval;
    struct page** elf_sec_pages;
    size_t i;

    log_info("Inside get_isdata_section_start\n");

    peekfs_assert(mm != NULL);
    peekfs_assert(ehdr != NULL);
    peekfs_assert(file_base != NULL);

    if(unlikely(ehdr->e_shentsize != sizeof(elf_shdr_t))) {
        log_warn("Invalid or corrupt ELF header at %px\n", ehdr);
        return ERR_PTR(-EINVAL);
    }

    section_headers_offset = ehdr->e_shoff;
    num_section_headers = ehdr->e_shnum;

    log_info("Should be able to find %d section headers at address %px\n", num_section_headers, (void*)(((uintptr_t) file_base) + section_headers_offset));

    elf_sec_start_page = (void __user*) rounddown(((uintptr_t) file_base) + section_headers_offset, PAGE_SIZE);
    elf_sec_end_page = (void __user*) roundup(((uintptr_t) elf_sec_start_page) + (sizeof(elf_shdr_t) * num_section_headers), PAGE_SIZE);

    peekfs_assert((elf_sec_end_page - elf_sec_start_page) % PAGE_SIZE == 0);

    elf_sec_page_num = (elf_sec_end_page - elf_sec_start_page) / PAGE_SIZE;

    elf_sec_pages = kmalloc(elf_sec_page_num * sizeof(struct page*), GFP_KERNEL);

    if(unlikely(elf_sec_pages == NULL)) {
        log_err("Could not allocate memory for page array\n");
        return ERR_PTR(-ENOMEM);
    }

    log_info("Getting %px -> %px for section headers (%lu pages) \n", (void*) elf_sec_start_page, (void*) elf_sec_end_page, elf_sec_page_num);

    gup_retval = get_user_pages_remote(mm, (uintptr_t)elf_sec_start_page, elf_sec_page_num, 0, elf_sec_pages, NULL, mm_locked);

    if(unlikely(!(*mm_locked))) {
        // If something went wrong and the lock was left unlocked, re-lock it
        if(unlikely(mmap_read_lock_killable(mm))) {
            if(gup_retval > 0) {
                put_pages(elf_sec_pages, gup_retval);
            }

            return ERR_PTR(-EINTR);
        }
        *mm_locked = 1;
    }

    if(unlikely(gup_retval < 0)) {
        log_err("Could not get section header pages at addresses %px->%px, GUPR returned %ld\n", (void*) elf_sec_start_page, (void*) elf_sec_end_page, gup_retval);
        kfree(elf_sec_pages);
        return ERR_PTR(gup_retval);
    }

    if(unlikely(gup_retval != elf_sec_page_num)) {
        log_err("GUPR did not return enough pages (%ld of %ld) for %px->%px\n", gup_retval, elf_sec_page_num, (void*) elf_sec_start_page, (void*) elf_sec_end_page);

        put_pages(elf_sec_pages, gup_retval);
        kfree(elf_sec_pages);
        return ERR_PTR(-EFAULT);
    }

    log_info("GUPR succesful for %px->%px\n", (void*) elf_sec_start_page, (void*) elf_sec_end_page);

    // Map all the pages to user accessible ones

    elf_sec_headers = vmap(elf_sec_pages, elf_sec_page_num, 0, PAGE_KERNEL_RO);

    if(unlikely(elf_sec_headers == NULL)) {
        log_err("Could not map section header pages to kernel vmem for addresses %px->%px\n", (void*) elf_sec_start_page, (void*) elf_sec_end_page);

        put_pages(elf_sec_pages, elf_sec_page_num);
        kfree(elf_sec_pages);
        return ERR_PTR(-EFAULT);
    }

    log_info("vmap succesful for %px->%px\n", (void*) elf_sec_start_page, (void*) elf_sec_end_page);

    for(i = 0; i < num_section_headers; i++) {
        log_info("Section header %lu has string offset %u\n", i, elf_sec_headers[i].sh_name);
    }
    log_info("Section header printing done!\n");

    vunmap(elf_sec_headers);
    put_pages(elf_sec_pages, elf_sec_page_num);
    kfree(elf_sec_pages);

    return (void*) 1;
}

int peekfs_parse_isdata_sections(struct peekable_process* peekable, struct list_head* isdata_sections, struct mm_struct* mm) {
    peekfs_assert(peekable != NULL);
    peekfs_assert(isdata_sections != NULL);
    peekfs_assert(mm != NULL);

    //TODO: Implement this function
    log_info("Inside parse_isdata_sections\n");
    return 0;
}
