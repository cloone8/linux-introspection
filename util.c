#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include <util.h>
#include <peekfs.h>
#include <log.h>

static void put_pages(struct page** pages, size_t num) {
    size_t i;

    for(i = 0; i < num; i++) {
        put_page(pages[i]);
    }
}

long copy_data_from_userspace(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked) {
    uintptr_t pages_start, pages_end;
    size_t num_pages, offset_from_requested;
    struct page** pages;
    void* mapped_pages;
    long retval;

    peekfs_assert(mm_locked != NULL);
    peekfs_assert(*mm_locked == 1);

    pages_start = rounddown((uintptr_t) user_buf, PAGE_SIZE);
    pages_end = roundup(((uintptr_t) user_buf) + size, PAGE_SIZE);
    offset_from_requested = ((uintptr_t) user_buf) - pages_start;

    peekfs_assert((pages_start + offset_from_requested) < pages_end);
    peekfs_assert((pages_end - pages_start) % PAGE_SIZE == 0);

    num_pages = (pages_end - pages_start) / PAGE_SIZE;

    pages = kmalloc(sizeof(struct page*) * num_pages, GFP_KERNEL);

    if(unlikely(!pages)) {
        return -ENOMEM;
    }

    retval = get_user_pages_remote(mm, pages_start, num_pages, 0, pages, NULL, mm_locked);

    if(unlikely(!(*mm_locked))) {
        // If something went wrong and the lock was left unlocked, re-lock it
        if(unlikely(mmap_read_lock_killable(mm))) {
            if(retval > 0) {
                put_pages(pages, retval);
            }

            return -EINTR;
        }
        *mm_locked = 1;
    }

    if(unlikely(retval < 0)) {
        log_err("Could not get pages at addresses %px->%px, GUPR returned %ld\n", (void*) pages_start, (void*) pages_end, retval);
        kfree(pages);
        return retval;
    } if(unlikely(retval != num_pages)) {
        log_err("GUPR did not return enough pages (%ld of %ld) for %px->%px\n", retval, num_pages, (void*) pages_start, (void*) pages_end);

        put_pages(pages, retval);
        kfree(pages);
        return -EFAULT;
    }

    mapped_pages = vmap(pages, num_pages, 0, PAGE_KERNEL_RO);

    if(unlikely(mapped_pages == NULL)) {
        log_err("Could not map section header pages to kernel vmem for addresses %px->%px\n", (void*) pages_start, (void*) pages_end);
        put_pages(pages, num_pages);
        kfree(pages);

        return -EFAULT;
    }

    // Seems like everything went fine. Do the actual copy now
    memcpy(buf, (void*) (((uintptr_t) mapped_pages) + offset_from_requested), size);

    // Cleanup
    vunmap(mapped_pages);
    put_pages(pages, num_pages);
    kfree(pages);

    return 0;
}
