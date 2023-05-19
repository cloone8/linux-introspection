#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include <memutil.h>
#include <peekfs.h>
#include <log.h>
#include <debug.h>

typedef enum {
    USPACE_COPY_FROM,
    USPACE_COPY_TO
} uspace_copy_t;

#define calc_pages_and_offsets(userbuf, bufsize, pages_start, pages_end, offset_from_requested, num_pages) {\
    pages_start = rounddown((uintptr_t) userbuf, PAGE_SIZE);\
    pages_end = roundup(((uintptr_t) userbuf) + bufsize, PAGE_SIZE);\
    offset_from_requested = ((uintptr_t) userbuf) - pages_start;\
    num_pages = (pages_end - pages_start) / PAGE_SIZE;\
}

static void put_pages(struct page** pages, size_t num) {
    size_t i;

    for(i = 0; i < num; i++) {
        put_page(pages[i]);
    }
}

static long gup_lock_recover(struct mm_struct* mm, uintptr_t start_addr, size_t num_pages, struct page** pages, int* mm_locked) {
    long retval = get_user_pages_remote(mm, start_addr, num_pages, 0, pages, NULL, mm_locked);

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
        log_err("Could not get pages at addresses %px->%px, GUPR returned %ld\n", (void*) start_addr, (void*) start_addr + (PAGE_SIZE * num_pages), retval);
        kfree(pages);
        return retval;
    } else if(unlikely(retval != num_pages)) {
        log_err("GUPR did not return enough pages (%ld of %ld) for %px->%px\n", retval, num_pages, (void*) start_addr, (void*) start_addr + (PAGE_SIZE * num_pages));

        put_pages(pages, retval);
        kfree(pages);
        return -EFAULT;
    }

    return retval;
}

static long do_userspace_copy(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked, uspace_copy_t copy_type) {
    uintptr_t pages_start, pages_end;
    size_t num_pages, offset_from_requested;
    struct page** pages;
    void* mapped_pages;
    long retval;
    long to_ret;
    pgprot_t map_prot;

    peekfs_assert(mm_locked != NULL);
    peekfs_assert(*mm_locked == 1);

    calc_pages_and_offsets(user_buf, size, pages_start, pages_end, offset_from_requested, num_pages);

    peekfs_assert((pages_start + offset_from_requested) < pages_end);
    peekfs_assert((pages_end - pages_start) % PAGE_SIZE == 0);

    pages = kmalloc(sizeof(struct page*) * num_pages, GFP_KERNEL);

    if(unlikely(!pages)) {
        return -ENOMEM;
    }

    retval = gup_lock_recover(mm, pages_start, num_pages, pages, mm_locked);

    if(unlikely(retval < 0)) {
        log_err("GUP failed: %ld\n", retval);
        kfree(pages);
        return retval;
    }

    if(likely(copy_type == USPACE_COPY_FROM)) {
        map_prot = PAGE_KERNEL_RO;
    } else if(likely(copy_type == USPACE_COPY_TO)) {
        map_prot = PAGE_KERNEL;
    } else {
        peekfs_assert(false);
    }

    mapped_pages = vmap(pages, num_pages, 0, map_prot);

    if(unlikely(mapped_pages == NULL)) {
        log_err("Could not map section header pages to kernel vmem for addresses %px->%px\n", (void*) pages_start, (void*) pages_end);
        put_pages(pages, num_pages);
        kfree(pages);

        return -EFAULT;
    }

    // Seems like everything went fine. Do the actual copy now
    if(likely(copy_type == USPACE_COPY_FROM)) {
        memcpy(buf, (void*) (((uintptr_t) mapped_pages) + offset_from_requested), size);
        to_ret = 0;
    } else if(likely(copy_type == USPACE_COPY_TO)) {
        memcpy((void*) (((uintptr_t) mapped_pages) + offset_from_requested), buf, size);
        to_ret = 0;
    } else {
        peekfs_assert(false);
    }

    // Cleanup
    vunmap(mapped_pages);
    put_pages(pages, num_pages);
    kfree(pages);

    return to_ret;
}

long copy_data_from_userspace(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked) {
    return do_userspace_copy(mm, user_buf, buf, size, mm_locked, USPACE_COPY_FROM);
}

long copy_data_to_userspace(struct mm_struct* mm, void __user* user_buf, void* buf, size_t size, int* mm_locked) {
    return do_userspace_copy(mm, user_buf, buf, size, mm_locked, USPACE_COPY_TO);
}
