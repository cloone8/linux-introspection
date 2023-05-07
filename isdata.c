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

// static void put_pages(struct page** pages, size_t num) {
//     size_t i;

//     for(i = 0; i < num; i++) {
//         put_page(pages[i]);
//     }
// }
