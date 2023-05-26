#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <isdata-headers/isdata_meta.h>

#include <peekfs.h>
#include <process.h>
#include <memutil.h>
#include <log.h>
#include <peek_ops.h>
#include <isdata.h>
#include <debug.h>

DEFINE_ISDATA_MAGIC_BYTES(isdata_magic_bytes);

static umode_t get_umode_for_addr(struct mm_struct* mm, void __user* addr);
static char* get_entry_name(struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked);
static long parse_isdata_entry(struct peekable_module* module, struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked);

static umode_t get_umode_for_addr(struct mm_struct* mm, void __user* addr) {
    struct vm_area_struct* vma = vma_lookup(mm, (uintptr_t) addr);

    if(unlikely(!vma)) {
        return 0;
    }

    peekfs_assert(vma->vm_flags & VM_READ);

    if(vma->vm_flags & VM_WRITE) {
        return 0666;
    } else {
        return 0444;
    }
}

static char* get_entry_name(struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked) {
    char* entry_name;
    long retval;

    if(unlikely(entry->name_len > PEEKFS_HUGEBUFSIZE)) {
        log_err("Entry name is too large: %u\n", entry->name_len);
        return ERR_PTR(-E2BIG);
    }

    entry_name = kmalloc(entry->name_len, GFP_KERNEL);

    if(unlikely(!entry_name)) {
        return ERR_PTR(-ENOMEM);
    }

    retval = copy_data_from_userspace(mm, entry->name, entry_name, entry->name_len, mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not copy entry name to kernelspace: %ld\n", retval);
        kfree(entry_name);
        return ERR_PTR(retval);
    }

    return entry_name;
}

static long parse_isdata_entry(struct peekable_module* module, struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked) {
    long retval;
    umode_t perms;
    char* entry_name = get_entry_name(entry, mm, mm_locked);

    if(unlikely(IS_ERR(entry_name))) {
        log_err("Could not determine entry name in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, PTR_ERR(entry_name));
        return PTR_ERR(entry_name);
    }

    log_info("PARSING ENTRY %s\n", entry_name);

    perms = get_umode_for_addr(mm, entry->addr);

    if(unlikely(!perms)) {
        log_warn("Could not find VMA for addr %px, defaulting to read-only\n", entry->addr);
        perms = 0444;
    }

    if(entry->flags & ISDATA_EFLAG_STRUCT) {
        retval = parse_isdata_struct_entry(module, module->proc_entry, entry_name, entry->addr, (void*) entry->size_or_def, entry->num_elems, perms, mm, mm_locked);
    } else {
        if(entry->num_elems > 1) {
            retval = parse_isdata_primitive_array_entry(module, module->proc_entry, entry_name, entry->addr, entry->size_or_def, entry->num_elems, perms, mm, mm_locked);
        } else {
            retval = parse_isdata_primitive_entry(module, module->proc_entry, entry_name, entry->addr, entry->size_or_def, perms, mm, mm_locked);
        }
    }

    if(unlikely(retval < 0)) {
        log_err("Could not create proc_entry for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
    }

    log_info("DONE PARSING ENTRY %s\n", entry_name);

    return retval;
}

struct peekable_module* parse_isdata_header(
    struct peekable_process* owner,
    void __user* isdata_header,
    struct mm_struct* mm,
    struct isdata_module* mod_hdr,
    int *mm_locked
) {
    struct peekable_module* new_module;
    long retval;
    char* mod_name;

    if(unlikely(mod_hdr->name_len > PEEKFS_HUGEBUFSIZE)) {
        // Otherwise we run the risk of allocating insane amounts of memory
        log_err("Module name too large: %u bytes\n", mod_hdr->name_len);
        return ERR_PTR(-E2BIG);
    }

    mod_name = kmalloc(mod_hdr->name_len, GFP_KERNEL);

    if(unlikely(!mod_name)) {
        return ERR_PTR(-ENOMEM);
    }

    retval = copy_data_from_userspace(mm, mod_hdr->name, mod_name, mod_hdr->name_len, mm_locked);

    if(unlikely(retval != 0)) {
        kfree(mod_name);
        return ERR_PTR(retval);
    }

    new_module = kmalloc(sizeof(struct peekable_module), GFP_KERNEL);

    if(unlikely(!new_module)) {
        kfree(mod_name);
        return ERR_PTR(-ENOMEM);
    }

    INIT_LIST_HEAD(&new_module->list);
    INIT_LIST_HEAD(&new_module->peekable_globals);
    new_module->isdata_header = isdata_header;
    new_module->name = mod_name;
    new_module->size = 0;
    new_module->proc_entry = proc_mkdir_data(mod_name, 0555, owner->proc_entry, new_module);
    new_module->owner_pid = owner->pid;

    if(unlikely(!new_module->proc_entry)) {
        log_err("Could not register proc entry for pid %d and header %s\n", pid_nr(owner->pid), mod_name);

        kfree(mod_name);
        kfree(new_module);

        return ERR_PTR(-EIO);
    }

    list_add(&new_module->list, &owner->peekable_modules);

    return new_module;
}

long parse_isdata_entries(
    struct peekable_process* owner,
    struct peekable_module* module,
    struct mm_struct* mm,
    struct isdata_module* mod_hdr,
    int* mm_locked
) {
    long retval;
    long total_size = 0;
    long to_ret = 0;
    uint64_t i;
    struct isdata_entry* entries;

    entries = kmalloc(mod_hdr->num_entries * sizeof(struct isdata_entry), GFP_KERNEL);

    if(unlikely(!entries)) {
        return -ENOMEM;
    }

    retval = copy_data_from_userspace(mm, mod_hdr->entries, entries, mod_hdr->num_entries * sizeof(struct isdata_entry), mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not get entries from userspace for process %d and module %s\n", pid_nr(owner->pid), module->name);
        to_ret = retval;
        goto ret;
    }

    log_info("Parsing %llu entries for module %s in process %d\n", mod_hdr->num_entries, module->name, pid_nr(owner->pid));

    for(i = 0; i < mod_hdr->num_entries; i++) {
        retval = parse_isdata_entry(module, entries + i, mm, mm_locked);

        if(unlikely(retval < 0)) {
            log_err("Could not parse isdata entry %llu: %ld\n", i, retval);
            to_ret = retval;
            goto ret;
        }

        total_size += retval;
    }

    proc_set_size(module->proc_entry, total_size);
    module->size = total_size;

ret:
    kfree(entries);
    return to_ret;
}
