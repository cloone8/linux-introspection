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

static long parse_isdata_array_entry(struct peekable_global* new_global, struct peekable_module* module, struct mm_struct* mm, char* name, struct isdata_entry* entry) {
    uint64_t array_elem;
    umode_t perms;

    new_global->proc_entry = proc_mkdir_data(name, 0555, module->proc_entry, new_global);

    if(unlikely(!new_global->proc_entry)) {
        log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
        return -EIO;
    }

    proc_set_size(new_global->proc_entry, entry->size * entry->num_elems);

    perms = get_umode_for_addr(mm, new_global->addr + (array_elem * entry->size));

    if(unlikely(!perms)) {
        log_warn("Could not find VMA for addr %px, defaulting to read-only\n", new_global->addr + (array_elem * entry->size));
        perms = 0444;
    }

    for(array_elem = 0; array_elem < entry->num_elems; array_elem++) {
        struct proc_dir_entry* array_elem_entry;
        char elem_name[PEEKFS_SMALLBUFSIZE] = {0};

        if(unlikely(snprintf(elem_name, PEEKFS_SMALLBUFSIZE - 1, "%llu", array_elem) >= PEEKFS_SMALLBUFSIZE)) {
            log_err("Array index too high: %llu\n", array_elem);
            proc_remove(new_global->proc_entry);
            return -E2BIG;
        }

        array_elem_entry = proc_create_data(elem_name, perms, new_global->proc_entry, &peek_ops_array, (void*)array_elem);

        if(unlikely(!array_elem_entry)) {
            log_err("Array entry could not be created: %llu\n", array_elem);
            proc_remove(new_global->proc_entry);
            return -EIO;
        }

        proc_set_size(array_elem_entry, entry->size);
    }

    return 0;
}

static long parse_isdata_single_entry(struct peekable_global* new_global, struct peekable_module* module, struct mm_struct* mm, char* name, struct isdata_entry* entry) {
    umode_t perms;

    perms = get_umode_for_addr(mm, new_global->addr);

    if(unlikely(!perms)) {
        log_warn("Could not find VMA for addr %px, defaulting to read-only\n", new_global->addr);
        perms = 0444;
    }

    new_global->proc_entry = proc_create_data(name, perms, module->proc_entry, &peek_ops_single, new_global);

    if(unlikely(!new_global->proc_entry)) {
        log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
        return -EIO;
    }

    proc_set_size(new_global->proc_entry, entry->size);

    return 0;
}

static long parse_isdata_entry(struct peekable_module* module, struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked) {
    long retval;
    char* entry_name;
    struct peekable_global* new_global;

    if(unlikely(entry->name_len > PEEKFS_HUGEBUFSIZE)) {
        log_err("Entry name in module %s too large: %u\n", module->name, entry->name_len);
        return -E2BIG;
    }

    entry_name = kmalloc(entry->name_len, GFP_KERNEL);

    if(unlikely(!entry_name)) {
        return -ENOMEM;
    }

    retval = copy_data_from_userspace(mm, entry->name, entry_name, entry->name_len, mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not copy entry name to kernelspace in module %s: %ld\n", module->name, retval);
        kfree(entry_name);
        return retval;
    }

    new_global = kmalloc(sizeof(struct peekable_global), GFP_KERNEL);

    if(unlikely(!new_global)) {
        kfree(entry_name);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&new_global->list);
    new_global->name = entry_name;
    new_global->addr = entry->addr;
    new_global->owner_pid = module->owner_pid;
    new_global->size = entry->size;

    if(entry->num_elems > 1) {
        retval = parse_isdata_array_entry(new_global, module, mm, entry_name, entry);
    } else {
        retval = parse_isdata_single_entry(new_global, module, mm, entry_name, entry);
    }

    if(unlikely(retval != 0)) {
        log_err("Could not create proc_entry for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
        kfree(entry_name);
        kfree(new_global);

        return retval;
    }

    list_add(&new_global->list, &module->peekable_globals);

    return 0;
}

long parse_isdata_entries(
    struct peekable_process* owner,
    struct peekable_module* module,
    struct mm_struct* mm,
    struct isdata_module* mod_hdr,
    int* mm_locked
) {
    long retval;
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

        if(unlikely(retval != 0)) {
            log_err("Could not parse isdata entry %llu: %ld\n", i, retval);
            to_ret = retval;
            goto ret;
        }
    }

ret:
    kfree(entries);
    return to_ret;
}
