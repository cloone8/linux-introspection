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

static inline uintptr_t align_and_get_size_diff(void** addr, uint64_t align_to) {
    void* new_addr = (void*) roundup((uintptr_t)(*addr), align_to);
    uintptr_t size_diff = (uintptr_t) new_addr - (uintptr_t)(*addr);
    *addr = new_addr;

    return size_diff;
}

static long parse_isdata_entry(struct peekable_module* module, struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked);
static long parse_isdata_primitive_array_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, size_t num_elems, umode_t perms, struct mm_struct* mm, int* mm_locked);
static long parse_isdata_primitive_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, umode_t perms, struct mm_struct* mm, int* mm_locked);
static long parse_isdata_struct_entry(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    char* name,
    void __user* addr,
    void __user* structdef,
    size_t num_elems,
    umode_t perms,
    struct mm_struct* mm, int* mm_locked
);
static char* get_entry_name(struct isdata_entry* entry, struct mm_struct* mm, int* mm_locked);
static umode_t get_umode_for_addr(struct mm_struct* mm, void __user* addr);
static long parse_isdata_struct_fields(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    void __user* addr,
    umode_t perms,
    struct isdata_structdef* structdef,
    struct mm_struct* mm, int* mm_locked
);

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

static long parse_isdata_primitive_array_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, size_t num_elems, umode_t perms, struct mm_struct* mm, int* mm_locked) {
    uint64_t array_elem;
    struct peekable_global* new_global;
    long to_ret = size * num_elems;

    new_global = kmalloc(sizeof(struct peekable_global), GFP_KERNEL);

    if(unlikely(!new_global)) {
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&new_global->list);
    new_global->name = name;
    new_global->addr = addr;
    new_global->owner_pid = module->owner_pid;
    new_global->size = size;

    new_global->proc_entry = proc_mkdir_data(name, 0555, parent, new_global);

    if(unlikely(!new_global->proc_entry)) {
        log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
        to_ret = -EIO;
        goto ret_no_proc_remove;
    }

    proc_set_size(new_global->proc_entry, size * num_elems);

    for(array_elem = 0; array_elem < num_elems; array_elem++) {
        struct proc_dir_entry* array_elem_entry;
        char elem_name[PEEKFS_SMALLBUFSIZE] = {0};

        if(unlikely(snprintf(elem_name, PEEKFS_SMALLBUFSIZE - 1, "%llu", array_elem) >= PEEKFS_SMALLBUFSIZE)) {
            log_err("Array index too high: %llu\n", array_elem);
            to_ret = -E2BIG;
            goto ret_err;
        }

        array_elem_entry = proc_create_data(elem_name, perms, new_global->proc_entry, &peek_ops_array, (void*)array_elem);

        if(unlikely(!array_elem_entry)) {
            log_err("Array entry could not be created: %llu\n", array_elem);
            to_ret = -EIO;
            goto ret_err;
        }

        proc_set_size(array_elem_entry, size);
    }

    list_add(&new_global->list, &module->peekable_globals);

ret:
    return to_ret;

ret_err:
    proc_remove(new_global->proc_entry);

ret_no_proc_remove:
    kfree(new_global);

    goto ret;
}

static long parse_isdata_struct_fields(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    void __user* addr,
    umode_t perms,
    struct isdata_structdef* structdef,
    struct mm_struct* mm, int* mm_locked
) {
    struct isdata_structfield* fields;
    uint64_t i;
    long retval, to_ret = 0;

    fields = kmalloc(structdef->num_fields * sizeof(struct isdata_structfield), GFP_KERNEL);

    if(unlikely(!fields)) {
        return -ENOMEM;
    }

    retval = copy_data_from_userspace(mm, structdef->fields, fields, structdef->num_fields * sizeof(struct isdata_structfield), mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not copy struct fields from userspace: %ld\n", retval);
        to_ret = retval;
        goto ret;
    }

    log_info("Struct base addr %px, size %llu, max addr %px\n", addr, structdef->size, (void*)(((uintptr_t) addr) + structdef->size));

    for(i = 0; i < structdef->num_fields; i++) {
        char name_buf[PEEKFS_BUFSIZE] = {0};
        struct isdata_structfield* field = fields + i;
        void __user* field_addr = (void*) (((uintptr_t) addr) + (field->offset_in_bits / 8));

        log_info("Parsing field with index %llu, addr %px and offset %llu\n", i, field_addr, field->offset_in_bits / 8);



        if(unlikely(field->name_len > (PEEKFS_BUFSIZE - 1))) {
            log_warn("Struct field name too long: %hu/%d. Truncating\n", field->name_len, PEEKFS_BUFSIZE - 1);
        }

        retval = copy_data_from_userspace(mm, field->name, name_buf, min(field->name_len, (uint16_t) (PEEKFS_BUFSIZE - 1)), mm_locked);

        if(unlikely(retval < 0)) {
            log_err("Could not copy struct field name from userspace: %ld\n", retval);
            to_ret = retval;
            goto ret;
        }

        if(field->flags & ISDATA_SFFLAG_STRUCT) {
            log_info("Field is struct called %s with addr %px and %llu elements\n", name_buf, (void*)field->size_bits_or_def, field->num_elems);

            retval = parse_isdata_struct_entry(module, parent, name_buf, field_addr, (void*)field->size_bits_or_def, field->num_elems, perms, mm, mm_locked);

            if(unlikely(retval < 0)) {
                log_err("Could not parse nested struct for field %s: %ld\n", name_buf, retval);
                to_ret = retval;
                goto ret;
            }
        } else {
            log_info("Field called %s with size %llu and %llu elements\n", name_buf, field->size_bits_or_def / 8, field->num_elems);

            peekfs_assert((((uintptr_t) field_addr) + (field->size_bits_or_def / 8)) <= (((uintptr_t) addr) + structdef->size));

            if(field->num_elems > 1) {
                retval = parse_isdata_primitive_array_entry(module, parent, name_buf, field_addr, field->size_bits_or_def / 8, field->num_elems, perms, mm, mm_locked);
            } else {
                retval = parse_isdata_primitive_entry(module, parent, name_buf, field_addr, field->size_bits_or_def / 8, perms, mm, mm_locked);
            }

            if(unlikely(retval < 0)) {
                log_err("Could not create primitive entry for field %s: %ld\n", name_buf, retval);
                to_ret = retval;
                goto ret;
            }
        }

        log_info("Done parsing field %s\n", name_buf);
    }

ret:
    kfree(fields);
    return to_ret;
}

static long parse_isdata_struct_entry(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    char* name,
    void __user* addr,
    void __user* structdef,
    size_t num_elems,
    umode_t perms,
    struct mm_struct* mm, int* mm_locked
) {
    long retval;
    struct proc_dir_entry* struct_folder_entry;
    struct isdata_structdef structlayout;

    log_info("Parsing struct %s...\n", name);

    retval = copy_data_from_userspace(mm, structdef, &structlayout, sizeof(struct isdata_structdef), mm_locked);

    if(unlikely(retval != 0)) {
        log_err("Could not copy struct definition from userspace in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
        return retval;
    }

    struct_folder_entry = proc_mkdir_data(name, 0555, parent, NULL);

    if(unlikely(!struct_folder_entry)) {
        log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
        return -EIO;
    }

    if(num_elems <= 1) {
        retval = parse_isdata_struct_fields(module, struct_folder_entry, addr, perms, &structlayout, mm, mm_locked);

        if(unlikely(retval < 0)) {
            log_err("Could not parse struct definition for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
            return retval;
        }

        proc_set_size(struct_folder_entry, structlayout.size);

        log_info("Done parsing struct %s. Total size %llu\n", name, structlayout.size);

        return structlayout.size;
    } else {
        size_t i;

        for(i = 0; i < num_elems; i++) {
            char elem_name[PEEKFS_SMALLBUFSIZE] = {0};
            struct proc_dir_entry* struct_field_parent;
            void __user* elem_addr = (void*) (((uintptr_t) addr) + (i * structlayout.size));

            if(unlikely(snprintf(elem_name, PEEKFS_SMALLBUFSIZE - 1, "%lu", i) >= PEEKFS_SMALLBUFSIZE)) {
                log_err("Array index too high: %lu\n", i);
                return -E2BIG;
            }

            struct_field_parent = proc_mkdir_data(elem_name, 0555, struct_folder_entry, NULL);

            if(unlikely(!struct_field_parent)) {
                log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
                return -EIO;
            }

            retval = parse_isdata_struct_fields(module, struct_field_parent, elem_addr, perms, &structlayout, mm, mm_locked);

            if(unlikely(retval < 0)) {
                log_err("Could not parse struct definition for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
                return retval;
            }

            proc_set_size(struct_field_parent, structlayout.size);
        }

        proc_set_size(struct_folder_entry, structlayout.size * structlayout.num_fields);

        log_info("Done parsing struct %s. Total size %llu\n", name, structlayout.size * structlayout.num_fields);

        return structlayout.size * structlayout.num_fields;
    }
}

static long parse_isdata_primitive_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, umode_t perms, struct mm_struct* mm, int* mm_locked) {
    struct peekable_global* new_global;
    new_global = kmalloc(sizeof(struct peekable_global), GFP_KERNEL);

    if(unlikely(!new_global)) {
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&new_global->list);
    new_global->name = name;
    new_global->addr = addr;
    new_global->owner_pid = module->owner_pid;
    new_global->size = size;

    new_global->proc_entry = proc_create_data(name, perms, parent, &peek_ops_single, new_global);

    if(unlikely(!new_global->proc_entry)) {
        log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
        kfree(new_global);
        return -EIO;
    }

    proc_set_size(new_global->proc_entry, size);

    list_add(&new_global->list, &module->peekable_globals);

    return size;
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
