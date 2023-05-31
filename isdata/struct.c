#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>

#include <peekfs.h>
#include <process.h>
#include <memutil.h>
#include <log.h>
#include <peek_ops.h>
#include <isdata.h>
#include <debug.h>

long parse_isdata_struct_fields(
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

    for(i = 0; i < structdef->num_fields; i++) {
        char name_buf[PEEKFS_BUFSIZE] = {0};
        struct isdata_structfield* field = fields + i;
        void __user* field_addr = (void*) (((uintptr_t) addr) + (field->offset_in_bits / 8));

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
            retval = parse_isdata_struct_entry(module, parent, name_buf, field_addr, (void*)field->size_bits_or_def, field->num_elems, perms, mm, mm_locked);

            if(unlikely(retval < 0)) {
                log_err("Could not parse nested struct for field %s: %ld\n", name_buf, retval);
                to_ret = retval;
                goto ret;
            }
        } else {
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
    }

ret:
    kfree(fields);
    return to_ret;
}

static long parse_singular_struct_entry(
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    void __user* addr,
    umode_t perms,
    struct isdata_structdef* structlayout,
    struct mm_struct* mm, int* mm_locked
) {
    long retval = parse_isdata_struct_fields(module, parent, addr, perms, structlayout, mm, mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not parse struct definition for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
        return retval;
    }

    proc_set_size(parent, structlayout->size);

    return structlayout->size;
}

static long parse_array_struct_entry(
    size_t num_elems,
    struct peekable_module* module,
    struct proc_dir_entry* parent,
    void __user* addr,
    umode_t perms,
    struct isdata_structdef* structlayout,
    struct mm_struct* mm, int* mm_locked
) {
    size_t i;

    for(i = 0; i < num_elems; i++) {
        long retval;
        char elem_name[PEEKFS_SMALLBUFSIZE] = {0};
        struct proc_dir_entry* struct_field_parent;
        void __user* elem_addr = (void*) (((uintptr_t) addr) + (i * structlayout->size));

        if(unlikely(snprintf(elem_name, PEEKFS_SMALLBUFSIZE - 1, "%lu", i) >= PEEKFS_SMALLBUFSIZE)) {
            log_err("Array index too high: %lu\n", i);
            return -E2BIG;
        }

        struct_field_parent = proc_mkdir_data(elem_name, 0555, parent, NULL);

        if(unlikely(!struct_field_parent)) {
            log_err("Could not create proc_entry for entry in process %d and module %s\n", pid_nr(module->owner_pid), module->name);
            return -EIO;
        }

        retval = parse_isdata_struct_fields(module, struct_field_parent, elem_addr, perms, structlayout, mm, mm_locked);

        if(unlikely(retval < 0)) {
            log_err("Could not parse struct definition for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
            return retval;
        }

        proc_set_size(struct_field_parent, structlayout->size);
    }

    proc_set_size(parent, structlayout->size * structlayout->num_fields);

    return structlayout->size * structlayout->num_fields;
}

long parse_isdata_struct_entry(
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

    if(num_elems > 1) {
        retval = parse_array_struct_entry(num_elems, module, struct_folder_entry, addr, perms, &structlayout, mm, mm_locked);
    } else {
        retval = parse_singular_struct_entry(module, struct_folder_entry, addr, perms, &structlayout, mm, mm_locked);
    }

    if(unlikely(retval < 0)) {
        log_err("Could not parse struct definition for entry in process %d and module %s: %ld\n", pid_nr(module->owner_pid), module->name, retval);
        return retval;
    }

    return retval;
}
