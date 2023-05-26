#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/list.h>

#include <peekfs.h>
#include <peek_ops.h>
#include <log.h>
#include <debug.h>
#include <isdata.h>
#include <process.h>

static struct peekable_global* alloc_global(char* name, void __user* addr, struct pid* owner_pid, size_t size) {
    struct peekable_global* new_global;
    size_t name_len;
    char* name_cpy;

    new_global = kmalloc(sizeof(struct peekable_global), GFP_KERNEL);

    if(unlikely(!new_global)) {
        return ERR_PTR(-ENOMEM);
    }

    name_len = strnlen(name, PEEKFS_HUGEBUFSIZE);

    if(unlikely(name_len >= (PEEKFS_HUGEBUFSIZE - 1))) {
        log_err("Entry name too large\n");
        kfree(new_global);
        return ERR_PTR(-E2BIG);
    }

    name_cpy = kmalloc(sizeof(char) * (name_len + 1), GFP_KERNEL);

    if(unlikely(!name_cpy)) {
        kfree(new_global);
        return ERR_PTR(-ENOMEM);
    }

    if(unlikely(strscpy(name_cpy, name, name_len + 1) == -E2BIG)) {
        log_err("Entry name copy too large\n");
        kfree(name_cpy);
        kfree(new_global);
        return ERR_PTR(-E2BIG);
    }

    INIT_LIST_HEAD(&new_global->list);
    new_global->name = name_cpy;
    new_global->addr = addr;
    new_global->owner_pid = owner_pid;
    new_global->size = size;

    return new_global;
}

long parse_isdata_primitive_array_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, size_t num_elems, umode_t perms, struct mm_struct* mm, int* mm_locked) {
    uint64_t array_elem;
    struct peekable_global* new_global;
    long to_ret = size * num_elems;

    peekfs_assert(module != NULL);
    peekfs_assert(parent != NULL);
    peekfs_assert(name != NULL);

    new_global = alloc_global(name, addr, module->owner_pid, size);

    if(unlikely(IS_ERR(new_global))) {
        log_err("Could not allocate new peekable global: %ld\n", PTR_ERR(new_global));
        return PTR_ERR(new_global);
    }

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

long parse_isdata_primitive_entry(struct peekable_module* module, struct proc_dir_entry* parent, char* name, void __user* addr, size_t size, umode_t perms, struct mm_struct* mm, int* mm_locked) {
    struct peekable_global* new_global;

    peekfs_assert(module != NULL);
    peekfs_assert(parent != NULL);
    peekfs_assert(name != NULL);

    new_global = alloc_global(name, addr, module->owner_pid, size);

    if(unlikely(IS_ERR(new_global))) {
        log_err("Could not allocate new peekable global: %ld\n", PTR_ERR(new_global));
        return PTR_ERR(new_global);
    }

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
