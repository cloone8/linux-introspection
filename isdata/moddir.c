#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <peekfs.h>
#include <debug.h>
#include <log.h>
#include <isdata.h>

struct mod_dir_entry* mde_create(struct proc_dir_entry* pde, char* name) {
    size_t name_len;
    char* name_cpy;
    struct mod_dir_entry* to_ret = kmalloc(sizeof(struct mod_dir_entry), GFP_KERNEL);

    if(unlikely(!to_ret)) {
        return NULL;
    }

    INIT_LIST_HEAD(&to_ret->list);
    INIT_LIST_HEAD(&to_ret->sub_entries);
    to_ret->entry = pde;

    if(name != NULL) {
        name_len = strnlen(name, PEEKFS_HUGEBUFSIZE - 1);

        if(unlikely(name_len >= (PEEKFS_HUGEBUFSIZE - 1))) {
            log_err("Module name too large to copy\n");
            return NULL;
        }

        name_cpy = kmalloc(sizeof(char) * (name_len + 1), GFP_KERNEL);

        if(unlikely(!name_cpy)) {
            return NULL;
        }

        if(unlikely(strscpy(name_cpy, name, name_len + 1) == -E2BIG)) {
            log_err("Module name too large to copy\n");
            kfree(name_cpy);
            return NULL;
        }

        to_ret->name = name_cpy;
    } else {
        to_ret->name = NULL;
    }

    return to_ret;
}

void mde_insert(struct mod_dir_entry* entry, struct mod_dir_entry* root) {
    peekfs_assert(entry != NULL);
    peekfs_assert(root != NULL);

    list_add(&entry->list, &root->sub_entries);
}

void mde_rm(struct mod_dir_entry* entry) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, &entry->sub_entries) {
        struct mod_dir_entry *sub_mde = container_of(cur, struct mod_dir_entry, list);
        mde_rm(sub_mde);
    }

    list_del(&entry->list);
    proc_remove(entry->entry);

    if(entry->name != NULL) {
        kfree(entry->name);
    }

    kfree(entry);
}

struct mod_dir_entry* mde_lookup(char* name, struct mod_dir_entry* root) {
    struct list_head *cur;

    peekfs_assert(root != NULL);
    peekfs_assert(name != NULL);

    list_for_each(cur, &root->sub_entries) {
        struct mod_dir_entry *sub_mde = container_of(cur, struct mod_dir_entry, list);

        if(sub_mde->name != NULL && strcmp(name, sub_mde->name) == 0) {
            return sub_mde;
        }
    }

    return NULL;
}
