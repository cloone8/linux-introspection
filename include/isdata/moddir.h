#ifndef __PEEKFS_ISDATA_MODDIR_H__
#define __PEEKFS_ISDATA_MODDIR_H__

#include <linux/kernel.h>
#include <linux/list.h>

struct mod_dir_entry {
    struct list_head list;
    char* name;
    struct proc_dir_entry* entry;
    struct list_head sub_entries;
};

struct mod_dir_entry* mde_create(struct proc_dir_entry* pde, char* name);
void mde_insert(struct mod_dir_entry* entry, struct mod_dir_entry* root);
void mde_rm(struct mod_dir_entry* entry);
struct mod_dir_entry* mde_lookup(char* name, struct mod_dir_entry* root);

#endif
