#ifndef __PEEKFS_PROCESS_H__
#define __PEEKFS_PROCESS_H__

#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/pid.h>

struct peekable_process {
    struct list_head list; // List NODE in the peekable process list

    // Main administrative data
    struct pid* pid;
    struct proc_dir_entry* proc_entry;
    struct mod_dir_entry* mod_dirs;

    // List of modules registered to this process
    struct list_head peekable_modules;

    struct rw_semaphore lock;
};

struct peekable_module {
    struct list_head list;
    char* name;
    size_t size;
    struct pid* owner_pid;
    void __user* isdata_header;
    struct proc_dir_entry* proc_entry;
    struct list_head peekable_globals;
};

struct peekable_global {
    struct list_head list;
    char* name;
    struct pid* owner_pid;
    size_t size;
    void __user* addr;
    struct proc_dir_entry* proc_entry;
};

long peekfs_clear_task_list(void);
long peekfs_clone_process(struct pid* base, struct pid* new);
long peekfs_register_module(struct pid* pid, void __user* module_hdr);
long peekfs_remove_module(struct pid* pid, void __user* module_hdr);
long peekfs_remove_task_by_pid(struct pid* pid);
struct peekable_process* peekfs_get_process(struct pid* pid, int access);

#endif
