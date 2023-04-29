#ifndef __PEEKFS_PROCESS_H__
#define __PEEKFS_PROCESS_H__

struct peekable_process {
    struct list_head list; // List NODE in the peekable process list
    pid_t pid;
    struct proc_dir_entry* proc_entry;
};

struct isdata_section {
    struct list_head list;
    char* bin_path;
    void __user* isdata_start;
};

long peekfs_refresh_task_list(void);
long peekfs_clear_task_list(void);

long peekfs_add_task(struct task_struct* task);
long peekfs_update_task(struct task_struct* task);
long peekfs_remove_task_by_pid(pid_t pid);

#endif
