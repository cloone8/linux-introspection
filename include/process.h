#ifndef __PEEKFS_PROCESS_H__
#define __PEEKFS_PROCESS_H__

int peekfs_refresh_task_list(void);
void peekfs_clear_task_list(void);

int peekfs_add_task(struct task_struct* task);
int peekfs_update_task(struct task_struct* task);
int peekfs_remove_task_by_pid(pid_t pid);

#endif
