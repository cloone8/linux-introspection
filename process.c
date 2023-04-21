#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <process.h>
#include <peekfs.h>

#define BUFSIZE (256)

static LIST_HEAD(_peekable_process_list);
struct list_head* peekable_process_list = &_peekable_process_list;

struct peekable_process {
    struct list_head list;
    struct task_struct* task;
    struct proc_dir_entry* proc_entry;
};

static struct peekable_process* register_task(struct task_struct* task) {
    char name_buf[BUFSIZE];
    struct proc_dir_entry* task_entry;
    struct peekable_process* new_entry;

    snprintf(name_buf, BUFSIZE - 1, "%d", task->pid);

    task_entry = proc_mkdir(name_buf, proc_main);

    if(task_entry == NULL) {
        printk(KERN_ERR "Could not create proc entry for task\n");
        return NULL;
    }

    new_entry = kmalloc(sizeof(struct peekable_process), GFP_KERNEL);

    if(new_entry == NULL) {
        printk(KERN_ERR "Could not allocate task struct\n");
        proc_remove(task_entry);
        return NULL;
    }

    new_entry->proc_entry = task_entry;
    new_entry->task = task;
    list_add(&new_entry->list, peekable_process_list);

    return new_entry;
}

static struct peekable_process* find_process_in_list(pid_t pid) {
    struct list_head *node;

    list_for_each(node, peekable_process_list) {
        struct peekable_process* entry = container_of(node, struct peekable_process, list);

        if(entry->task->pid == pid) {
            return entry;
        }
    }

    return NULL;
}

static void peekfs_remove_task(struct peekable_process* process) {
    proc_remove(process->proc_entry);
    list_del(&process->list);
    kfree(process);
}

int peekfs_remove_task_by_pid(pid_t pid) {
    struct peekable_process* process;

    process = find_process_in_list(pid);

    if(process != NULL) {
        peekfs_remove_task(process);
        return 0;
    } else {
        return 1;
    }
}

int peekfs_add_task(struct task_struct* task) {
    if(register_task(task) != NULL) {
        return 0;
    }

    return 1;
}

void peekfs_clear_task_list(void) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, peekable_process_list) {
        struct peekable_process* task = container_of(cur, struct peekable_process, list);
        peekfs_remove_task(task);
    }
}

int peekfs_refresh_task_list(void) {
    struct task_struct* task_list;

    // First, clean the entire list
    peekfs_clear_task_list();

    // Now add the new ones
    for_each_process(task_list) {
        if(register_task(task_list) == NULL) {
            printk(KERN_ERR "Could not register task %d in peekfs\n", task_list->pid);

            // Clear the list, something went wrong!
            peekfs_clear_task_list();
            return 1;
        }
    }

    return 0;
}
