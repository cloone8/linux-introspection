#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>

#include <process.h>
#include <peekfs.h>

#define BUFSIZE (256)

static LIST_HEAD(_peekable_process_list);
static struct list_head* peekable_process_list = &_peekable_process_list;

DEFINE_MUTEX(peekable_process_list_mtx);

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

static void remove_peekable_process(struct peekable_process* process) {
    proc_remove(process->proc_entry);
    list_del(&process->list);
    kfree(process);
}

static void clear_peekable_processes(void) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, peekable_process_list) {
        struct peekable_process* task = container_of(cur, struct peekable_process, list);
        remove_peekable_process(task);
    }
}

static int update_peekable_process(struct peekable_process* peekable, struct task_struct* task) {
    return 0;
}

int peekfs_remove_task_by_pid(pid_t pid) {
    struct peekable_process* process;

    process = find_process_in_list(pid);

    if(process != NULL) {
        remove_peekable_process(process);
        return 0;
    } else {
        return 1;
    }
}

int peekfs_add_task(struct task_struct* task) {
    struct peekable_process* ret;

    mutex_lock(&peekable_process_list_mtx);
    ret = register_task(task);
    mutex_unlock(&peekable_process_list_mtx);

    if(ret != NULL) {
        return 0;
    }

    return 1;
}

int peekfs_update_task(struct task_struct* task) {
    struct peekable_process* peekable;
    int update_ret;
    int retval = 0;

    mutex_lock(&peekable_process_list_mtx);

    peekable = find_process_in_list(task->pid);

    if(peekable == NULL) {
        retval = 1;
        goto update_task_ret;
    }

    update_ret = update_peekable_process(peekable, task);

    if(update_ret != 0) {
        retval = 2;
        goto update_task_ret;
    }

update_task_ret:
    mutex_unlock(&peekable_process_list_mtx);
    return retval;
}

void peekfs_clear_task_list(void) {
    mutex_lock(&peekable_process_list_mtx);

    clear_peekable_processes();

    mutex_unlock(&peekable_process_list_mtx);
}

int peekfs_refresh_task_list(void) {
    struct task_struct* task_list;

    mutex_lock(&peekable_process_list_mtx);

    // First, clean the entire list
    clear_peekable_processes();

    // Now add the new ones
    for_each_process(task_list) {
        if(register_task(task_list) == NULL) {
            printk(KERN_ERR "Could not register task %d in peekfs\n", task_list->pid);

            // Clear the list, something went wrong!
            clear_peekable_processes();
            mutex_unlock(&peekable_process_list_mtx);
            return 1;
        }
    }

    mutex_unlock(&peekable_process_list_mtx);
    return 0;
}
