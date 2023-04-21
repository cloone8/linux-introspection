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
};

static int register_task(struct task_struct* task) {
    char name_buf[BUFSIZE];

    snprintf(name_buf, BUFSIZE - 1, "%d", task->pid);
    proc_mkdir(name_buf, proc_main);

    return 0;
}

static int task_registered(struct task_struct* task) {

}

int peekfs_refresh_task_list(void) {
    struct task_struct* task_list;

    for_each_process(task_list) {
        if(register_task(task_list) != 0) {

            printk(KERN_ERR "Could not register task %d in peekfs\n", task_list->pid);
            return 1;
        }
    }

    return 0;
}
