#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

#include <peekfs.h>
#include <process.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PeekFS introspection filesystem");

#define BUFSIZE (256)

// ProcFS related vars
struct proc_dir_entry* proc_main;

// Timer related vars
static void process_refresh_handler(struct work_struct* work);
static unsigned interrupt_count = 0;
static struct workqueue_struct *my_workqueue;
static DECLARE_DELAYED_WORK(process_refresh_task, process_refresh_handler);

static volatile int die = 0;

// static ssize_t mywrite(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
// 	printk( KERN_DEBUG "write handler\n");
// 	return -1;
// }

// static ssize_t myread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
// 	printk( KERN_DEBUG "read handle on %s\n", file->f_path.dentry->d_name.name);
// 	return 0;
// }

// static struct proc_ops myops = {
//     .proc_read = myread,
//     .proc_write = mywrite
// };
static void process_refresh_handler(struct work_struct* work) {
	interrupt_count++;

    printk(KERN_INFO "Interrupt %u called\n", interrupt_count);

    if(die) {
        return;
    }

    if(peekfs_refresh_task_list() != 0) {
        printk(KERN_ERR "Error refreshing task list\n");
    }

    queue_delayed_work(my_workqueue, &process_refresh_task, PEEKFS_REFRESH_PROCESS_TASK_INTERVAL_JIFFIES);
}

static int __init peekfs_init(void) {
    printk(KERN_INFO "Initializing PeekFS\n");

    printk(KERN_INFO "Initializing proc filesystem base\n");
    proc_main = proc_mkdir(PEEKFS_MAIN_DIR, NULL);

    if(!proc_main) {
        printk(KERN_ERR "Error creating proc filesystem base\n");
        goto err_proc_mkdir;
    }

    printk(KERN_INFO "Initializing background work queue\n");
    my_workqueue = create_workqueue(PEEKFS_WORKQUEUE_NAME);

    if(!my_workqueue) {
        printk(KERN_ERR "Error creating workqueue\n");
        goto err_create_workqueue;
    }

    printk(KERN_INFO "Initializing process refresh task\n");
    if(!queue_delayed_work(my_workqueue, &process_refresh_task, PEEKFS_REFRESH_PROCESS_TASK_INTERVAL_JIFFIES)) {
        printk(KERN_ERR "Error scheduling process refresh task\n");
        goto err_queue_process_refresh;
    }

    printk(KERN_INFO "Done initializing PeekFS\n");
    return 0;

    // Error handlers that should not be encountered during normal execution
    die = 1;
    cancel_delayed_work(&process_refresh_task);

err_queue_process_refresh:
    flush_workqueue(my_workqueue);
    destroy_workqueue(my_workqueue);

err_create_workqueue:
    proc_remove(proc_main);

err_proc_mkdir:
    return 1;
}

static void __exit peekfs_exit(void) {
    printk(KERN_INFO "Stopping PeekFS\n");

    printk(KERN_INFO "Stopping background work\n");
    die = 1;
    cancel_delayed_work(&process_refresh_task);
    flush_workqueue(my_workqueue);
    destroy_workqueue(my_workqueue);

    printk(KERN_INFO "Destroying proc filesystem\n");

    proc_remove(proc_main);
    printk(KERN_INFO "Cleanup done, exiting PeekFS\n");
}

module_init(peekfs_init);
module_exit(peekfs_exit);
