#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/kprobes.h>

#include <peekfs.h>
#include <process.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PeekFS introspection filesystem");

// Some bookkeeping, useful for debugging
static atomic64_t num_handlers = ATOMIC_INIT(0);
static atomic64_t num_fork = ATOMIC_INIT(0);
static atomic64_t num_exec = ATOMIC_INIT(0);
static atomic64_t num_exit = ATOMIC_INIT(0);

// ProcFS related vars
struct proc_dir_entry* proc_main;

// Kprobe related vars
static int krp_fork_handler(struct kretprobe_instance* probe, struct pt_regs* regs);
static int krp_exec_handler(struct kretprobe_instance* probe, struct pt_regs* regs);
static int krp_exit_handler(struct kretprobe_instance* probe, struct pt_regs* regs);

struct krp_data {

};

static struct kretprobe krp_fork = {
    .kp.symbol_name = "copy_process",
    .handler = krp_fork_handler,
    .data_size = sizeof(struct krp_data),
    .maxactive = 2 * NR_CPUS
};

static struct kretprobe krp_exec = {
    .kp.symbol_name = "bprm_execve",
    .handler = krp_exec_handler,
    .data_size = sizeof(struct krp_data),
    .maxactive = 2 * NR_CPUS
};

static struct kretprobe krp_exit = {
    .kp.symbol_name = "do_exit",
    .entry_handler = krp_exit_handler,
    .data_size = sizeof(struct krp_data),
    .maxactive = 2 * NR_CPUS
};

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

static int krp_fork_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    struct task_struct* forked_task;
    s64 my_num_handlers = atomic64_add_return(1, &num_handlers);
    s64 my_num_fork = atomic64_add_return(1, &num_fork);

    rcu_read_lock();

    printk(KERN_INFO "Fork handler called in %s with pid %d in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_fork);

    forked_task = (struct task_struct*) regs_return_value(regs);

    printk(KERN_INFO "Forking pid %d to %d in CPU %d %lld:%lld\n", current->pid, forked_task->pid, smp_processor_id(), my_num_handlers, my_num_fork);

    if(peekfs_add_task(forked_task) != 0) {
        printk(KERN_WARNING "Could not add task %s with pid %d to peekable task list in CPU %d %lld:%lld\n", forked_task->comm, forked_task->pid, smp_processor_id(), my_num_handlers, my_num_fork);
    }

    printk(KERN_INFO "Fork handler done in %s with pid %d in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_fork);

    rcu_read_unlock();

    return 0;
}

static int krp_exec_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    s64 my_num_handlers = atomic64_add_return(1, &num_handlers);
    s64 my_num_exec = atomic64_add_return(1, &num_exec);

    rcu_read_lock();

    printk(KERN_INFO "Exec handler for %s with pid %d in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_exec);

    if(peekfs_update_task(current) != 0) {
        printk(KERN_WARNING "Could not update task %s with pid %d in peekable task list in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_exec);
    }

    printk(KERN_INFO "Exec handler done for %s with pid %d in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_exec);

    rcu_read_unlock();

    return 0;
}

static int krp_exit_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    s64 my_num_handlers = atomic64_add_return(1, &num_handlers);
    s64 my_num_exit = atomic64_add_return(1, &num_exit);

    rcu_read_lock();

    printk(KERN_INFO "Exit handler for %s with pid %d in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_exit);

    if(peekfs_remove_task_by_pid(current->pid) != 0) {
        printk(KERN_WARNING "Could not remove task %s with pid %d from peekable task list in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_exit);
    }

    printk(KERN_INFO "Exit handler done for %s with pid %d in CPU %d %lld:%lld\n", current->comm, current->pid, smp_processor_id(), my_num_handlers, my_num_exit);

    rcu_read_unlock();

    return 0;
}

static int peekfs_register_kprobes(void) {
    int retval;

    retval = register_kretprobe(&krp_exit);

    if(retval < 0) {
        printk(KERN_INFO "Registering exit kretprobe failed, returned %d\n", retval);
        goto err_register_kprobes_exit;
    }

    retval = register_kretprobe(&krp_fork);

    if(retval < 0) {
        printk(KERN_INFO "Registering fork kretprobe failed, returned %d\n", retval);
        goto err_register_kprobes_fork;
    }

    retval = register_kretprobe(&krp_exec);

    if(retval < 0) {
        printk(KERN_INFO "Registering exec kretprobe failed, returned %d\n", retval);
        goto err_register_kprobes_exec;
    }

    return 0;
    // Normally unreachable cleanup routines
    unregister_kretprobe(&krp_exec);
err_register_kprobes_exec:
    unregister_kretprobe(&krp_fork);
err_register_kprobes_fork:
    unregister_kretprobe(&krp_exit);
err_register_kprobes_exit:
    return 1;
}

static void peekfs_remove_kprobes(void) {
    unregister_kretprobe(&krp_exit);
    unregister_kretprobe(&krp_fork);
    unregister_kretprobe(&krp_exec);
}

static int __init peekfs_init(void) {
    printk(KERN_INFO "Initializing PeekFS\n");

    printk(KERN_INFO "Initializing proc filesystem base\n");
    proc_main = proc_mkdir(PEEKFS_MAIN_DIR, NULL);

    if(unlikely(!proc_main)) {
        printk(KERN_ERR "Error creating proc filesystem base\n");
        goto err_proc_mkdir;
    }

    // Do the initial peekable task list initialization
    printk(KERN_INFO "Initializing peekable task list\n");
    if(unlikely(peekfs_refresh_task_list() != 0)) {
        printk(KERN_ERR "Could not initialize the peekable task list\n");
        goto err_init_task_list;
    }

    // Register the kprobes
    printk(KERN_INFO "Registering kprobes\n");
    if(unlikely(peekfs_register_kprobes() != 0)) {
        printk(KERN_ERR "Could not register kprobes\n");
        goto err_register_kprobes;
    }

    return 0;

    // Error handlers that should not be encountered during normal execution
    peekfs_remove_kprobes();

err_register_kprobes:
    peekfs_clear_task_list();

err_init_task_list:
    proc_remove(proc_main);

err_proc_mkdir:
    return -1;
}

static void __exit peekfs_exit(void) {
    printk(KERN_INFO "Stopping PeekFS\n");

    printk(KERN_INFO "Removing kprobes\n");
    peekfs_remove_kprobes();

    printk(KERN_INFO "Destroying peekable task list\n");

    peekfs_clear_task_list();
    printk(KERN_INFO "Destroying proc filesystem\n");

    proc_remove(proc_main);
    printk(KERN_INFO "Cleanup done, exiting PeekFS\n");
}

module_init(peekfs_init);
module_exit(peekfs_exit);
