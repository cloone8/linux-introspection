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
#include <log.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PeekFS introspection filesystem");

// Some bookkeeping, useful for debugging
static atomic64_t num_handlers = ATOMIC_INIT(0);
static atomic64_t num_fork = ATOMIC_INIT(0);
static atomic64_t num_exec = ATOMIC_INIT(0);
static atomic64_t num_exit = ATOMIC_INIT(0);
static atomic64_t num_active = ATOMIC_INIT(0);

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
    char cur_task_name[TASK_COMM_LEN];
    char forked_task_name[TASK_COMM_LEN];
    s64 my_num_handlers = atomic64_add_return(1, &num_handlers);
    s64 my_num_fork = atomic64_add_return(1, &num_fork);

    atomic64_inc(&num_active);

    rcu_read_lock();

    get_task_comm(cur_task_name, current);

    log_info("Fork handler called in %s with pid %d in CPU %d %lld:%lld\n", cur_task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_fork);

    forked_task = (struct task_struct*) regs_return_value(regs);

    if(unlikely(IS_ERR(forked_task))) {
        log_info("Forking pid %d failed (%ld), handler doing nothing\n", current->pid, PTR_ERR(forked_task));
    } else {
        get_task_comm(forked_task_name, forked_task);

        log_info("Forking pid %d to %d in CPU %d %lld:%lld\n", current->pid, forked_task->pid, smp_processor_id(), my_num_handlers, my_num_fork);

        // Not the current task, who knows what's going on with it and who else is scheduling it. Let's make sure
        // it doesn't get cleaned
        get_task_struct(forked_task);

        if(peekfs_add_task(forked_task) != 0) {
            log_warn("Could not add task %s with pid %d to peekable task list in CPU %d %lld:%lld\n", forked_task_name, forked_task->pid, smp_processor_id(), my_num_handlers, my_num_fork);
        }

        put_task_struct(forked_task);
    }

    log_info("Fork handler done in %s with pid %d in CPU %d %lld:%lld\n", cur_task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_fork);

    rcu_read_unlock();
    atomic64_dec(&num_active);
    return 0;
}

static int krp_exec_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    char task_name[TASK_COMM_LEN] = {0};
    s64 my_num_handlers = atomic64_add_return(1, &num_handlers);
    s64 my_num_exec = atomic64_add_return(1, &num_exec);
    atomic64_inc(&num_active);

    rcu_read_lock();

    get_task_comm(task_name, current);

    log_info("Exec handler for %s with pid %d in CPU %d %lld:%lld\n", task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_exec);

    if(unlikely(fatal_signal_pending(current))) {
        // Something went wrong during exec, skip the handler
        log_info("Error during exec call for %s with pid %d, skipping handler\n", task_name, current->pid);
    } else {
        if(peekfs_update_task(current) != 0) {
            log_warn("Could not update task %s with pid %d in peekable task list in CPU %d %lld:%lld\n", task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_exec);
        }
    }

    log_info("Exec handler done for %s with pid %d in CPU %d %lld:%lld\n", task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_exec);

    rcu_read_unlock();

    atomic64_dec(&num_active);
    return 0;
}

static int krp_exit_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    char task_name[TASK_COMM_LEN] = {0};
    s64 my_num_handlers = atomic64_add_return(1, &num_handlers);
    s64 my_num_exit = atomic64_add_return(1, &num_exit);
    atomic64_inc(&num_active);

    rcu_read_lock();

    get_task_comm(task_name, current);

    log_info("Exit handler for %s with pid %d in CPU %d %lld:%lld\n", task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_exit);

    if(peekfs_remove_task_by_pid(current->pid) != 0) {
        log_warn("Could not remove task %s with pid %d from peekable task list in CPU %d %lld:%lld\n", task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_exit);
    }

    log_info("Exit handler done for %s with pid %d in CPU %d %lld:%lld\n", task_name, current->pid, smp_processor_id(), my_num_handlers, my_num_exit);

    rcu_read_unlock();

    atomic64_dec(&num_active);
    return 0;
}

static int peekfs_register_kprobes(void) {
    int retval;

    retval = register_kretprobe(&krp_exit);

    if(retval < 0) {
        log_info("Registering exit kretprobe failed, returned %d\n", retval);
        goto err_register_kprobes_exit;
    }

    retval = register_kretprobe(&krp_fork);

    if(retval < 0) {
        log_info("Registering fork kretprobe failed, returned %d\n", retval);
        goto err_register_kprobes_fork;
    }

    retval = register_kretprobe(&krp_exec);

    if(retval < 0) {
        log_info("Registering exec kretprobe failed, returned %d\n", retval);
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
    return retval;
}

static void peekfs_remove_kprobes(void) {
    unregister_kretprobe(&krp_exit);
    unregister_kretprobe(&krp_fork);
    unregister_kretprobe(&krp_exec);
}

static int __init peekfs_init(void) {
    int retval = 0;

    log_info("Initializing PeekFS\n");

    log_info("Initializing proc filesystem base\n");
    proc_main = proc_mkdir(PEEKFS_MAIN_DIR, NULL);

    if(unlikely(!proc_main)) {
        log_err("Error creating proc filesystem base\n");
        retval = -EIO;
        goto err_proc_mkdir;
    }

    // Do the initial peekable task list initialization
    log_info("Initializing peekable task list\n");
    if(unlikely((retval = peekfs_refresh_task_list()) != 0)) {
        log_err("Could not initialize the peekable task list\n");
        goto err_init_task_list;
    }

    // Register the kprobes
    log_info("Registering kprobes\n");
    if(unlikely((retval = peekfs_register_kprobes()) != 0)) {
        log_err("Could not register kprobes\n");
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
    return retval;
}

static void __exit peekfs_exit(void) {
    s64 handlers_active;
    log_info("Stopping PeekFS\n");

    log_info("Removing kprobes\n");
    peekfs_remove_kprobes();

    log_info("Waiting for all current handlers to exit: %lld\n", atomic64_read(&num_active));

    while((handlers_active = atomic64_read(&num_active)) > 0) {
        log_info("Waiting for %lld...\n", handlers_active);
        mdelay(500);
    }

    log_info("All handlers done\n");

    log_info("Destroying peekable task list\n");

    peekfs_clear_task_list();
    log_info("Destroying proc filesystem\n");

    proc_remove(proc_main);
    log_info("Cleanup done, exiting PeekFS\n");
}

module_init(peekfs_init);
module_exit(peekfs_exit);
