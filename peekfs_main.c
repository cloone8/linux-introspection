#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>
#include <linux/smp.h>
#include <linux/kprobes.h>

#include <peekfs.h>
#include <process.h>
#include <log.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PeekFS introspection filesystem");

// Some bookkeeping, useful for debugging
static atomic64_t num_active = ATOMIC_INIT(0);

// ProcFS related vars
struct proc_dir_entry* proc_main;

// Kprobe related vars
static int krp_exec_handler(struct kretprobe_instance* probe, struct pt_regs* regs);
static int krp_exit_handler(struct kretprobe_instance* probe, struct pt_regs* regs);

struct krp_data {

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

static ssize_t register_write(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos) {
    long retval;
    struct pid* pid;
    void __user* module_hdr;

    log_info("User writing %lu bytes to register file\n", count);

    if(count != sizeof(void*)) {
        // User must write exactly one pointer
        return -EINVAL;
    }

    if(unlikely(copy_from_user(&module_hdr, buffer, sizeof(void*)))) {
        return -EFAULT;
    }

    pid = find_get_pid(current->pid);

    if(unlikely(!pid)) {
        return -ESRCH;
    }

    retval = peekfs_register_module(pid, module_hdr);

    put_pid(pid);

    if(unlikely(retval < 0)) {
        return retval;
    }

    return sizeof(void*);
}

static struct proc_ops register_ops = {
    .proc_write = register_write
};

static ssize_t unregister_write(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos) {
    long retval;
    struct pid* pid;
    void __user* module_hdr;

    log_info("User writing %lu bytes to unregister file\n", count);

    if(count != sizeof(void*)) {
        // User must write exactly one pointer
        return -EINVAL;
    }

    if(unlikely(copy_from_user(&module_hdr, buffer, sizeof(void*)))) {
        return -EFAULT;
    }

    pid = find_get_pid(current->pid);

    if(unlikely(!pid)) {
        return -ESRCH;
    }

    retval = peekfs_remove_module(pid, module_hdr);

    if(unlikely(retval != 0)) {
        return retval;
    }

    return sizeof(void*);
}

static struct proc_ops unregister_ops = {
    .proc_write = unregister_write
};

static int krp_exec_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    long retval;
    struct pid* pid;
    char task_name[TASK_COMM_LEN] = {0};
    atomic64_inc(&num_active);

    get_task_comm(task_name, current);
    pid = find_get_pid(current->pid);

    if(unlikely(!pid)) {
        log_warn("Couldn't get local PID for PID %d\n", current->pid);
        goto ret;
    }

    log_info("Exec handler for %s with pid %d in CPU %d\n", task_name, pid_nr(pid), smp_processor_id());

    retval = peekfs_remove_task_by_pid(pid);

    if(unlikely(retval != 0)) {
        log_err("Error trying to remove process %d from peekable process list\n", pid_nr(pid));
    }

    put_pid(pid);
ret:
    atomic64_dec(&num_active);
    return 0;
}

static int krp_exit_handler(struct kretprobe_instance* probe, struct pt_regs* regs) {
    long retval;
    struct pid* pid;
    char task_name[TASK_COMM_LEN] = {0};
    atomic64_inc(&num_active);

    get_task_comm(task_name, current);
    pid = find_get_pid(current->pid);

    if(unlikely(!pid)) {
        log_warn("Couldn't get local PID for PID %d\n", current->pid);
        goto ret;
    }

    log_info("Exit handler for %s with pid %d in CPU %d\n", task_name, pid_nr(pid), smp_processor_id());

    retval = peekfs_remove_task_by_pid(pid);

    if(unlikely(retval != 0)) {
        log_err("Error trying to remove process %d from peekable process list\n", pid_nr(pid));
    }

    put_pid(pid);
ret:
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

    retval = register_kretprobe(&krp_exec);

    if(retval < 0) {
        log_info("Registering exec kretprobe failed, returned %d\n", retval);
        goto err_register_kprobes_exec;
    }

    return 0;
    // Normally unreachable cleanup routines
    unregister_kretprobe(&krp_exec);
err_register_kprobes_exec:
    unregister_kretprobe(&krp_exit);
err_register_kprobes_exit:
    return retval;
}

static void peekfs_remove_kprobes(void) {
    unregister_kretprobe(&krp_exit);
    unregister_kretprobe(&krp_exec);
}

static int __init peekfs_init(void) {
    int retval = 0;
    struct proc_dir_entry *proc_unregister, *proc_register;

    log_info("Initializing PeekFS\n");

    log_info("Initializing proc filesystem base\n");
    proc_main = proc_mkdir(PEEKFS_MAIN_DIR, NULL);

    if(unlikely(!proc_main)) {
        log_err("Error creating proc filesystem base\n");
        retval = -EIO;
        goto err_proc_mkdir;
    }

    log_info("Initializing deregistration proc file\n");
    proc_unregister = proc_create("unregister", 0222, proc_main, &unregister_ops);

    if(unlikely(!proc_unregister)) {
        log_err("Error creating deregistration file\n");
        retval = -EIO;
        goto err_proc_unregister;
    }

    log_info("Initializing registration proc file\n");
    proc_register = proc_create("register", 0222, proc_main, &register_ops);
    if(unlikely(!proc_register)) {
        log_err("Error creating registration file\n");
        retval = -EIO;
        goto err_proc_register;
    }

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
    proc_remove(proc_register);
err_proc_register:
    proc_remove(proc_unregister);
err_proc_unregister:
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
