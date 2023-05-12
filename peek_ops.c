#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/rwsem.h>

#include <peekfs.h>
#include <process.h>
#include <peek_ops.h>
#include <util.h>
#include <log.h>

static ssize_t read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    ssize_t to_ret = 0;
    long retval;
    size_t bytes_to_read;
    struct peekable_global* entry;
    struct peekable_process* process;
    struct task_struct* process_task;
    struct mm_struct* mm;
    void* kernel_userdata_buf;
    int mm_locked = 0;

    // Let's find out what variable and what process has been read
    entry = pde_data(file_inode(file));
    process = peekfs_get_process(entry->owner_pid, 0);

    if(unlikely(IS_ERR(process))) {
        log_err("Error finding process to be introspected: %ld\n", PTR_ERR(process));
        to_ret = PTR_ERR(process);
        goto ret_no_unlock;
    }

    if(unlikely(!process)) {
        log_err("Could not find process to be introspected\n");
        to_ret = -ESRCH;
        goto ret_no_unlock;
    }

    // Okay, now get the kernel task_struct for the process to-be-read
    process_task = get_pid_task(process->pid, PIDTYPE_PID);

    if(unlikely(!process_task)) {
        // Weird, the process must have been killed in the meantime. Remove it
        struct pid* missing_pid = get_pid(process->pid);
        up_read(&process->lock);
        log_err("Could not get process task struct for PID %u\n", pid_nr(missing_pid));

        retval = peekfs_remove_task_by_pid(missing_pid);

        if(unlikely(retval != 1)) {
            if(retval == 0) {
                log_err("Couldn't remove process with PID %u, it was alreay gone\n", pid_nr(missing_pid));
            } else {
                log_err("Couldn't remove process with PID %u, error encountered: %ld\n", pid_nr(missing_pid), retval);
            }
        }

        put_pid(missing_pid);
        to_ret = -ESRCH;
        goto ret_no_task_put;
    }

    // We got the task_struct, now get the memory management struct for it
    mm = get_task_mm(process_task);

    if(unlikely(!mm)) {
        to_ret = -ENXIO;
        goto ret_no_mm_put;
    }

    // ...and lock it
    if(unlikely(mmap_read_lock_killable(mm))) {
        to_ret = -EINTR;
        goto ret_no_free_kbuf;
    }

    mm_locked = 1;

    // Finally we're done with all the initialization. Let's start actually reading the data
    if((*offset) >= entry->size) {
        // Trying to read beyond EOF
        to_ret = 0;
        goto ret_no_free_kbuf;
    }

    bytes_to_read = min(count, (entry->size - (size_t)(*offset)));
    kernel_userdata_buf = kmalloc(bytes_to_read, GFP_KERNEL);

    if(unlikely(!kernel_userdata_buf)) {
        to_ret = -ENOMEM;
        goto ret_no_free_kbuf;
    }

    retval = copy_data_from_userspace(mm, entry->addr + (*offset), kernel_userdata_buf, bytes_to_read, &mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not retrieve introspected global data: %ld\n", retval);
        to_ret = retval;
        goto ret;
    }

    // We succesfully got the data. Copy it to the reader now
    retval = copy_to_user(buf, kernel_userdata_buf, bytes_to_read);

    if(unlikely(retval != 0)) {
        log_err("Could not copy global data to userspace\n");
        to_ret = -EFAULT;
        goto ret;
    }

    // Copy was succesful. Increment the offset, and return the amount of bytes that were
    // read
    (*offset) += bytes_to_read;
    to_ret = bytes_to_read;

ret:
    kfree(kernel_userdata_buf);
ret_no_free_kbuf:
    if(mm_locked) {
        mmap_read_unlock(mm);
    }
    mmput(mm);
ret_no_mm_put:
    put_task_struct(process_task);
ret_no_task_put:
    up_read(&process->lock);
ret_no_unlock:
    return to_ret;
}

/*
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count.
 */
static int open_handler(struct inode *inode, struct file *file) {
	try_module_get(THIS_MODULE);
	return 0;
}

/*
 * The file is closed - again, interesting only because
 * of the reference count.
 */
static int close_handler(struct inode *inode, struct file *file) {
	module_put(THIS_MODULE);
	return 0;
}

static struct proc_ops _peek_ops = {
    .proc_read = read_handler,
    .proc_open = open_handler,
    .proc_release = close_handler,
};

struct proc_ops* peek_ops = &_peek_ops;
