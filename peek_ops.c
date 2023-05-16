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
#include <memutil.h>
#include <log.h>

static long get_proc_structs(struct pid* pid, struct peekable_process** process_ret, struct task_struct** task_ret, struct mm_struct** mm_ret) {
    struct peekable_process* process;
    struct task_struct* process_task;
    struct mm_struct* mm;
    long retval;
    long to_ret = 0;

    peekfs_assert(pid != NULL);
    peekfs_assert(process_ret != NULL);
    peekfs_assert(task_ret != NULL);
    peekfs_assert(mm_ret != NULL);

    // Let's find out what variable and what process has been read
    process = peekfs_get_process(pid, 0);

    if(unlikely(IS_ERR(process))) {
        log_err("Error finding process to be introspected: %ld\n", PTR_ERR(process));
        return PTR_ERR(process);
    }

    if(unlikely(!process)) {
        log_err("Could not find process to be introspected\n");
        return -ESRCH;
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
        goto ret_err;
    }

    // Everything went okay. Assign the return variables
    *process_ret = process;
    *task_ret = process_task;
    *mm_ret = mm;

ret:
    return to_ret;

// Error handling routines
ret_err:
    mmput(mm);
ret_no_mm_put:
    put_task_struct(process_task);
ret_no_task_put:
    up_read(&process->lock);
    goto ret;
}

static ssize_t peekfs_read_handler(
    // Start of normal proc_read handler params
    struct file* file,
    char __user* buf,
    size_t count,
    loff_t* offset,
    // End of normal proc_read handler params, custom params here
    struct peekable_global* entry,
    size_t elem
) {
    ssize_t to_ret = 0;
    long retval;
    void* addr_to_read;
    size_t bytes_to_read;
    struct peekable_process* process;
    struct task_struct* process_task;
    struct mm_struct* mm;
    void* kernel_userdata_buf;
    int mm_locked = 0;

    retval = get_proc_structs(entry->owner_pid, &process, &process_task, &mm);

    if(unlikely(retval != 0)) {
        log_err("Could not get introspection task structs: %ld\n", retval);
        return retval;
    }

    mm_locked = 1;

    // Finally we're done with all the initialization. Let's start actually reading the data
    if((*offset) >= entry->size) {
        // Trying to read beyond EOF
        to_ret = 0;
        goto ret_no_free_kbuf;
    }

    // addr = base + array_offset + file_offset
    addr_to_read = (void*) (((uintptr_t) entry->addr) + (entry->size * elem) + (*offset));
    bytes_to_read = min(count, (entry->size - (size_t)(*offset)));
    kernel_userdata_buf = kmalloc(bytes_to_read, GFP_KERNEL);

    if(unlikely(!kernel_userdata_buf)) {
        to_ret = -ENOMEM;
        goto ret_no_free_kbuf;
    }

    retval = copy_data_from_userspace(mm, addr_to_read, kernel_userdata_buf, bytes_to_read, &mm_locked);

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
    put_task_struct(process_task);
    up_read(&process->lock);
    return to_ret;
}

static ssize_t peekfs_write_handler(
    // Start of normal proc_write handler params
    struct file* file,
    const char __user* buf,
    size_t count,
    loff_t* offset,
    // End of normal proc_write handler params, custom params here
    struct peekable_global* entry,
    size_t elem
) {
    ssize_t to_ret = 0;
    long retval;
    void* addr_to_write;
    size_t bytes_to_write;
    struct peekable_process* process;
    struct task_struct* process_task;
    struct mm_struct* mm;
    void* kernel_userdata_buf;
    int mm_locked = 0;

    retval = get_proc_structs(entry->owner_pid, &process, &process_task, &mm);

    if(unlikely(retval != 0)) {
        log_err("Could not get introspection task structs: %ld\n", retval);
        return retval;
    }

    mm_locked = 1;

    // Finally we're done with all the initialization. Let's start actually reading the data
    if((*offset) >= entry->size) {
        // Trying to read beyond EOF
        to_ret = 0;
        goto ret_no_free_kbuf;
    }

    // addr = base + array_offset + file_offset
    addr_to_write = (void*) (((uintptr_t) entry->addr) + (entry->size * elem) + (*offset));
    bytes_to_write = min(count, (entry->size - (size_t)(*offset)));
    kernel_userdata_buf = kmalloc(bytes_to_write, GFP_KERNEL);

    if(unlikely(!kernel_userdata_buf)) {
        to_ret = -ENOMEM;
        goto ret_no_free_kbuf;
    }

    retval = copy_from_user(kernel_userdata_buf, buf, bytes_to_write);
    if(unlikely(retval != 0)) {
        log_err("Could not copy data to write to kernelspace\n");
        to_ret = -EFAULT;
        goto ret;
    }

    retval = copy_data_to_userspace(mm, addr_to_write, kernel_userdata_buf, bytes_to_write, &mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Could not write to introspected global: %ld\n", retval);
        to_ret = retval;
        goto ret;
    }

    // Copy was succesful. Increment the offset, and return the amount of bytes that were
    // read
    (*offset) += bytes_to_write;
    to_ret = bytes_to_write;

ret:
    kfree(kernel_userdata_buf);
ret_no_free_kbuf:
    if(mm_locked) {
        mmap_read_unlock(mm);
    }
    mmput(mm);
    put_task_struct(process_task);
    up_read(&process->lock);
    return to_ret;
}


/*
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count.
 */
static int open_handler(struct inode *inode, struct file *file) {
	if(!try_module_get(THIS_MODULE)) {
        log_err("Trying to open file for introspection but mpdule dying\n");
        return -EFAULT;
    }

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

static ssize_t array_read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    return peekfs_read_handler(file, buf, count, offset, proc_get_parent_data(file_inode(file)), (size_t)pde_data(file_inode(file)));
}

static ssize_t array_write_handler(struct file* file, const char __user* buf, size_t count, loff_t* offset) {
    return peekfs_write_handler(file, buf, count, offset, proc_get_parent_data(file_inode(file)), (size_t)pde_data(file_inode(file)));
}

static ssize_t single_read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    return peekfs_read_handler(file, buf, count, offset, pde_data(file_inode(file)), 0);
}

static ssize_t single_write_handler(struct file* file, const char __user* buf, size_t count, loff_t* offset) {
    return peekfs_write_handler(file, buf, count, offset, pde_data(file_inode(file)), 0);
}

struct proc_ops peek_ops_single = {
    .proc_read = single_read_handler,
    .proc_write = single_write_handler,
    .proc_open = open_handler,
    .proc_release = close_handler,
};

struct proc_ops peek_ops_array = {
    .proc_read = array_read_handler,
    .proc_write = array_write_handler,
    .proc_open = open_handler,
    .proc_release = close_handler,
};
