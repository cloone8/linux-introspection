#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>

#include <peekfs.h>
#include <process.h>
#include <peek_ops.h>

static ssize_t read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    unsigned long retval;
    struct inode* this_inode;
    struct peekable_module* mod_info;
    struct peekable_process* process;
    struct pid* pid;
    void __user* data_pointer;
    size_t to_read;

    this_inode = file_inode(file);
    data_pointer = pde_data(this_inode);
    mod_info = proc_get_parent_data(this_inode);
    pid = mod_info->owner;
    process = peekfs_get_process(pid, 0);

    if(unlikely(IS_ERR(process))) {
        return PTR_ERR(process);
    }

    if(unlikely(!process)) {
        return -ESRCH;
    }

    // to_read = min(count, )

    // retval = copy_to_user(buf, hello, len);

    if(retval) {
        return -EFAULT;
    }
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
