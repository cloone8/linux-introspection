#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include <peekfs.h>
#include <peek_ops.h>

static ssize_t read_handler(struct file* file, char __user* buf, size_t count, loff_t* offset) {
    static int finished = 0;
    unsigned long retval;
    char hello[] = "Hello reader!";
    size_t len = min(count, sizeof(hello));

    if(finished) {
        return 0;
    }

    retval = copy_to_user(buf, hello, len);

    if(retval) {
        return -EFAULT;
    }

    finished = 1;

    return len;
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
    .proc_release = close_handler
};

struct proc_ops* peek_ops = &_peek_ops;
