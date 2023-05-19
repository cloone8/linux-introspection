#include <linux/kernel.h>
#include <linux/module.h>

#include <debug.h>
#include <log.h>

#include "internal.h"

/*
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count.
 */
int open_handler(struct inode *inode, struct file *file) {
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
int close_handler(struct inode *inode, struct file *file) {
	module_put(THIS_MODULE);
	return 0;
}
