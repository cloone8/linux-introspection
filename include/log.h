#ifndef __PEEKFS_LOG_H__
#define __PEEKFS_LOG_H__

#include <linux/kernel.h>
#include <linux/delay.h>

#include <debug.h>

#ifdef PEEKFS_DEBUG
    #define __peekfs_log(level, fmt, ...) printk(level "peekfs: " fmt, ##__VA_ARGS__); udelay(300)
#else
    #define __peekfs_log(level, fmt, ...) printk(level "peekfs: " fmt, ##__VA_ARGS__)
#endif

#define log_info(fmt, ...) __peekfs_log(KERN_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) __peekfs_log(KERN_WARNING, fmt, ##__VA_ARGS__)
#define log_err(fmt, ...) __peekfs_log(KERN_ERR, fmt, ##__VA_ARGS__)

#endif
