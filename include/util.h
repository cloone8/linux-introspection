#ifndef __PEEKFS_UTIL_H__
#define __PEEKFS_UTIL_H__

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <debug.h>

#define mutex_lock_or_ret(lock) { \
        int __mutex_lock_or_ret_retval = mutex_lock_killable(lock); \
                                                                            \
        if(unlikely(__mutex_lock_or_ret_retval != 0)) { \
            log_err("Lock interrupted in %s::%s line %d with return value %d\n", __FILE__, __FUNCTION__, __LINE__, __mutex_lock_or_ret_retval); \
            return __mutex_lock_or_ret_retval; \
        } \
    }

#endif
