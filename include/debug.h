#ifndef __PEEKFS_DEBUG_H__
#define __PEEKFS_DEBUG_H__

#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/smp.h>
#include <linux/delay.h>

#ifdef PEEKFS_DEBUG

    #define peekfs_assert_ret(condition) __peekfs_assert_ret(condition, #condition, __FILE__, __LINE__)
    #define peekfs_assert(condition) __peekfs_assert(condition, #condition, __FILE__, __LINE__)

    static __always_inline int __peekfs_assert_ret(int invariant, char* message, const char* file, const int line) {
        if(unlikely(!invariant)) {
            mdelay(100);
            WARN(true, "(CPU %d) ASSERTION FAILED: %s (%s:%d)", smp_processor_id(), message, file, line);
            mdelay(100);
        }

        return invariant;
    }

    static __always_inline void __peekfs_assert(int invariant, char* message, const char* file, const int line) {
        if(unlikely(!invariant)) {
            mdelay(100);
            WARN(true, "(CPU %d) ASSERTION FAILED: %s (%s:%d)", smp_processor_id(), message, file, line);
            mdelay(100);
        }
    }

#else

    #define peekfs_assert(condition)
    #define peekfs_assert_ret(condition) (1)

#endif

#endif
