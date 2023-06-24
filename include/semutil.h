#ifndef __PEEKFS_SEMUTIL_H__
#define __PEEKFS_SEMUTIL_H__

#include <linux/kernel.h>
#include <linux/rwsem.h>

#include <log.h>
#include <debug.h>

static __always_inline int down_read_atomic(struct rw_semaphore* rwsem, int atomic) {
    if(atomic) {
#ifdef PEEKFS_DEBUG
        uint64_t count = 0;
#endif
        while(1) {
#ifdef PEEKFS_DEBUG
            if((count++ % 100000) == 0 && count != 1) {
                log_warn("down_readatomic iter %llu\n", count - 1);
            }
#endif
            if(down_read_trylock(rwsem) == 1) {
                return 0;
            }
        }
    } else {
        return down_read_interruptible(rwsem);
    }
}

static __always_inline int down_write_atomic(struct rw_semaphore* rwsem, int atomic) {
    if(atomic) {
#ifdef PEEKFS_DEBUG
        uint64_t count = 0;
#endif
        while(1) {
#ifdef PEEKFS_DEBUG
            if((count++ % 100000) == 0 && count != 1) {
                log_warn("down_write_atomic iter %llu\n", count - 1);
            }
#endif
            if(down_write_trylock(rwsem) == 1) {
                return 0;
            }
        }
    } else {
        return down_write_killable(rwsem);
    }
}

#endif
