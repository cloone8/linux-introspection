#ifndef __PEEKFS_H__
#define __PEEKFS_H__

#include <linux/types.h>
#include <linux/time.h>

#define PEEKFS_MAIN_DIR ("peek")
#define PEEKFS_WORKQUEUE_NAME ("peekfs")
#define PEEKFS_REFRESH_PROCESS_TASK_INTERVAL_MS (1000)
#define PEEKFS_REFRESH_PROCESS_TASK_INTERVAL_JIFFIES (ms_to_jiffies(PEEKFS_REFRESH_PROCESS_TASK_INTERVAL_MS))

static inline unsigned long ms_to_jiffies(int64_t ms) {
    const struct timespec64 as_timespec = ns_to_timespec64(ms * 1000000);

    return timespec64_to_jiffies(&as_timespec);
}

extern struct proc_dir_entry* proc_main;

#endif
