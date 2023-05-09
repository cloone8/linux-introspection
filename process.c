#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/sched/task.h>

#include <process.h>
#include <peekfs.h>
#include <isdata.h>
#include <debug.h>
#include <log.h>
#include <util.h>

static LIST_HEAD(peekable_process_list);

static DECLARE_RWSEM(peekable_process_list_rwsem);

// Pre-define internal functions
static struct peekable_process *create_peekable_process(struct pid* pid);
static struct peekable_module *create_peekable_module(struct peekable_process *owner, void __user* isdata_header);
static struct peekable_process *find_process_in_list(struct pid* pid);
static void remove_peekable_module(struct peekable_process *owner, struct peekable_module *module);
static void remove_peekable_process(struct peekable_process *process);
static void clear_peekable_processes(void);

static struct peekable_module *create_peekable_module(struct peekable_process *owner, void __user* isdata_header) {
    // TODO: Something

    return 0;
}

/**
 * Returns a new peekable process and initializes it. The process is returned with the
 * lock in a write-locked state, so the caller can freely modify it without other processes
 * making use of the new peekable proc already.
 */
static struct peekable_process *create_peekable_process(struct pid* pid) {
    char name_buf[PEEKFS_SMALLBUFSIZE] = {0};
    struct proc_dir_entry *task_entry;
    struct peekable_process *new_entry;
    int retval;

    retval = snprintf(name_buf, PEEKFS_SMALLBUFSIZE - 1, "%d", pid_nr(pid));

    if(unlikely(retval >= PEEKFS_SMALLBUFSIZE)) {
        log_err("Process PID truncated: %d. Filesystem incoherent\n", retval);
        return ERR_PTR(-E2BIG);
    }

    task_entry = proc_mkdir(name_buf, proc_main);

    if(unlikely(task_entry == NULL)) {
        log_err("Could not create proc entry for task\n");
        return ERR_PTR(-EIO);
    }

    new_entry = kmalloc(sizeof(struct peekable_process), GFP_KERNEL);

    if(unlikely(new_entry == NULL)) {
        log_err("Could not allocate task struct\n");
        proc_remove(task_entry);
        return ERR_PTR(-ENOMEM);
    }

    // Initialization was okay! Make sure to register our new struct pid reference
    get_pid(pid);

    new_entry->proc_entry = task_entry;
    new_entry->pid = pid;
    INIT_LIST_HEAD(&new_entry->peekable_modules);
    init_rwsem(&new_entry->lock);

    // Pre-lock the process to avoid others making use of it before it's ready
    down_write(&new_entry->lock);

    list_add(&new_entry->list, &peekable_process_list);

    return new_entry;
}

static struct peekable_process *find_process_in_list(struct pid* pid) {
    struct list_head *node;

    list_for_each(node, &peekable_process_list) {
        struct peekable_process *entry = container_of(node, struct peekable_process, list);

        if(entry->pid == pid) {
            return entry;
        }
    }

    return NULL;
}

static void remove_peekable_module(struct peekable_process *owner, struct peekable_module *module) {
    peekfs_assert(module != NULL);
    peekfs_assert(owner != NULL);
    peekfs_assert(!list_entry_is_head(module, &owner->peekable_modules, list));

    list_del(&module->list);
    proc_remove(module->proc_entry);
    kfree(module);
}

static void remove_peekable_process(struct peekable_process *process) {
    struct list_head *cur, *next;
    peekfs_assert(process != NULL);
    peekfs_assert(!list_entry_is_head(process, &peekable_process_list, list));

    list_for_each_safe(cur, next, &process->peekable_modules) {
        struct peekable_module *module = container_of(cur, struct peekable_module, list);
        remove_peekable_module(process, module);
    }

    list_del(&process->list);
    proc_remove(process->proc_entry);

    put_pid(process->pid);
    kfree(process);
}

static void clear_peekable_processes(void) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, &peekable_process_list) {
        struct peekable_process *task = container_of(cur, struct peekable_process, list);
        // TODO: Lock process being cleared
        remove_peekable_process(task);
    }
}

/**
 * Tries to remove the peekable process with the given PID.
 * Returns 1 if the process was found and removed, 0 if no process was found
 * and a -ERRVAL if an error was encountered.
 */
long peekfs_remove_task_by_pid(struct pid* pid) {
    struct peekable_process *process;

    down_read(&peekable_process_list_rwsem);

    process = find_process_in_list(pid);

    if(unlikely(process != NULL)) {
        // Okay, we know the process is peekable. Unlock, then upgrade
        // the lock to the writable variant (and re-check whether the process is
        // still there)

        up_read(&peekable_process_list_rwsem);
        down_write(&peekable_process_list_rwsem);
        process = find_process_in_list(pid);

        if(unlikely(process == NULL)) {
            // Someone else deleted the process in the meantime. Just return
            up_write(&peekable_process_list_rwsem);
            return 0;
        }

        // TODO: Lock process being cleared
        remove_peekable_process(process);

        up_write(&peekable_process_list_rwsem);
        return 1;
    } else {

        up_read(&peekable_process_list_rwsem);
        return 0;
    }
}

long peekfs_register_module(struct pid* pid, void __user* module_hdr) {
    struct peekable_process* module_owner;
    int new_process;
    struct peekable_module* new_module;
    int to_ret = 0;

    if(unlikely(down_write_killable(&peekable_process_list_rwsem))) {
        return -EINTR;
    }

    module_owner = find_process_in_list(pid);

    if(likely(module_owner)) {
        new_process = 0;
        // The process already exists. Lock it, and add a module to it
        if(unlikely(down_write_killable(&module_owner->lock))) {
            to_ret = -EINTR;
            goto ret_unlock_list;
        }
    } else {
        new_process = 1;
        // Process doesn't exist. Add a new one first
        module_owner = create_peekable_process(pid);

        if(IS_ERR(module_owner)) {
            to_ret = PTR_ERR(module_owner);
            goto ret_unlock_list;
        }

        // New processes come pre-locked, so no need to do that here
    }

    // Now let's add the module
    new_module = create_peekable_module(module_owner, module_hdr);

    if(unlikely(IS_ERR(new_module))) {
        to_ret = PTR_ERR(new_module);

        if(new_process) {
            remove_peekable_process(module_owner);
            goto ret_unlock_list;
        } else {
            goto ret_unlock_all;
        }
    }

ret_unlock_all:
    up_write(&module_owner->lock);
ret_unlock_list:
    // TODO: We can probably unlock this a whole lot earlier
    up_write(&peekable_process_list_rwsem);
    return to_ret;
}

long peekfs_remove_module(struct pid* pid, void __user* module_hdr) {
    int to_ret = 0;
    down_write(&peekable_process_list_rwsem);

    up_write(&peekable_process_list_rwsem);
    return to_ret;
}

long peekfs_clear_task_list(void) {
    down_write(&peekable_process_list_rwsem);
    clear_peekable_processes();
    up_write(&peekable_process_list_rwsem);

    return 0;
}
