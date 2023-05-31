#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>

#include <process.h>
#include <peekfs.h>
#include <isdata.h>
#include <debug.h>
#include <log.h>
#include <memutil.h>

static LIST_HEAD(peekable_process_list);

static DECLARE_RWSEM(peekable_process_list_rwsem);

// Pre-define internal functions
static struct peekable_process *create_peekable_process(struct pid* pid);
static struct peekable_module *create_peekable_module(struct peekable_process *owner, void __user* isdata_header);
static struct peekable_process *find_process_in_list(struct pid* pid);
static struct peekable_module *find_module_in_list(struct peekable_process* process, void __user* mod_hdr);
static void remove_peekable_global(struct peekable_module* module, struct peekable_global* global);
static void remove_peekable_module(struct peekable_process *owner, struct peekable_module *module);
static void remove_peekable_process(struct peekable_process *process);
static void clear_peekable_processes(void);
static void calculate_peekable_process_pde_size(struct peekable_process *process);

/**
 * Requires the process write-lock to be held
 */
static void calculate_peekable_process_pde_size(struct peekable_process *process) {
    struct list_head* cur;
    long total_size = 0;

    list_for_each(cur, &process->peekable_modules) {
        struct peekable_module *mod = container_of(cur, struct peekable_module, list);
        total_size += mod->size;
    }

    proc_set_size(process->proc_entry, total_size);
}

/**
 * Requires the owner write-lock to be held
 */
static struct peekable_module *create_peekable_module(struct peekable_process *owner, void __user* isdata_header) {
    struct peekable_module* new_module, *to_ret;
    struct task_struct* owner_task;
    struct mm_struct* mm;
    int mm_locked = 0;
    struct isdata_module mod_hdr;
    long retval;

    owner_task = get_pid_task(owner->pid, PIDTYPE_PID);

    if(unlikely(!owner_task)) {
        return ERR_PTR(-ESRCH);
    }

    mm = get_task_mm(owner_task);

    if(unlikely(!mm)) {
        to_ret = ERR_PTR(-ENXIO);
        goto ret_put_task;
    }

    if(unlikely(mmap_read_lock_killable(mm))) {
        to_ret = ERR_PTR(-EINTR);
        goto ret_put_mm;
    }

    mm_locked = 1;

    retval = copy_data_from_userspace(mm, isdata_header, &mod_hdr, sizeof(struct isdata_module), &mm_locked);

    if(unlikely(retval != 0)) {
        to_ret = ERR_PTR(retval);
        goto ret_unlock;
    }

    if(unlikely(memcmp(isdata_magic_bytes, mod_hdr.magic, ISDATA_MAGIC_BYTES_LEN) != 0)) {
        log_err("Process %d tried to register, but no module header was found\n", pid_nr(owner->pid));
        to_ret = ERR_PTR(-EINVAL);
        goto ret_unlock;
    }

    if(unlikely(mod_hdr.version != ISDATA_VERSION)) {
        log_err("Wrong isdata header version. Detected %hu but supported version is %hu\n", mod_hdr.version, ISDATA_VERSION);
        to_ret = ERR_PTR(-EINVAL);
        goto ret_unlock;
    }

    new_module = parse_isdata_header(owner, isdata_header, mm, &mod_hdr, &mm_locked);

    if(unlikely(IS_ERR(new_module))) {
        log_err("Error parsing isdata header in process %d: %ld\n", pid_nr(owner->pid), PTR_ERR(new_module));
        to_ret = new_module;
        goto ret_unlock;
    }

    retval = parse_isdata_entries(owner, new_module, mm, &mod_hdr, &mm_locked);

    if(unlikely(retval < 0)) {
        log_err("Error parsing entries from isdata header in process %d and module %s: %ld\n", pid_nr(owner->pid), new_module->name, retval);
        remove_peekable_module(owner, new_module);
        to_ret = ERR_PTR(retval);
        goto ret_unlock;
    }

ret_unlock:
    if(mm_locked) {
        mmap_read_unlock(mm);
    }
ret_put_mm:
    mmput(mm);
ret_put_task:
    put_task_struct(owner_task);
    return to_ret;
}

/**
 * Returns a new peekable process and initializes it. The process is returned with the
 * lock in a write-locked state, so the caller can freely modify it without other processes
 * making use of the new peekable proc already.
 *
 * Requires the list-write lock to be held
 */
static struct peekable_process *create_peekable_process(struct pid* pid) {
    char name_buf[PEEKFS_SMALLBUFSIZE] = {0};
    struct proc_dir_entry *task_entry;
    struct peekable_process *new_entry;
    struct mod_dir_entry* mod_dirs;
    int retval;

    retval = snprintf(name_buf, PEEKFS_SMALLBUFSIZE - 1, "%d", pid_nr(pid));

    if(unlikely(retval >= PEEKFS_SMALLBUFSIZE)) {
        log_err("Process PID truncated: %d. Filesystem incoherent\n", retval);
        return ERR_PTR(-E2BIG);
    }

    task_entry = proc_mkdir_data(name_buf, 0555, proc_main, pid);

    if(unlikely(task_entry == NULL)) {
        log_err("Could not create proc entry for task\n");
        return ERR_PTR(-EIO);
    }

    mod_dirs = mde_create(task_entry, NULL);

    if(unlikely(mod_dirs == NULL)) {
        log_err("Could not create mod dirs for task\n");
        proc_remove(task_entry);
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
    new_entry->mod_dirs = mod_dirs;
    INIT_LIST_HEAD(&new_entry->peekable_modules);
    init_rwsem(&new_entry->lock);

    // Pre-lock the process to avoid others making use of it before it's ready
    down_write(&new_entry->lock);

    list_add(&new_entry->list, &peekable_process_list);

    return new_entry;
}

/**
 * Finds a process in the list by PID.
 *
 * Requires the list read-lock to be held
*/
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

/**
 * Finds a module in the given process by its header.
 *
 * Requires the process read-lock to be held
 */
static struct peekable_module *find_module_in_list(struct peekable_process* process, void __user* mod_hdr) {
    struct list_head *node;
    peekfs_assert(process != NULL);

    list_for_each(node, &process->peekable_modules) {
        struct peekable_module *module = container_of(node, struct peekable_module, list);

        if(module->isdata_header == mod_hdr) {
            return module;
        }
    }

    return NULL;
}

/**
 * Removes a peekable module from the given process.
 *
 * Requires the owner peekable_process write-lock to be held
 */
static void remove_peekable_global(struct peekable_module* module, struct peekable_global* global) {
    peekfs_assert(module != NULL);
    peekfs_assert(global != NULL);
    peekfs_assert(!list_entry_is_head(global, &module->peekable_globals, list));

    list_del(&global->list);
    proc_remove(global->proc_entry);
    kfree(global->name);
    kfree(global);
}

/**
 * Removes a peekable module from the given process.
 *
 * Requires the owner write-lock to be held
 */
static void remove_peekable_module(struct peekable_process *owner, struct peekable_module *module) {
    struct list_head *cur, *next;
    peekfs_assert(module != NULL);
    peekfs_assert(owner != NULL);
    peekfs_assert(!list_entry_is_head(module, &owner->peekable_modules, list));

    log_info("Removing module %s from process %u\n", module->name, pid_nr(owner->pid));

    // Do this first, so the process cannot be found anymore
    list_for_each_safe(cur, next, &module->peekable_globals) {
        struct peekable_global *global = container_of(cur, struct peekable_global, list);
        remove_peekable_global(module, global);
    }

    list_del(&module->list);
    proc_remove(module->proc_entry);
    kfree(module->name);
    kfree(module);
}

/**
 * Removes a peekable process from the list
 *
 * Requires the process-write lock and the list-write lock to be held
*/
static void remove_peekable_process(struct peekable_process *process) {
    struct list_head *cur, *next;
    peekfs_assert(process != NULL);
    peekfs_assert(!list_entry_is_head(process, &peekable_process_list, list));

    log_info("Removing process with pid %u\n", pid_nr(process->pid));

    // Do this first, so the process cannot be found anymore
    list_for_each_safe(cur, next, &process->peekable_modules) {
        struct peekable_module *module = container_of(cur, struct peekable_module, list);
        remove_peekable_module(process, module);
    }

    mde_rm(process->mod_dirs);
    list_del(&process->list);

    proc_remove(process->proc_entry);

    put_pid(process->pid);
    kfree(process);
}

/**
 * Clears all peekable processes.
 *
 * Requires the list-write lock to be held, and locks all processes
 * at some point
 */
static void clear_peekable_processes(void) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, &peekable_process_list) {
        struct peekable_process *task = container_of(cur, struct peekable_process, list);
        down_write(&task->lock);
        remove_peekable_process(task);
        // Don't unlock, because the task is gone
    }
}

/**
 * Set access to 0 for read-only, 1 for write
*/
struct peekable_process* peekfs_get_process(struct pid* pid, int access) {
    struct peekable_process* to_ret;

    if(unlikely(down_read_killable(&peekable_process_list_rwsem))) {
        return ERR_PTR(-EINTR);
    }

    to_ret = find_process_in_list(pid);

    if(likely(to_ret)) {
        if(access) {
            if(unlikely(down_write_killable(&to_ret->lock))) {
                up_read(&peekable_process_list_rwsem);
                return ERR_PTR(-EINTR);
            }
        } else {
            if(unlikely(down_read_killable(&to_ret->lock))) {
                up_read(&peekable_process_list_rwsem);
                return ERR_PTR(-EINTR);
            }
        }
    }

    up_read(&peekable_process_list_rwsem);

    return to_ret;
}

/**
 * Tries to remove the peekable process with the given PID.
 * Returns 1 if the process was found and removed, 0 if no process was found
 * and a -ERRVAL if an error was encountered.
 */
long peekfs_remove_task_by_pid(struct pid* pid) {
    struct peekable_process *process;
    down_write(&peekable_process_list_rwsem);

    process = find_process_in_list(pid);

    if(process == NULL) {
        // Process does not exist or is not peekable
        up_write(&peekable_process_list_rwsem);
        return 0;
    }

    down_write(&process->lock);

    remove_peekable_process(process);

    up_write(&peekable_process_list_rwsem);
    return 1;

}

long peekfs_register_module(struct pid* pid, void __user* module_hdr) {
    struct peekable_process* module_owner;
    int new_process_created = 0;
    struct peekable_module* new_module;
    long to_ret = 0;

    if(unlikely(down_write_killable(&peekable_process_list_rwsem))) {
        return -EINTR;
    }

    module_owner = find_process_in_list(pid);

    if(likely(module_owner)) {
        // The process already exists. Lock it, and add a module to it
        if(unlikely(down_write_killable(&module_owner->lock))) {
            to_ret = -EINTR;
            goto ret_unlock_list;
        }
    } else {
        // Process doesn't exist. Add a new one first
        module_owner = create_peekable_process(pid);

        if(IS_ERR(module_owner)) {
            to_ret = PTR_ERR(module_owner);
            goto ret_unlock_list;
        }

        new_process_created = 1;
        // New processes come pre-locked, so no need to do that here
    }

    // At this point, we'll no longer need to modify the list, so we can "downgrade"
    // to a read-only lock. This isn't possible for new processes, as they might
    // have to be removed on-error later
    if(likely(!new_process_created)) {
        downgrade_write(&peekable_process_list_rwsem);
    }

    // Now let's add the module
    new_module = create_peekable_module(module_owner, module_hdr);
    // And re-calculate the total process proc folder size
    calculate_peekable_process_pde_size(module_owner);

    if(unlikely(IS_ERR(new_module))) {
        to_ret = PTR_ERR(new_module);

        if(unlikely(new_process_created)) {
            remove_peekable_process(module_owner);
            goto ret_unlock_list;
        }
    }

    up_write(&module_owner->lock);

ret_unlock_list:
    if(likely(!new_process_created)) {
        up_read(&peekable_process_list_rwsem);
        return to_ret;
    } else {
        up_write(&peekable_process_list_rwsem);
        return to_ret;
    }
}

long peekfs_remove_module(struct pid* pid, void __user* module_hdr) {
    long to_ret = 0;
    struct peekable_process* process;
    struct peekable_module* module;

    down_write(&peekable_process_list_rwsem);

    process = find_process_in_list(pid);

    if(unlikely(!process)) {
        log_err("Attempted to remove module for non-existing process %u\n", pid_nr(pid));
        to_ret = -ESRCH;
        goto ret_no_unlock_proc;
    }

    down_write(&process->lock);

    module = find_module_in_list(process, module_hdr);

    if(unlikely(!module)) {
        log_err("Attempted to remove non-existing module from process %u\n", pid_nr(pid));
        to_ret = -ENXIO;
        goto ret_unlock_proc;
    }

    remove_peekable_module(process, module);

    if(list_empty(&process->peekable_modules)) {
        remove_peekable_process(process);
        goto ret_no_unlock_proc;
    }

ret_unlock_proc:
    up_write(&process->lock);
ret_no_unlock_proc:
    up_write(&peekable_process_list_rwsem);
    return to_ret;

}

long peekfs_clear_task_list(void) {
    down_write(&peekable_process_list_rwsem);
    clear_peekable_processes();
    up_write(&peekable_process_list_rwsem);

    return 0;
}
