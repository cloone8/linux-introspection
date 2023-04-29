#include <linux/bug.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/delay.h>

#include <process.h>
#include <peekfs.h>
#include <isdata.h>
#include <debug.h>

/*
    TODO: Use get_task_comm instead of raw task->comm
    TODO: Use proper linux error codes (EINVAL, ENOMEM, etc.)
*/

static LIST_HEAD(peekable_process_list);

DEFINE_MUTEX(peekable_process_list_mtx);

// Pre-define internal functions
static struct isdata_section* find_isdata_section_for_vma(struct vm_area_struct* vma, struct mm_struct* mm);
static int check_task_peekable(struct task_struct *task, struct list_head *isdata_sections);
static struct peekable_process *register_task_if_peekable(struct task_struct *task);
static struct peekable_process *create_peekable_process(struct task_struct *task);
static struct peekable_process *find_process_in_list(pid_t pid);
static void remove_isdata_sections(struct list_head *isdata_sections);
static void remove_peekable_process(struct peekable_process *process);
static void clear_peekable_processes(void);

static struct peekable_process *create_peekable_process(struct task_struct *task) {
    char name_buf[PEEKFS_SMALLBUFSIZE] = {0};
    struct proc_dir_entry *task_entry;
    struct peekable_process *new_entry;
    int retval;

    retval = snprintf(name_buf, PEEKFS_SMALLBUFSIZE - 1, "%d", task->pid);

    if(unlikely(retval >= PEEKFS_SMALLBUFSIZE)) {
        // Bad, but not fatal
        printk(KERN_WARNING "Process PID truncated: %d\n", retval);
    }

    task_entry = proc_mkdir(name_buf, proc_main);

    if(unlikely(task_entry == NULL)) {
        printk(KERN_ERR "Could not create proc entry for task\n");
        return NULL;
    }

    new_entry = kmalloc(sizeof(struct peekable_process), GFP_KERNEL);

    if(unlikely(new_entry == NULL)) {
        printk(KERN_ERR "Could not allocate task struct\n");
        proc_remove(task_entry);
        return NULL;
    }

    new_entry->proc_entry = task_entry;
    new_entry->pid = task->pid;

    list_add(&new_entry->list, &peekable_process_list);

    return new_entry;
}

/**
 * Tries to register the given task to the list of peekable processes, if the task
 * actually contains introspection metadata.
 *
 * Returns the peekable process if OK and the task was peekable, returns NULL
 * if OK and the task was not peekable, and returns an ERR_PTR if error
 */
static struct peekable_process *register_task_if_peekable(struct task_struct *task) {
    struct peekable_process *to_ret = NULL;
    struct list_head found_isdata_sections = LIST_HEAD_INIT(found_isdata_sections);
    int retval;

    retval = check_task_peekable(task, &found_isdata_sections);

    if(retval > 0) {
        // Task is peekable! Try to parse it
        struct mm_struct *task_mm;

        to_ret = create_peekable_process(task);

        if(unlikely(to_ret == NULL)) {
            printk(KERN_ERR "Could not register task %d (%s) in peekfs\n", task->pid, task->comm);
            goto ret_err;
        }

        task_mm = get_task_mm(task);

        if(unlikely(task_mm == NULL)) {
            printk(KERN_ERR "Could not get task mm for task %d (%s)\n", task->pid, task->comm);
            goto ret_err;
        }

        retval = peekfs_parse_isdata_sections(to_ret, &found_isdata_sections, task_mm);
        mmput(task_mm);

        if(unlikely(retval != 0)) {
            printk(KERN_ERR "Could not parse task %d (%s) isdata sections\n", task->pid, task->comm);
            goto ret_err;
        }
    } else if(unlikely(retval < 0)) {
        printk(KERN_ERR "Could not check task %d (%s) for peekability: %d\n", task->pid, task->comm, retval);
        goto ret_err;
    }

ret:
    remove_isdata_sections(&found_isdata_sections);
    return to_ret;

ret_err:
    if (to_ret != NULL) {
        remove_peekable_process(to_ret);
    }

    to_ret = ERR_PTR(-EINVAL);
    goto ret;
}

static struct peekable_process *find_process_in_list(pid_t pid) {
    struct list_head *node;

    list_for_each(node, &peekable_process_list) {
        struct peekable_process *entry = container_of(node, struct peekable_process, list);

        if(entry->pid == pid) {
            return entry;
        }
    }

    return NULL;
}

static void remove_isdata_sections(struct list_head *isdata_sections) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, isdata_sections) {
        struct isdata_section *isdata_section = container_of(cur, struct isdata_section, list);
        list_del(&isdata_section->list);
        kfree(isdata_section->bin_path);
        kfree(isdata_section);
    }
}

static void remove_peekable_process(struct peekable_process *process) {
    peekfs_assert(process != NULL);
    peekfs_assert(!list_entry_is_head(process, &peekable_process_list, list));

    proc_remove(process->proc_entry);
    list_del(&process->list);
    kfree(process);
}

static void clear_peekable_processes(void) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, &peekable_process_list) {
        struct peekable_process *task = container_of(cur, struct peekable_process, list);
        remove_peekable_process(task);
    }
}

static struct isdata_section* find_isdata_section_for_vma(struct vm_area_struct* vma, struct mm_struct* mm) {
    struct isdata_section *found_section;
    struct file *vma_file;
    char *vma_file_path;
    size_t vma_file_path_len;
    long gup_retval;
    ssize_t strscpy_retval;
    int mm_locked = 1;
    struct page *first_page;
    elf_ehdr *elf_hdr;
    void __user *isdata_start;
    char path_buf[PEEKFS_BIGBUFSIZE] = {0}; // +1 so we always keep a null terminator

    peekfs_assert(vma != NULL);
    peekfs_assert(mm != NULL);

    // Check if the VMA is backed by a file
    vma_file = vma->vm_file;

    if(!vma_file) {
        // Nope, no file backing. Must be anonymous memory, so it won't
        // contain introspection metadata
        return NULL;
    }

    if(vma->vm_pgoff != 0) {
        // The VMA is backed by a file, but it points to the middle of one.
        // Very unlikely we'll find an ELF header there
        return NULL;
    }

    vma_file_path = d_path(&vma_file->f_path, path_buf, PEEKFS_BIGBUFSIZE);

    if(unlikely(IS_ERR(vma_file_path) || ((vma_file_path_len = strnlen(vma_file_path, PEEKFS_BIGBUFSIZE)) == PEEKFS_BIGBUFSIZE))) {
        // In addition to checking whether d_path returned an error, make sure the buffer had enough space
        printk(KERN_WARNING "Error reading filepath for VMA %p->%p: %ld\n", (void *)vma->vm_start, (void *)vma->vm_end, PTR_ERR(vma_file_path));
        return IS_ERR(vma_file_path) ? vma_file_path : ERR_PTR(-ENOMEM);
    }

    gup_retval = get_user_pages_remote(mm, vma->vm_start, 1, 0, &first_page, NULL, &mm_locked);

    if(!mm_locked) {
        // If something went wrong and the lock was left unlocked, re-lock it
        mmap_read_lock(mm);
    }

    if(unlikely(gup_retval <= 0)) {
        printk(KERN_WARNING "Error retrieving memory for VMA %p->%p\n", (void*)vma->vm_start, (void*)vma->vm_end);
        return gup_retval < 0 ? ERR_PTR(gup_retval) : ERR_PTR(-EIO);
    }

    elf_hdr = kmap(first_page);

    if(!is_elf_header(elf_hdr) || unlikely(!ehdr_arch_compatible(elf_hdr))) {
        // The beginning of the file does not contain an ELF header
        kunmap(first_page);
        put_page(first_page);
        return NULL;
    }

    isdata_start = peekfs_get_isdata_section_start(mm, elf_hdr);

    kunmap(first_page);
    put_page(first_page);

    if(unlikely(IS_ERR(isdata_start))) {
        printk(KERN_WARNING "Error finding isdata start for VMA %p->%p\n", (void*)vma->vm_start, (void*)vma->vm_end);
        return isdata_start;
    }

    if(isdata_start == NULL) {
        return NULL;
    }

    // Okay! We found the isdata section. This process is definitely peekable.
    found_section = kmalloc(sizeof(struct isdata_section), GFP_KERNEL);

    if(unlikely(found_section == NULL)) {
        return ERR_PTR(-ENOMEM);
    }

    found_section->isdata_start = isdata_start;
    found_section->bin_path = kmalloc((vma_file_path_len + 1) * sizeof(char), GFP_KERNEL);

    if(unlikely(found_section->bin_path == NULL)) {
        kfree(found_section);
        return ERR_PTR(-ENOMEM);
    }

    strscpy_retval = strscpy(found_section->bin_path, vma_file_path, vma_file_path_len + 1);
    peekfs_assert(strscpy_retval != -E2BIG);

    return found_section;
}

/**
 * Checks whether the given task is peekable by looking for valid .isdata
 * sections in each of the binaries of the task's memory space.
 *
 * Returns the amount of valid isdata sections found, or a -ERRVAL
 */
static int check_task_peekable(struct task_struct *task, struct list_head *isdata_sections) {
    int retval = 0;
    struct mm_struct *mm;
    struct vm_area_struct *vma, *vma_next;

    peekfs_assert(list_empty(isdata_sections)); // The incoming list of isdata_sections must be empty

    // Acquire the task mm
    mm = get_task_mm(task);

    if(mm == NULL) {
        // Task dying or has no mem space, so not peekable
        return 0;
    }

    mmap_read_lock(mm);
    down_read(&mm->mmap_lock);

    // Go through all VMAs and try to find the ones backed by a file.
    // For these file-backed VMAs, try to see if they contain introspectable data
    vma_next = mm->mmap;
    while(vma_next) {
        struct isdata_section* found_section;

        // Prep for next iteration
        vma = vma_next;
        vma_next = vma->vm_next;

        found_section = find_isdata_section_for_vma(vma, mm);

        if(unlikely(IS_ERR(found_section))) {
            printk(KERN_WARNING "Could not check VMA %p->%p in task %d (%s) for peekability: %ld\n", (void*)vma->vm_start, (void*)vma->vm_end, task->pid, task->comm, PTR_ERR(found_section));
            continue;
        }

        if(found_section != NULL) {
            // Found an isdata section!
            list_add(&found_section->list, isdata_sections);
            retval++;
        }
    }

    // Release the task mm again
    up_read(&mm->mmap_lock);
    mmap_read_unlock(mm);
    mmput(mm);

    return retval;
}

int peekfs_remove_task_by_pid(pid_t pid) {
    struct peekable_process *process;

    mutex_lock(&peekable_process_list_mtx);

    process = find_process_in_list(pid);

    if(process != NULL) {
        remove_peekable_process(process);
        mutex_unlock(&peekable_process_list_mtx);
        return 0;
    } else {
        mutex_unlock(&peekable_process_list_mtx);
        return 1;
    }
}

int peekfs_add_task(struct task_struct *task) {
    struct peekable_process *ret;

    mutex_lock(&peekable_process_list_mtx);

    printk(KERN_INFO "Trying to register new task, if possible, for PID %d\n", task->pid);
    ret = register_task_if_peekable(task);
    printk(KERN_INFO "Registration for PID %d done. Value: %p, succesful: %d, NULL %d\n", task->pid, ret, !IS_ERR(ret), ret == NULL);

    mutex_unlock(&peekable_process_list_mtx);

    if(unlikely(IS_ERR(ret))) {
        return 1;
    }

    return 1;
}

int peekfs_update_task(struct task_struct *task) {
    struct peekable_process *peekable;

    mutex_lock(&peekable_process_list_mtx);

    peekable = find_process_in_list(task->pid);

    if(peekable != NULL) {
        // If the process is currently peekable, remove it so we can update it
        remove_peekable_process(peekable);
    }

    peekable = register_task_if_peekable(task);

    mutex_unlock(&peekable_process_list_mtx);

    if(unlikely(IS_ERR(peekable))) {
        return 1;
    }

    return 0;
}

void peekfs_clear_task_list(void) {
    mutex_lock(&peekable_process_list_mtx);

    clear_peekable_processes();

    mutex_unlock(&peekable_process_list_mtx);
}

int peekfs_refresh_task_list(void) {
    int to_ret = 0;
    struct task_struct *task;

    mutex_lock(&peekable_process_list_mtx);

    // First, clean the entire list
    clear_peekable_processes();

    // Now add the new ones
    rcu_read_lock();

    for_each_process(task) {
        struct peekable_process *peekable = register_task_if_peekable(task);

        if(IS_ERR(peekable)) {
            goto ret_err;
        }
    }

ret:
    rcu_read_unlock();
    mutex_unlock(&peekable_process_list_mtx);
    return to_ret;

ret_err:
    to_ret = 1;
    clear_peekable_processes();
    goto ret;
}
