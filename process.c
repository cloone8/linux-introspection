#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mmap_lock.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#include <process.h>
#include <peekfs.h>
#include <isdata.h>

#define BUFSIZE (256)

static LIST_HEAD(_peekable_process_list);
static struct list_head* peekable_process_list = &_peekable_process_list;

DEFINE_MUTEX(peekable_process_list_mtx);

struct peekable_process {
    struct list_head list;
    struct task_struct* task;
    struct proc_dir_entry* proc_entry;
    struct list_head isdata_sections;
};

struct isdata_section {
    struct list_head list;
};

static struct peekable_process* register_task(struct task_struct* task) {
    char name_buf[BUFSIZE];
    struct proc_dir_entry* task_entry;
    struct peekable_process* new_entry;

    snprintf(name_buf, BUFSIZE - 1, "%d", task->pid);

    task_entry = proc_mkdir(name_buf, proc_main);

    if(task_entry == NULL) {
        printk(KERN_ERR "Could not create proc entry for task\n");
        return NULL;
    }

    new_entry = kmalloc(sizeof(struct peekable_process), GFP_KERNEL);

    if(new_entry == NULL) {
        printk(KERN_ERR "Could not allocate task struct\n");
        proc_remove(task_entry);
        return NULL;
    }

    new_entry->proc_entry = task_entry;
    new_entry->task = task;
    new_entry->isdata_sections = LIST_HEAD_INIT(new_entry->isdata_sections);
    list_add(&new_entry->list, peekable_process_list);

    return new_entry;
}

static struct peekable_process* find_process_in_list(pid_t pid) {
    struct list_head *node;

    list_for_each(node, peekable_process_list) {
        struct peekable_process* entry = container_of(node, struct peekable_process, list);

        if(entry->task->pid == pid) {
            return entry;
        }
    }

    return NULL;
}

static void remove_peekable_process(struct peekable_process* process) {
    proc_remove(process->proc_entry);
    list_del(&process->list);
    kfree(process);
}

static void clear_peekable_processes(void) {
    struct list_head *cur, *next;

    list_for_each_safe(cur, next, peekable_process_list) {
        struct peekable_process* task = container_of(cur, struct peekable_process, list);
        remove_peekable_process(task);
    }
}

static int update_peekable_process(struct peekable_process* peekable, struct task_struct* task) {
    return 0;
}

static void __user *check_task_peekable(struct task_struct* task) {
    int retval = 0;
    struct mm_struct* mm;
    struct vm_area_struct *vma, *vma_next;
    char path_buf[BUFSIZE + 1] = {0}; // +1 so we always keep a null terminator

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
        struct file* vma_file;
        char* vma_file_path;
        long gup_retval;
        int mm_locked = 1;
        struct page* first_page;
        Elf64_Ehdr* elf_hdr;
        void* isdata_start;

        // Prep for next iteration
        vma = vma_next;
        vma_next = vma->vm_next;

        // Check if the VMA is backed by a file
        vma_file = vma->vm_file;

        if(!vma_file) {
            // Nope, no file backing. Must be anonymous memory, so it won't
            // contain introspection metadata
            printk(KERN_INFO "Process %d (%s) contains VMA from %p->%p NOT backed by file\n", task->pid, task->comm, (void*)vma->vm_start, (void*)vma->vm_end);
            continue;
        }

        if(vma->vm_pgoff == 0) {
            printk(KERN_INFO "Process %d (%s) contains VMA from %p->%p that maps to start of file\n", task->pid, task->comm, (void*)vma->vm_start, (void*)vma->vm_end);
        } else {
            printk(KERN_INFO "Process %d (%s) contains VMA from %p->%p that maps to middle of file\n", task->pid, task->comm, (void*)vma->vm_start, (void*)vma->vm_end);
            continue;
        }

        vma_file_path = d_path(&vma_file->f_path, path_buf, BUFSIZE);

        if(IS_ERR(vma_file_path)) {
            printk(KERN_WARNING "Error reading filepath for VMA %p->%p of process %d (%s): %ld\n", (void*)vma->vm_start, (void*)vma->vm_end, task->pid, task->comm, PTR_ERR(vma_file_path));
            continue;
        }

        printk(KERN_INFO "Process %d (%s) contains VMA from %p->%p backed by file %s\n", task->pid, task->comm, (void*)vma->vm_start, (void*)vma->vm_end, vma_file_path);

        gup_retval = get_user_pages_remote(mm, vma->vm_start, 1, 0, &first_page, NULL, &mm_locked);

        if(!mm_locked) {
            // If something went wrong and the lock was left unlocked, re-lock it
            mmap_read_lock(mm);
        }

        if(gup_retval <= 0) {
            printk(KERN_WARNING "Error retrieving memory from remote process %d (%s)\n", task->pid, task->comm);
            continue;
        }

        elf_hdr = kmap(first_page);

        if(!is_elf_header(elf_hdr)) {
            continue;
        }



        printk(KERN_INFO "Detected ELF header in file %s at %p for process %d (%s)\n", vma_file_path, (void*)vma->vm_start, task->pid, task->comm);

        isdata_start = peekfs_get_isdata_section_start(mm, elf_hdr);

        kunmap(first_page);
        put_page(first_page);

        if(isdata_start != NULL) {
            // Okay! We found the isdata section. This process is definitely peekable.
        }
    }

    // Release the task mm again
check_task_peekable_ret_ok:
    up_read(&mm->mmap_lock);
    mmap_read_unlock(mm);
    mmput(mm);

    return retval;
}

int peekfs_remove_task_by_pid(pid_t pid) {
    struct peekable_process* process;

    process = find_process_in_list(pid);

    if(process != NULL) {
        remove_peekable_process(process);
        return 0;
    } else {
        return 1;
    }
}

int peekfs_add_task(struct task_struct* task) {
    struct peekable_process* ret;

    mutex_lock(&peekable_process_list_mtx);
    ret = register_task(task);
    mutex_unlock(&peekable_process_list_mtx);

    if(ret != NULL) {
        return 0;
    }

    return 1;
}

int peekfs_update_task(struct task_struct* task) {
    struct peekable_process* peekable;
    int update_ret;
    int retval = 0;

    mutex_lock(&peekable_process_list_mtx);

    peekable = find_process_in_list(task->pid);

    if(peekable == NULL) {
        retval = 1;
        goto update_task_ret;
    }

    update_ret = update_peekable_process(peekable, task);

    if(update_ret != 0) {
        retval = 2;
        goto update_task_ret;
    }

update_task_ret:
    mutex_unlock(&peekable_process_list_mtx);
    return retval;
}

void peekfs_clear_task_list(void) {
    mutex_lock(&peekable_process_list_mtx);

    clear_peekable_processes();

    mutex_unlock(&peekable_process_list_mtx);
}

int peekfs_refresh_task_list(void) {
    struct task_struct* task;

    mutex_lock(&peekable_process_list_mtx);

    // First, clean the entire list
    clear_peekable_processes();

    // Now add the new ones
    rcu_read_lock();

    for_each_process(task) {
        if(check_task_peekable(task)) {
            // Task is peekable. Try to register it for introspection
            if(register_task(task) == NULL) {
                // Registration failed!
                printk(KERN_ERR "Could not register task %d in peekfs\n", task->pid);

                // Clear the list, something went wrong!
                rcu_read_unlock();
                clear_peekable_processes();
                mutex_unlock(&peekable_process_list_mtx);
                return 1;
            }
        }
    }

    rcu_read_unlock();
    mutex_unlock(&peekable_process_list_mtx);
    return 0;
}
