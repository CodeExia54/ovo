#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/rcupdate.h>

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
#include <linux/dcache.h>
#include <linux/maple_tree.h>

extern char *d_path(const struct path *, char *, int);
#endif

#define ARC_PATH_MAX 256

extern struct mm_struct *get_task_mm(struct task_struct *task);
extern void mmput(struct mm_struct *);

// Ref: https://elixir.bootlin.com/linux/v6.1.57/source/mm/mmap.c#L325
//      https://elixir.bootlin.com/linux/v6.1.57/source/fs/open.c#L998
uintptr_t traverse_vma(struct mm_struct* mm, char* name) {
    struct vm_area_struct *vma;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct ma_state mas = {
		.tree = &mm->mm_mt,
		.index = 0,
		.last = 0,
		.node = MAS_START,
		.min = 0,
		.max = ULONG_MAX,
		.alloc = NULL,
	};

    while ((vma = mas_find(&mas, ULONG_MAX)) != NULL)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
            path_nm = d_path(&(vma->vm_file)->f_path, buf, ARC_PATH_MAX-1);
#else
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
#endif
            pr_info("traverse_vma - path_nm: %s\n", path_nm);
            if (!strcmp(kbasename(path_nm), name)) {
                pr_info("traverse_vma - found: %lx\n", vma->vm_start);
                return vma->vm_start;
            }
        }
    }
    return 0;
}

uintptr_t get_module_base(pid_t pid, char* name) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    rcu_read_lock();
    pid_struct = find_vpid(pid);
    if (!pid_struct) {
        return false;
    }
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        pr_err("get_module_base pid_task failed.\n");
        return false;
    }
    rcu_read_unlock();
#else
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_err("get_module_base find_get_pid failed.\n");
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        pr_err("get_module_base get_pid_task failed.\n");
        return false;
    }
#endif

    mm = get_task_mm(task);
    if (!mm) {
        pr_err("get_module_base get_task_mm failed.\n");
        return false;
    }
    mmput(mm);

    return traverse_vma(mm, name);
}
