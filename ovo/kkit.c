//
// Created by fuqiuluo on 25-1-22.
//
#include <linux/kprobes.h>
#include "kkit.h"

static struct kprobe kp_get_cmdline;
static int (*my_get_cmdline)(struct task_struct *task, char *buffer, int buflen) = NULL;

/* kprobe pre-handler for get_cmdline: log call info but do not call original */
static int get_cmdline_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];
    char *buffer = (char *)regs->regs[1];
    int buflen = (int)regs->regs[2];

    pr_info("[ovo] get_cmdline called at address %p\n", p->addr);
    pr_info("[ovo] args: task=%p pid=%d comm=%s buffer=%p buflen=%d\n",
            task,
            task ? task->pid : -1,
            task ? task->comm : "NULL",
            buffer,
            buflen);

    /* Allow original get_cmdline to execute normally */
    return 0;
}


int ovo_flip_open(const char *filename, int flags, umode_t mode, struct file **f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char *filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open = (struct file* (*)(const char *filename, int flags, umode_t mode))ovo_kallsyms_lookup_name("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

int ovo_flip_close(struct file **f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static struct file* (*reserve_flip_close)(struct file **f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file* (*)(struct file **f, fl_owner_t id))ovo_kallsyms_lookup_name("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
#endif
}

bool is_file_exist(const char *filename) {
    struct file* fp;

    if(ovo_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            ovo_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

    return false;
}

unsigned long ovo_kallsyms_lookup_name(const char *symbol_name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        struct kprobe kp = {
                .symbol_name = "kallsyms_lookup_name"
        };

        if(register_kprobe(&kp) < 0) {
            return 0;
        }
        lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
    }
    return lookup_name(symbol_name);
#else
    return kallsyms_lookup_name(symbol_name);
#endif
}

unsigned long *ovo_find_syscall_table(void) {
    unsigned long *syscall_table;
    syscall_table = (unsigned long*)ovo_kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

int mark_pid_root(pid_t pid) {
    static struct cred* (*my_prepare_creds)(void) = NULL;

    struct pid * pid_struct;
    struct task_struct *task;
    kuid_t kuid;
    kgid_t kgid;
    struct cred *new_cred;

    kuid = KUIDT_INIT(0);
    kgid = KGIDT_INIT(0);

    pid_struct = find_get_pid(pid);

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task == NULL){
        printk(KERN_ERR "[ovo] Failed to get current task info.\n");
        return -1;
    }

    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void *) ovo_kallsyms_lookup_name("prepare_creds");
        if (my_prepare_creds == NULL) {
            printk(KERN_ERR "[ovo] Failed to find prepare_creds\n");
            return -1;
        }
    }

    new_cred = my_prepare_creds();
    if (new_cred == NULL) {
        printk(KERN_ERR "[ovo] Failed to prepare new credentials\n");
        return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;

    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}

int is_pid_alive(pid_t pid) {
    struct pid * pid_struct;
    struct task_struct *task;
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

static void foreach_process(void (*callback)(struct ovo_task_struct *)) {
    struct task_struct *task;
    struct ovo_task_struct ovo_task;
    int ret = 0;

    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void *) ovo_kallsyms_lookup_name("get_cmdline");
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        ovo_task = (struct ovo_task_struct) {
                .task = task,
                .cmdline_len = 0
        };

        memset(ovo_task.cmdline, 0, 256);
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, ovo_task.cmdline, 256);
            if (ret < 0) {
                continue;
            }
            ovo_task.cmdline_len = ret;
        }

        callback(&ovo_task);
    }
    rcu_read_unlock();
}

pid_t find_process_by_name(const char *name) {
    static bool kprobe_registered = false;
    struct task_struct *task;
    char cmdline[256];
    size_t name_len;
    int ret;
    void *kallsyms_addr;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("[ovo] process name is empty\n");
        return -2;
    }

    // Register kprobe if not done yet and log its address
    if (!kprobe_registered) {
        int ret_kp;  // Declare variable first
        pr_info("[ovo_debug] Attempting to register get_cmdline kprobe...\n");
        ret_kp = register_kprobe(&kp_get_cmdline);
        if (ret_kp == 0) {
                pr_info("[ovo_debug] get_cmdline kprobe registered at address: %p\n", kp_get_cmdline.addr);
                kprobe_registered = true;
            } else {
                pr_err("[ovo_debug] Failed to register get_cmdline kprobe, error: %d\n", ret_kp);
            }
        } else {
            pr_info("[ovo_debug] get_cmdline kprobe already registered at address: %p\n", kp_get_cmdline.addr);
        }

    // Resolve get_cmdline address via kallsyms and log it
    kallsyms_addr = (void *)ovo_kallsyms_lookup_name("get_cmdline");
    if (kallsyms_addr) {
        pr_info("[ovo_debug] get_cmdline address resolved via kallsyms: %p\n", kallsyms_addr);
    } else {
        pr_err("[ovo_debug] Failed to resolve get_cmdline via kallsyms\n");
    }
    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL) {
            // We do NOT call get_cmdline because kprobe will catch calls
            ret = -1;
        } else {
            ret = -1;
        }

        if (ret < 0) {
            pr_warn("[ovo] Failed to get cmdline for pid %d : %s\n", task->pid, task->comm);
            if (strncmp(task->comm, name, min(strlen(task->comm), name_len)) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        } else {
            if (strncmp(cmdline, name, min(name_len, strlen(cmdline))) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        }
    }
    rcu_read_unlock();

    return 0;
}



#if INJECT_SYSCALLS == 1
int hide_process(pid_t pid) {
    // TODO("没有必要实现这个东西")
    return 0;
}
#endif

/* Define the kprobe globally */
static int get_cmdline_pre(struct kprobe *p, struct pt_regs *regs);

static struct kprobe kp_get_cmdline = {
    .symbol_name = "get_cmdline",
    .pre_handler = get_cmdline_pre,
};
