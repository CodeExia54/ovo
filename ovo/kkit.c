//
// Created by fuqiuluo on 25-1-22.
//
#include <linux/kprobes.h>
#include "kkit.h"

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

int mark_pid_root(pid_t pid)
{
/*
    struct pid *pid_struct;
    struct task_struct *task;
    struct cred *new_cred;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        printk(KERN_ERR "[ovo] find_get_pid failed\n");
        return -ESRCH;
    }

    rcu_read_lock();
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    put_pid(pid_struct);

    if (!task) {
        printk(KERN_ERR "[ovo] pid_task lookup failed\n");
        return -ESRCH;
    }

    new_cred = prepare_creds();
    if (!new_cred) {
        printk(KERN_ERR "[ovo] Failed to prepare new credentials\n");
        put_task_struct(task);
        return -ENOMEM;
    }

    new_cred->uid  = KUIDT_INIT(0);
    new_cred->gid  = KGIDT_INIT(0);
    new_cred->euid = KUIDT_INIT(0);
    new_cred->egid = KGIDT_INIT(0);

    rcu_assign_pointer(task->cred, new_cred);

    put_task_struct(task);
    return 0;
*/
    return 0;
}

int is_pid_alive(pid_t pid) {
/*
    struct pid *pid_struct;
    struct task_struct *task;
    bool alive = false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    rcu_read_lock();
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task)
        alive = pid_alive(task);
    rcu_read_unlock();

    put_pid(pid_struct);
    return alive;
*/
    return false;
}

static int (*my_get_cmdline)(struct task_struct *task, char *buffer, int buflen) = NULL;

static void foreach_process(void (*callback)(struct ovo_task_struct *)) {
/*
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
*/
}

pid_t find_process_by_name(const char *name) {
/*
    struct task_struct *task;
    struct task_struct *found_task = NULL;
    char cmdline[256];
    size_t name_len;
    int ret;
    pid_t pid;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("[ovo] process name is empty\n");
        return -2;
    }

    pr_info("[ovo] find_process_by_name called with pkg name: '%s'\n", name);

    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void *)ovo_kallsyms_lookup_name("get_cmdline");
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
        } else {
            ret = -1;
        }

        if (ret < 0) {
            pr_warn("[ovo] Failed to get cmdline for pid %d\n", task->pid);
            if (strncmp(task->comm, name, min(strlen(task->comm), name_len)) == 0) {
                get_task_struct(task);
                found_task = task;
                break;
            }
        } else {
            if (strncmp(cmdline, name, min(name_len, strlen(cmdline))) == 0) {
                get_task_struct(task);
                found_task = task;
                break;
            }
        }
    }
    rcu_read_unlock();

    if (!found_task) {
        pr_info("[ovo] find_process_by_name: no process found for '%s'\n", name);
        return 0;
    }

    pid = found_task->pid;
    pr_info("[ovo] find_process_by_name: found pid %d for pkg '%s'\n", pid, name);
    put_task_struct(found_task);

    return pid;
*/
    return 0;
}

#if INJECT_SYSCALLS == 1
int hide_process(pid_t pid) {
    // TODO("没有必要实现这个东西")
    return 0;
}
#endif
