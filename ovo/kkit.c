//
// Created by fuqiuluo on 25-2-3.
//
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/uio.h>
#include <linux/fcntl.h> 

#include "kkit.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#endif

// Rename the static pointer to avoid clash with function name
static unsigned long (*kallsyms_lookup_name_ptr)(const char *symbol_name) = NULL;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};

static struct kprobe getcmd_kp;
static bool getcmd_kp_registered = false;
static int (*my_get_cmdline)(struct task_struct *task, char *buffer, int buflen) = NULL;

// This is the function declared in kkit.h, acting as wrapper
unsigned long ovo_kallsyms_lookup_name(const char *symbol_name) {
#if defined(KPROBE_LOOKUP)
	if (kallsyms_lookup_name_ptr == NULL) {
		if (register_kprobe(&kp) < 0) {
			pr_err("[ovo] Failed to register kprobe for kallsyms_lookup_name\n");
			return 0;
		}
		kallsyms_lookup_name_ptr = (unsigned long (*)(const char *)) kp.addr;
		unregister_kprobe(&kp);
		pr_info("[ovo] kallsyms_lookup_name resolved at %px\n", kallsyms_lookup_name_ptr);
	}
	return kallsyms_lookup_name_ptr(symbol_name);
#else
	return kallsyms_lookup_name(symbol_name);
#endif
}

static int resolve_get_cmdline(void) {
	if (my_get_cmdline) {
		pr_info("[ovo] get_cmdline already resolved at %px\n", my_get_cmdline);
		return 0;
	}
	if (getcmd_kp_registered) {
		pr_info("[ovo] get_cmdline kprobe already registered\n");
		return 0;
	}

	memset(&getcmd_kp, 0, sizeof(getcmd_kp));
	getcmd_kp.symbol_name = "get_cmdline";

	if (register_kprobe(&getcmd_kp) < 0) {
		pr_err("[ovo] Failed to register kprobe for get_cmdline\n");
		getcmd_kp_registered = false;
		return -1;
	}

	my_get_cmdline = (int (*)(struct task_struct*, char*, int))getcmd_kp.addr;
	getcmd_kp_registered = true;

	pr_info("[ovo] get_cmdline resolved successfully at %px\n", my_get_cmdline);
	return 0;
}

void unregister_get_cmdline(void) {
	if (getcmd_kp_registered) {
		unregister_kprobe(&getcmd_kp);
		getcmd_kp_registered = false;
		pr_info("[ovo] Unregistered get_cmdline kprobe\n");
		my_get_cmdline = NULL;
	}
}

unsigned long *ovo_find_syscall_table(void) {
	unsigned long *table = NULL;
	if (!kallsyms_lookup_name_ptr) {
		pr_err("[ovo] kallsyms_lookup_name is NULL, cannot find sys_call_table\n");
		return NULL;
	}
	table = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
	pr_info("[ovo] sys_call_table resolved at %px\n", table);
	return table;
}

int ovo_flip_open(const char *filename, int flags, umode_t mode, struct file **f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	*f = filp_open(filename, flags, mode);
	return IS_ERR(*f) ? -2 : 0;
#else
	static struct file* (*reserve_flip_open)(const char *filename, int flags, umode_t mode) = NULL;
	if (reserve_flip_open == NULL) {
		reserve_flip_open = (struct file* (*)(const char *, int, umode_t))ovo_kallsyms_lookup_name("filp_open");
		if (reserve_flip_open == NULL) {
			pr_err("[ovo] Failed to resolve filp_open\n");
			return -1;
		}
		pr_info("[ovo] filp_open resolved at %px\n", reserve_flip_open);
	}
	*f = reserve_flip_open(filename, flags, mode);
	return IS_ERR(*f) ? -2 : 0;
#endif
}

int ovo_flip_close(struct file **f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
	if (*f) {
		filp_close(*f, id);
		*f = NULL;
	}
	return 0;
#else
	static int (*reserve_flip_close)(struct file *filp, fl_owner_t id) = NULL;
	if (*f == NULL)
		return 0;
	if (reserve_flip_close == NULL) {
		reserve_flip_close = (int (*)(struct file *, fl_owner_t))ovo_kallsyms_lookup_name("filp_close");
		if (reserve_flip_close == NULL) {
			pr_err("[ovo] Failed to resolve filp_close\n");
			return -1;
		}
		pr_info("[ovo] filp_close resolved at %px\n", reserve_flip_close);
	}
	reserve_flip_close(*f, id);
	*f = NULL;
	return 0;
#endif
}

bool is_file_exist(const char *filename) {
	struct file* fp;
	if (ovo_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
		if (!IS_ERR(fp)) {
			ovo_flip_close(&fp, NULL);
			return true;
		}
		return false;
	}
	return false;
}

int mark_pid_root(pid_t pid) {
	static struct cred* (*my_prepare_creds)(void) = NULL;
	struct pid *pid_struct;
	struct task_struct *task;
	kuid_t kuid = KUIDT_INIT(0);
	kgid_t kgid = KGIDT_INIT(0);
	struct cred *new_cred;

	pid_struct = find_get_pid(pid);
	task = pid_task(pid_struct, PIDTYPE_PID);
	if (task == NULL) {
		pr_err("[ovo] Failed to get current task info.\n");
		return -1;
	}
	if (my_prepare_creds == NULL) {
		my_prepare_creds = (void *) ovo_kallsyms_lookup_name("prepare_creds");
		if (my_prepare_creds == NULL) {
			pr_err("[ovo] Failed to resolve prepare_creds\n");
			return -1;
		}
		pr_info("[ovo] prepare_creds resolved at %px\n", my_prepare_creds);
	}
	new_cred = my_prepare_creds();
	if (new_cred == NULL) {
		pr_err("[ovo] Failed to prepare new credentials\n");
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
	struct pid *pid_struct;
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
	char comm[TASK_COMM_LEN];
	int ret = 0;

	resolve_get_cmdline();

	rcu_read_lock();
	for_each_process(task) {
		if (task->mm == NULL)
			continue;

		ovo_task.task = task;
		ovo_task.cmdline_len = 0;
		memset(ovo_task.cmdline, 0, sizeof(ovo_task.cmdline));

		if (my_get_cmdline != NULL) {
			ret = my_get_cmdline(task, ovo_task.cmdline, sizeof(ovo_task.cmdline));
			if (ret > 0)
				ovo_task.cmdline_len = ret;
		} else {
			get_task_comm(comm, task);
			strscpy(ovo_task.cmdline, comm, sizeof(ovo_task.cmdline));
			ovo_task.cmdline_len = strnlen(ovo_task.cmdline, sizeof(ovo_task.cmdline));
		}

		callback(&ovo_task);
	}
	rcu_read_unlock();
}

pid_t find_process_by_name(const char *name) {
	struct task_struct *task;
	char cmdline[256];
	char comm[TASK_COMM_LEN];
	size_t name_len;
	int ret;

	name_len = strlen(name);
	if (name_len == 0) {
		pr_err("[ovo] process name is empty\n");
		return -2;
	}

	resolve_get_cmdline();

	rcu_read_lock();
	for_each_process(task) {
		if (task->mm == NULL)
			continue;

		cmdline[0] = '\0';
		if (my_get_cmdline != NULL) {
			ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
		} else {
			ret = -1;
			get_task_comm(comm, task);
			strscpy(cmdline, comm, sizeof(cmdline));
		}

		if (ret < 0 || cmdline[0] == '\0') {
			pr_warn("[ovo] Failed to get cmdline for pid %d\n", task->pid);
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
	return 0;
}
#endif

// Renamed initialization function as requested
int ovo_resolve_all_symbols(void) {
	int ret;

	ret = resolve_kallsyms_lookup_name();
	if (ret < 0) {
		pr_err("[ovo] Failed to resolve kallsyms_lookup_name\n");
		return ret;
	}

	ret = resolve_get_cmdline();
	if (ret < 0) {
		pr_err("[ovo] Failed to resolve get_cmdline\n");
		return ret;
	}

	pr_info("[ovo] All required symbols resolved successfully\n");
	return 0;
}

// Cleanup function to clean kprobes on module unload
void ovo_cleanup(void) {
	unregister_get_cmdline();
}
