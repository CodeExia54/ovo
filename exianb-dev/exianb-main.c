// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/minmax.h>
#endif
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/input/mt.h>
#include <linux/input-event-codes.h>
#include <linux/kprobes.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "kprobekallsyms.h"    // Use your custom kprobe kallsyms header

static char *mCommon = "invoke_syscall";
module_param(mCommon, charp, 0644);
MODULE_PARM_DESC(mCommon, "Parameter");

static struct miscdevice dispatch_misc_device;

static int (*my_get_cmdline)(struct task_struct *tsk, char *buf, int buflen) = NULL;

static void __init hide_myself(void)
{
	struct vmap_area *va, *vtmp;
	struct module_use *use, *tmp;
	struct list_head *vmap_list =
		(struct list_head *)ksym_lookup_name_log("vmap_area_list");
	struct rb_root *vmap_root =
		(struct rb_root *)ksym_lookup_name_log("vmap_area_root");

	if (!vmap_list || !vmap_root)
		return;

	list_for_each_entry_safe(va, vtmp, vmap_list, list) {
		if ((unsigned long)THIS_MODULE > va->va_start &&
		    (unsigned long)THIS_MODULE < va->va_end) {
			list_del(&va->list);
			rb_erase(&va->rb_node, vmap_root);
		}
	}

	list_del_init(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);

	list_for_each_entry_safe(use, tmp, &THIS_MODULE->target_list, target_list) {
		list_del(&use->source_list);
		list_del(&use->target_list);
		sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
		kfree(use);
	}
}

pid_t find_process_by_name(const char *name)
{
	struct task_struct *task;
	char cmdline[256];
	size_t name_len;
	int ret;

	name_len = strlen(name);
	if (name_len == 0) {
		pr_err("[ovo] process name is empty\n");
		return -2;
	}

	if (!my_get_cmdline)
		my_get_cmdline = (void *)ksym_lookup_name_log("get_cmdline");

	rcu_read_lock();
	for_each_process(task) {
		if (task->mm == NULL)
			continue;

		cmdline[0] = '\0';
		if (my_get_cmdline != NULL) {
			ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
		} else {
			ret = -1;
		}

		if (ret < 0) {
			pr_warn("pvm: Failed to get cmdline for pid %d : %s\n", task->pid, task->comm);
			if (strncmp(task->comm, name, min(strlen(task->comm), name_len)) == 0) {
				rcu_read_unlock();
				pr_info("[ovo] pid matched returning %d", task->pid);
				return task->pid;
			}
		} else {
			pr_warn("pvm: success to get cmdline for pid %d : %s\n", task->pid, cmdline);
			if (strncmp(cmdline, name, min(name_len, strlen(cmdline))) == 0) {
				rcu_read_unlock();
				pr_info("[ovo] (in cmdline) pid matched returning %d", task->pid);
				return task->pid;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

static int dispatch_open(struct inode *node, struct file *file) { return 0; }
static int dispatch_close(struct inode *node, struct file *file) { return 0; }

bool isFirst = true;
static struct kprobe kpp;

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
	static char name[0x100] = {0};

	if (isFirst) {
		// unregister_kprobe(&kpp);
		isFirst = false;
	}

	switch (cmd) {
	case OP_READ_MEM:
#ifdef OP_RW_MEM
	case OP_RW_MEM:
#endif
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) {
			pr_err("pvm: OP_READ_MEM copy_from_user failed.\n");
			return -1;
		}
#ifdef OP_RW_MEM
		if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, cmd == OP_RW_MEM))
#else
		if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size, false))
#endif
			return -1;
		break;

	case OP_WRITE_MEM:
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
			return -1;
		if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
			return -1;
		break;

	case OP_MODULE_BASE:
		if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 ||
		    copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
			return -1;
		mb.base = get_module_base(mb.pid, name);
		if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
			return -1;
		break;

	default:
		break;
	}
	return 0;
}

static const struct file_operations dispatch_fops = {
	.owner = THIS_MODULE,
	.open = dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

struct ioctl_cf {
	int fd;
	char name[15];
};

struct ioctl_cf cf;

struct prctl_cf {
	int pid;
	uintptr_t addr;
	void *buffer;
	int size;
};

int filedescription;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	uint64_t v4;

	if ((uint32_t)(regs->regs[1]) == 167 /* syscall 29 on AArch64 */) {
		v4 = regs->user_regs.regs[0];

		// Handle memory read request
		if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x999) {
			struct prctl_cf cfp;
			pid_t pidd = find_process_by_name("com.activision.callofduty.shooter");
			pr_info("pvm: bgmi pid %d", pidd);
			if (!copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp))) {
				if (!read_process_memory(cfp.pid, cfp.addr, cfp.buffer, cfp.size, false))
					pr_err("pvm: read_process_memory failed\n");
			}
		}

		if (*(uint32_t *)(regs->user_regs.regs[0] + 8) == 0x9999) {
			struct prctl_cf cfp;
			if (!copy_from_user(&cfp, *(const void **)(v4 + 16), sizeof(cfp))) {
				if (!read_process_memory(cfp.pid, cfp.addr, cfp.buffer, cfp.size, true))
					pr_err("pvm: read_process_memory failed\n");
			}
		}
	}

	return 0;
}

bool isDevUse = false;

static int __init hide_init(void)
{
	int ret;

	// Initialize kallsyms: this caches pointer and unregisters kprobe immediately
	ret = kallsyms_init("kallsyms_lookup_name");
	if (ret) {
		pr_err("driverX: kallsyms_init failed (%d)\n", ret);
		return ret;
	}

	// Now your ksym_lookup_name_log() uses cached pointer, just like the old method

	kpp.symbol_name = mCommon;
	kpp.pre_handler = handler_pre;

	dispatch_misc_device.minor = MISC_DYNAMIC_MINOR;
	dispatch_misc_device.name = "quallcomm_null";
	dispatch_misc_device.fops = &dispatch_fops;

	ret = register_kprobe(&kpp);
	if (ret < 0) {
		pr_err("driverX: Failed to register kprobe: %d (%s)\n", ret, kpp.symbol_name);
		kpp.symbol_name = "invoke_syscall";
		kpp.pre_handler = handler_pre;
		ret = register_kprobe(&kpp);
		if (ret < 0) {
			isDevUse = true;
			ret = misc_register(&dispatch_misc_device);
			pr_err("driverX: Failed to register kprobe: %d (%s) using dev\n", ret, kpp.symbol_name);
			return ret;
		}
	}

	hide_myself();

	// Register kprobe for get_cmdline and cache address
	static struct kprobe kpc = {
		.symbol_name = "get_cmdline",
	};

	if (register_kprobe(&kpc) < 0) {
		printk("kpm: cmdline bsdk not kprobed\n");
	} else {
		my_get_cmdline = (int (*)(struct task_struct *task, char *buffer, int buflen))kpc.addr;
		pr_info("pvm: cmdline bsdk wala found\n");
		unregister_kprobe(&kpc);
	}

	return 0;
}

static void __exit hide_exit(void)
{
	if (isDevUse)
		misc_deregister(&dispatch_misc_device);
	else
		unregister_kprobe(&kpp);

	kallsyms_exit();
}

module_init(hide_init);
module_exit(hide_exit);

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
