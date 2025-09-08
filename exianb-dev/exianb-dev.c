// driverX_main.c
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#include <linux/minmax.h>
#endif
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/sysfs.h>

#include <linux/input/mt.h>
#include <linux/input-event-codes.h>
#include <linux/kprobes.h>

/* ---- universal helper -------------------------------------------- */
#include "kprobekallsyms.h"
/* Use ONLY the by-name resolver (resolved via kprobe). */
#define klookup(name)  ksym_lookup_name_log(name)   /* logs each resolve */
/* ------------------------------------------------------------------ */

static char *mCommon = "invoke_syscall";
module_param(mCommon, charp, 0644);
MODULE_PARM_DESC(mCommon, "Parameter");

static struct miscdevice dispatch_misc_device;

/* If prctl_cf is not already defined in headers, define it here so stack
 * variables compile without incomplete-type errors. */
#ifndef HAVE_PRCTL_CF_DEF
struct prctl_cf {
	pid_t           pid;
	unsigned long   addr;
	void __user    *buffer;
	size_t          size;
};
#endif

/* --------------------------- hide_myself -------------------------- */
static void __init hide_myself(void)
{
	struct vmap_area *va, *vtmp;
	struct module_use *use, *tmp;
	struct list_head *vmap_list =
		(struct list_head *)klookup("vmap_area_list");
	struct rb_root *vmap_root =
		(struct rb_root *)klookup("vmap_area_root");

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

	list_for_each_entry_safe(use, tmp, &THIS_MODULE->target_list,
				 target_list) {
		list_del(&use->source_list);
		list_del(&use->target_list);
		sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
		kfree(use);
	}
}

/* --------------------------- helpers ------------------------------ */
static int (*my_get_cmdline)(struct task_struct *, char *, int);

static pid_t find_process_by_name(const char *name)
{
	struct task_struct *task;
	char cmdline[256];  // fixed: buffer instead of char
	size_t name_len = strlen(name);
	int ret;

	if (!name_len)
		return -EINVAL;

	if (!my_get_cmdline)
		my_get_cmdline = (void *)klookup("get_cmdline");

	rcu_read_lock();
	for_each_process(task) {
		if (!task->mm)
			continue;

		cmdline[0] = '\0';  // initialize buffer
		ret = my_get_cmdline ? my_get_cmdline(task, cmdline, sizeof(cmdline))
				     : -1;

		if (ret < 0) {
			if (!strncmp(task->comm, name,
				     min(strlen(task->comm), name_len))) {
				rcu_read_unlock();
				return task->pid;
			}
		} else {
			if (!strncmp(cmdline, name,
				     min(name_len, strlen(cmdline)))) {
				rcu_read_unlock();
				return task->pid;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

/* --------------------- ioctl & syscall kprobe --------------------- */
static struct kprobe syscall_probe;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	u64 v4;

	if ((u32)regs->regs[1] != 167)   /* AArch64 svc 29 */
		return 0;

	// fixed: assign first element, not entire array
	v4 = regs->user_regs.regs[0];

	if (*(u32 *)(regs->user_regs.regs + 8) == 0x999) {
		struct prctl_cf cfp;
		if (!copy_from_user(&cfp, *(const void __user **)(v4 + 16), sizeof(cfp)))
			read_process_memory(cfp.pid, cfp.addr, cfp.buffer,
					    cfp.size, false);
	}

	if (*(u32 *)(regs->user_regs.regs + 8) == 0x9999) {
		struct prctl_cf cfp;
		if (!copy_from_user(&cfp, *(const void __user **)(v4 + 16), sizeof(cfp)))
			read_process_memory(cfp.pid, cfp.addr, cfp.buffer,
					    cfp.size, true);
	}
	return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	static COPY_MEMORY  cm;
	static MODULE_BASE  mb;
	static char name[0x100];

	switch (cmd) {
	case OP_READ_MEM:
#ifdef OP_RW_MEM
	case OP_RW_MEM:
#endif
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
			return -EFAULT;
#ifdef OP_RW_MEM
		if (!read_process_memory(cm.pid, cm.addr, cm.buffer,
					 cm.size, cmd == OP_RW_MEM))
#else
		if (!read_process_memory(cm.pid, cm.addr, cm.buffer,
					 cm.size, false))
#endif
			return -EIO;
		break;

	case OP_WRITE_MEM:
		if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
			return -EFAULT;
		if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
			return -EIO;
		break;

	case OP_MODULE_BASE:
		if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) ||
		    copy_from_user(name, (void __user *)mb.name,
				   sizeof(name) - 1))
			return -EFAULT;
		mb.base = get_module_base(mb.pid, name);
		if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
			return -EFAULT;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int dispatch_open(struct inode *n, struct file *f) { return 0; }
static int dispatch_close(struct inode *n, struct file *f) { return 0; }

static const struct file_operations dispatch_fops = {
	.owner          = THIS_MODULE,
	.open           = dispatch_open,
	.release        = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

/* ----------------------- module init / exit ----------------------- */
static bool isDevUse;

static int __init hide_init(void)
{
	int ret;

	ret = kallsyms_init("kallsyms_lookup_name");
	if (ret) {
		pr_err("driverX: kallsyms_init failed (%d)\n", ret);
		return ret;
	}

	syscall_probe.symbol_name = mCommon;
	syscall_probe.pre_handler = handler_pre;

	dispatch_misc_device.minor = MISC_DYNAMIC_MINOR;
	dispatch_misc_device.name  = "quallcomm_null";
	dispatch_misc_device.fops  = &dispatch_fops;

	ret = register_kprobe(&syscall_probe);
	if (ret) {
		syscall_probe.symbol_name = "invoke_syscall";
		ret = register_kprobe(&syscall_probe);
		if (ret) {
			isDevUse = true;
			return misc_register(&dispatch_misc_device);
		}
	}

	hide_myself();
	return 0;
}

static void __exit hide_exit(void)
{
	if (isDevUse)
		misc_deregister(&dispatch_misc_device);
	else
		unregister_kprobe(&syscall_probe);

	kallsyms_exit();
}

module_init(hide_init);
module_exit(hide_exit);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

MODULE_AUTHOR("exianb");
MODULE_DESCRIPTION("exianb");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
