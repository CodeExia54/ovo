// SPDX-License-Identifier: GPL
#include "kprobekallsyms.h"
#include <linux/kernel.h>
#include <linux/printk.h>

static struct kprobe kp = { .symbol_name = NULL };
static int kallsyms_initialized = 0;

int kallsyms_init(const char *symbol_name)
{
	int ret;

	if (kallsyms_initialized)
		return 0;

	kp.symbol_name = symbol_name; /* expect "kallsyms_lookup_name" */

	ret = register_kprobe(&kp);
	if (ret) {
		pr_err("kprobekallsyms: Failed to register kprobe on %s: %d\n", symbol_name, ret);
		return ret;
	}

	kallsyms_initialized = 1;
	pr_info("kprobekallsyms: registered kprobe on %s at %px\n", symbol_name, kp.addr);
	return 0;
}

void kallsyms_exit(void)
{
	if (!kallsyms_initialized)
		return;

	unregister_kprobe(&kp);
	kallsyms_initialized = 0;
	pr_info("kprobekallsyms: unregistered kprobe on %s\n", kp.symbol_name);
}

unsigned long ksym_lookup_name(const char *name)
{
	if (!kallsyms_initialized || !kp.addr)
		return 0;

	return ((unsigned long (*)(const char *))kp.addr)(name);
}

unsigned long ksym_lookup_name_log(const char *name)
{
	unsigned long addr = ksym_lookup_name(name);
	pr_info("kprobe_kallsyms: resolved %s = %px\n", name, (void *)addr);
	return addr;
}
