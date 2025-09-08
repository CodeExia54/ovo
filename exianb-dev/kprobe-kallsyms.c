// SPDX-License-Identifier: GPL
#include "kprobe-kallsyms.h"
#include <linux/kernel.h>
#include <linux/printk.h>

static struct kprobe kp = { .symbol_name = NULL };

int kallsyms_init(const char *symbol_name)
{
	kp.symbol_name = symbol_name;     /* expect "kallsyms_lookup_name" */
	return register_kprobe(&kp);      /* kp.addr => kallsyms_lookup_name */
}

void kallsyms_exit(void)
{
	unregister_kprobe(&kp);
}

unsigned long ksym_lookup_name(const char *name)
{
	if (!kp.addr)
		return 0;
	return ((unsigned long (*)(const char *))kp.addr)(name);
}

unsigned long ksym_lookup_name_log(const char *name)
{
	unsigned long addr = ksym_lookup_name(name);
	pr_info("kprobe_kallsyms: resolved %s = %px\n", name, (void *)addr);
	return addr;
}
