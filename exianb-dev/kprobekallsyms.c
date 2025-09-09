// SPDX-License-Identifier: GPL
#include "kprobekallsyms.h"
#include <linux/kernel.h>
#include <linux/printk.h>

static struct kprobe kp = { .symbol_name = NULL };
static unsigned long (*kallsyms_lookup_name_func)(const char *name) = NULL;
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

	// Cache pointer to kallsyms_lookup_name function
	kallsyms_lookup_name_func = (unsigned long (*)(const char *))kp.addr;

	// Unregister immediately to reduce overhead, keeping pointer cached
	unregister_kprobe(&kp);

	if (!kallsyms_lookup_name_func) {
		pr_err("kprobekallsyms: Failed to cache kallsyms_lookup_name function pointer\n");
		return -EINVAL;
	}

	kallsyms_initialized = 1;
	pr_info("kprobekallsyms: cached kallsyms_lookup_name function at %px\n", kp.addr);

	return 0;
}

void kallsyms_exit(void)
{
	kallsyms_lookup_name_func = NULL;
	kallsyms_initialized = 0;
}

unsigned long ksym_lookup_name(const char *name)
{
	if (!kallsyms_initialized || !kallsyms_lookup_name_func)
		return 0;

	return kallsyms_lookup_name_func(name);
}

unsigned long ksym_lookup_name_log(const char *name)
{
	unsigned long addr = ksym_lookup_name(name);
	pr_info("kprobe_kallsyms: resolved %s = %px\n", name, (void *)addr);
	return addr;
}
