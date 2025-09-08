#ifndef KPROBE_KALLSYMS_H
#define KPROBE_KALLSYMS_H

#include <linux/kprobes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set up a kprobe on "kallsyms_lookup_name". Call once in module_init. */
int  kallsyms_init(const char *symbol_name);

/* Remove the kprobe. Call from module_exit. */
void kallsyms_exit(void);

/* Wrapper that looks up a symbol address by name via kp.addr. */
unsigned long ksym_lookup_name(const char *name);

/* Same as above but logs each resolution. */
unsigned long ksym_lookup_name_log(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* KPROBE_KALLSYMS_H */
