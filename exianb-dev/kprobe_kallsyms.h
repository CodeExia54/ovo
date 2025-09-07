#ifndef KPROBE_KALLSYMS_H
#define KPROBE_KALLSYMS_H

#include <linux/kprobes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set up a kprobe on “kallsyms_lookup_name”. Call once in module_init. */
int  kallsyms_init(const char *symbol_name);

/* Remove the kprobe. Call from module_exit. */
void kallsyms_exit(void);

/* Drop-in replacement for kallsyms_lookup_name. */
unsigned long kallsyms_lookup(const char *name);

/* Same as above but logs:
 *   kprobe_kallsyms: resolved <sym> = <addr>
 * every time it is called. */
unsigned long kallsyms_lookup_log(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* KPROBE_KALLSYMS_H */
