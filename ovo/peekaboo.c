//
// Created by fuqiuluo on 25-1-22.
//
#include "peekaboo.h"
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/tty.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>
#include <linux/slab.h>
#include <linux/init_task.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "kkit.h"

#include <linux/input/mt.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/input-event-codes.h>
/*
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
#endif

unsigned long (*kallsyms_lookup_nameXX)(const char *name);
*/
void cuteBabyPleaseDontCry(void) {
    /*
    if (is_file_exist("/proc/sched_debug")) {
        remove_proc_entry("sched_debug", NULL);
    }

    if (is_file_exist("/proc/uevents_records")) {
        remove_proc_entry("uevents_records", NULL);
    }

#ifdef MODULE
    #if HIDE_SELF_MODULE == 1
    list_del(&THIS_MODULE->list); //lsmod,/proc/modules
    kobject_del(&THIS_MODULE->mkobj.kobj); // /sys/modules
    list_del(&THIS_MODULE->mkobj.kobj.entry); // kobj struct list_head entry
    #endif
#endif

#if HIDE_SELF_MODULE == 1
    // protocol disguise! A lie
    memcpy(THIS_MODULE->name, "nfc\0", 4);
    //remove_proc_entry("protocols", net->proc_net);
#endif
   */
	
   // struct vmap_area *va, *vtmp;
    struct module_use *use, *tmp;
   // struct list_head *_vmap_area_list;
   // struct rb_root *_vmap_area_root;
	
/*
#ifdef KPROBE_LOOKUP
    
    if (register_kprobe(&kp) < 0) {
	    printk("driverX: module hide failed");
        return;
    }
    kallsyms_lookup_nameXX = (unsigned long (*)(const char *name)) kp.addr;
    unregister_kprobe(&kp);
#endif
	
    // return;
	
    _vmap_area_list =
        (struct list_head *) kallsyms_lookup_nameXX("vmap_area_list");
    _vmap_area_root = (struct rb_root *) kallsyms_lookup_nameXX("vmap_area_root");

    ** hidden from /proc/vmallocinfo **
    list_for_each_entry_safe (va, vtmp, _vmap_area_list, list) {
        if ((unsigned long) THIS_MODULE > va->va_start &&
            (unsigned long) THIS_MODULE < va->va_end) {
            list_del(&va->list);
            ** remove from red-black tree **
            rb_erase(&va->rb_node, _vmap_area_root);
        }
    }
*/
    /* hidden from /proc/modules */
    list_del_init(&THIS_MODULE->list);

    /* hidden from /sys/modules */
    kobject_del(&THIS_MODULE->mkobj.kobj);

    /* decouple the dependency */
    list_for_each_entry_safe (use, tmp, &THIS_MODULE->target_list,
                              target_list) {
        list_del(&use->source_list);
        list_del(&use->target_list);
        sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
        kfree(use);
    }    
}
