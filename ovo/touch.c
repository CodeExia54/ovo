//
// Created by fuqiuluo on 25-2-9.
//
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

#include "touch.h"
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/input/mt.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/input-event-codes.h>
#include "kkit.h"

// Forward declaration added here to fix implicit declaration error
static void handle_cache_events(struct input_dev* dev);

static void *kallsym_lookup_addr = NULL;
static struct list_head *input_dev_list = NULL;
static struct mutex *input_mutex = NULL;

static inline int is_event_supported(unsigned int code,
                                     unsigned long *bm, unsigned int max)
{
    return code <= max && test_bit(code, bm);
}

int get_last_driver_slot(struct input_dev* dev) {
    int slot, new_slot, is_new_slot;
    struct input_mt *mt;

    if (!dev) {
        pr_err("[ovo_debug] wtf? dev is null\n");
        return -114;
    }

    mt = dev->mt;
    new_slot = mt ? mt->slot : -999;
    slot     = dev->absinfo ? dev->absinfo[ABS_MT_SLOT].value : -999;

    if (new_slot == -999 && slot == -999)
        return -114;
    if (slot == -999)
        return new_slot;
    if (new_slot == -999)
        return slot;

    is_new_slot = (new_slot != slot);
    return is_new_slot ? new_slot : slot;
}

static void (*my_input_handle_event)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value) = NULL;

// Use kprobe to resolve the symbol address
static void *resolve_symbol_with_kprobe(const char *name)
{
    struct kprobe kp = { .symbol_name = (char *)name };
    void *addr = NULL;
    int ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (void *)kp.addr;
        unregister_kprobe(&kp);
    } else {
        pr_err("[ovo_debug] resolve_symbol_with_kprobe failed for %s, ret = %d\n", name, ret);
    }
    return addr;
}

static int init_my_input_handle_event(void)
{
    my_input_handle_event =
        (void (*)(struct input_dev *, unsigned int, unsigned int, int))
        resolve_symbol_with_kprobe("input_handle_event");
    if (!my_input_handle_event) {
        pr_err("[ovo_debug] failed to resolve input_handle_event symbol\n");
        return -ENOENT;
    }
    pr_info("[ovo_debug] resolved input_handle_event at %p\n", my_input_handle_event);
    return 0;
}

// Resolve kallsyms_lookup_name address using kprobe and cache it
static int resolve_kallsym_lookup(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[ovo_debug] Failed to register kprobe for kallsyms_lookup_name: %d\n", ret);
        return ret;
    }
    kallsym_lookup_addr = (void *)kp.addr;
    unregister_kprobe(&kp);

    if (!kallsym_lookup_addr) {
        pr_err("[ovo_debug] kallsyms_lookup_name addr NULL\n");
        return -ENOENT;
    }

    pr_info("[ovo_debug] kallsyms_lookup_name resolved at %p\n", kallsym_lookup_addr);
    return 0;
}

// Lookup input_dev_list and input_mutex using kallsyms_lookup_name resolved address
static int resolve_input_list_and_mutex(void)
{
    unsigned long (*kallsyms_lookup_name_func)(const char *name);

    int ret = resolve_kallsym_lookup();
    if (ret)
        return ret;

    kallsyms_lookup_name_func = kallsym_lookup_addr;

    input_dev_list = (struct list_head *)kallsyms_lookup_name_func("input_dev_list");
    input_mutex = (struct mutex *)kallsyms_lookup_name_func("input_mutex");

    if (!input_dev_list || !input_mutex) {
        pr_err("[ovo_debug] Failed to resolve input_dev_list or input_mutex\n");
        return -ENOENT;
    }

    pr_info("[ovo_debug] input_dev_list at %p, input_mutex at %p\n", input_dev_list, input_mutex);
    return 0;
}

struct input_dev* find_touch_device(void)
{
    static struct input_dev* CACHE = NULL;
    struct input_dev *dev;

    if (CACHE)
        return CACHE;

    if (!input_dev_list || !input_mutex) {
        pr_err("[ovo_debug] find_touch_device called but symbols not resolved\n");
        return NULL;
    }

    mutex_lock(input_mutex);
    list_for_each_entry(dev, input_dev_list, node) {
        if (test_bit(EV_ABS, dev->evbit) &&
            (test_bit(ABS_MT_POSITION_X, dev->absbit) || test_bit(ABS_X, dev->absbit)) &&
            dev->name && strcmp(dev->name, "fts_ts") == 0) {
            pr_info("[ovo_debug] Selected device: %s\n", dev->name);
            mutex_unlock(input_mutex);
            CACHE = dev;
            return dev;
        }
    }
    mutex_unlock(input_mutex);

    pr_err("[ovo_debug] Touch device 'fts_ts' not found\n");
    return NULL;
}

static struct event_pool *pool = NULL;
struct event_pool *get_event_pool(void) { return pool; }

int input_event_cache(unsigned int type, unsigned int code, int value, int lock)
{
    if (!my_input_handle_event) {
        pr_err("[ovo_debug] input_handle_event not initialized\n");
        return -EINVAL;
    }

    if (!pool) {
        pr_err("[ovo_debug] ERROR: event pool is NULL in input_event_cache\n");
        return -ENOMEM;
    }

    pr_info("[ovo_debug] input_event_cache: caching event type=%u code=%u value=%d at jiffies=%lu\n",
            type, code, value, jiffies);

    unsigned long flags;
    if (lock)
        spin_lock_irqsave(&pool->event_lock, flags);

    if (pool->size >= MAX_EVENTS) {
        pr_err("[ovo_debug] event pool full: size=%u, max=%d\n", pool->size, MAX_EVENTS);
        if (lock)
            spin_unlock_irqrestore(&pool->event_lock, flags);
        return -EFAULT;
    }
    pool->events[pool->size++] = (struct ovo_touch_event){ type, code, value };

    pr_info("[ovo_debug] input_event_cache: event cached, pool size=%u at jiffies=%lu\n", pool->size, jiffies);

    if (lock) {
        spin_unlock_irqrestore(&pool->event_lock, flags);
        pr_info("[ovo_debug] input_event_cache: released pool lock at jiffies=%lu\n", jiffies);
    }

    // Immediately flush after caching to reduce delay
    struct input_dev *dev = find_touch_device();
    if (dev) {
        pr_info("[ovo_debug] input_event_cache: triggering immediate flush at jiffies=%lu\n", jiffies);
        handle_cache_events(dev);
    } else {
        pr_warn("[ovo_debug] input_event_cache: device not found for flush at jiffies=%lu\n", jiffies);
    }

    return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
    int id;

    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        pr_info("[ovo_debug] input_mt_report_slot_state_cache: reporting slot inactive at jiffies=%lu\n", jiffies);
        return 0;
    }

    struct input_dev *dev = find_touch_device();
    if (!dev) {
        pr_err("[ovo_debug] input_mt_report_slot_state_cache: no device found\n");
        return -EINVAL;
    }

    struct input_mt *mt = dev->mt;
    if (!mt) {
        pr_err("[ovo_debug] input_mt_report_slot_state_cache: dev->mt NULL\n");
        return -EINVAL;
    }

    if (mt->slot < 0 || mt->slot >= mt->num_slots) {
        pr_err("[ovo_debug] input_mt_report_slot_state_cache: invalid slot %d\n", mt->slot);
        return -EINVAL;
    }

    struct input_mt_slot *slot = &mt->slots[mt->slot];
    id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
    if (id < 0) {
        id = input_mt_new_trkid(mt);
        pr_info("[ovo_debug] input_mt_report_slot_state_cache: new tracking id %d at slot %d, jiffies=%lu\n",
                id, mt->slot, jiffies);
    }

    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);

    return id;
}

bool input_mt_report_slot_state_with_id_cache(unsigned int tool_type,
                                              bool active, int id, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        pr_info("[ovo_debug] input_mt_report_slot_state_with_id_cache: reporting slot inactive at jiffies=%lu\n", jiffies);
        return false;
    }

    pr_info("[ovo_debug] input_mt_report_slot_state_with_id_cache: reporting active id=%d at jiffies=%lu\n", id, jiffies);

    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);

    return true;
}

static void handle_cache_events(struct input_dev* dev) {
    struct input_mt *mt = dev->mt;
    struct input_mt_slot *slot;
    unsigned long flags1, flags2;
    int id, i;

    pr_info("[ovo_debug] handle_cache_events enter for dev=%s at jiffies=%lu\n", dev ? dev->name : "NULL", jiffies);

    if (!dev) {
        pr_err("[ovo_debug] handle_cache_events: dev NULL at jiffies=%lu\n", jiffies);
        return;
    }

    if (!mt) {
        pr_err("[ovo_debug] handle_cache_events: dev->mt NULL for device %s at jiffies=%lu\n", dev->name, jiffies);
        return;
    }

    if (mt->slot < 0 || mt->slot >= mt->num_slots) {
        pr_err("[ovo_debug] handle_cache_events: invalid slot (%d) for device %s at jiffies=%lu\n", mt->slot, dev->name, jiffies);
        return;
    }

    slot = &mt->slots[mt->slot];

    spin_lock_irqsave(&pool->event_lock, flags2);
    if (pool->size == 0) {
        pr_info("[ovo_debug] handle_cache_events: empty event pool at jiffies=%lu\n", jiffies);
        spin_unlock_irqrestore(&pool->event_lock, flags2);
        return;
    }

    pr_info("[ovo_debug] handle_cache_events: processing %u events on device %s slot=%d at jiffies=%lu\n",
            pool->size, dev->name, mt->slot, jiffies);

    spin_lock_irqsave(&dev->event_lock, flags1);

    for (i = 0; i < pool->size; ++i) {
        struct ovo_touch_event event = pool->events[i];

        if (event.type == EV_ABS &&
            event.code == ABS_MT_TRACKING_ID &&
            event.value == -114514) {
            id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
            if (id < 0)
                id = input_mt_new_trkid(mt);
            event.value = id;
            pr_info("[ovo_debug] handle_cache_events: replaced -114514 with new tracking id %d at jiffies=%lu\n", id, jiffies);
        }

        pr_info("[ovo_debug] handle_cache_events: sending event #%d: type=%u code=%u value=%d at jiffies=%lu\n",
                i, event.type, event.code, event.value, jiffies);

        int ret = input_event_no_lock(dev, event.type, event.code, event.value);
        if (ret != 0)
            pr_err("[ovo_debug] handle_cache_events: input_event_no_lock returned %d for event #%d\n", ret, i);
    }

    pr_info("[ovo_debug] handle_cache_events: sending EV_SYN (SYN_REPORT) at jiffies=%lu\n", jiffies);
    int ret_sync = input_event_no_lock(dev, EV_SYN, SYN_REPORT, 0);
    if (ret_sync != 0)
        pr_err("[ovo_debug] handle_cache_events: input_event_no_lock returned %d for EV_SYN\n", ret_sync);
    else
        pr_info("[ovo_debug] handle_cache_events: EV_SYN sent successfully at jiffies=%lu\n", jiffies);

    spin_unlock_irqrestore(&dev->event_lock, flags1);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags2);

    pr_info("[ovo_debug] handle_cache_events exit for dev=%s at jiffies=%lu\n", dev->name, jiffies);
}

static int input_handle_event_handler_pre(struct kprobe *p,
                                          struct pt_regs *regs)
{
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];
    int value = (int)regs->regs[3];
    struct input_dev* dev = (struct input_dev*)regs->regs[0];

    if (!dev || !dev->name || strcmp(dev->name, "fts_ts") != 0) {
        return 0;
    }

    pr_info("[ovo_debug_kprobe] input_event fired: dev=%s type=%u code=%u value=%d at jiffies=%lu\n",
            dev->name, type, code, value, jiffies);

    if (type == EV_ABS &&
        (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y || code == ABS_MT_TRACKING_ID)) {
        pr_info("[ovo_debug_user] Userspace touch event seen: type=%u code=%u value=%d at jiffies=%lu\n",
                type, code, value, jiffies);
    }

    if (type != EV_SYN)
        return 0;

    handle_cache_events(dev);

    return 0;
}

static int input_handle_event_handler2_pre(struct kprobe *p,
                                           struct pt_regs *regs)
{
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];
    int value = (int)regs->regs[3];
    struct input_handle* handle = (struct input_handle*)regs->regs[0];
    struct input_dev* dev = handle ? handle->dev : NULL;

    if (!dev || !dev->name || strcmp(dev->name, "fts_ts") != 0) {
        return 0;
    }

    pr_info("[ovo_debug_kprobe] input_inject_event fired: dev=%s type=%u code=%u value=%d at jiffies=%lu\n",
            dev->name, type, code, value, jiffies);

    if (type == EV_ABS &&
        (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y || code == ABS_MT_TRACKING_ID)) {
        pr_info("[ovo_debug_user] Userspace injected event via input_inject_event: type=%u code=%u value=%d at jiffies=%lu\n",
                type, code, value, jiffies);
    }

    if (type != EV_SYN)
        return 0;

    handle_cache_events(dev);

    return 0;
}

// Optional: Hook input_mt_sync_frame if you want to debug or flush on frame sync
static int input_mt_sync_frame_pre(struct kprobe *p, struct pt_regs *regs) {
    struct input_dev* dev = (struct input_dev*)regs->regs[0];
    if(!dev) {
        return 0;
    }

    // Uncomment to flush cache on this sync event if desired
     pr_info("[ovo_debug] input_mt_sync_frame called for dev=%s at jiffies=%lu\n", dev->name, jiffies);
     handle_cache_events(dev);
    return 0;
}

static struct kprobe input_event_kp = {
    .symbol_name = "input_event",
    .pre_handler = input_handle_event_handler_pre,
};

static struct kprobe input_inject_event_kp = {
    .symbol_name = "input_inject_event",
    .pre_handler = input_handle_event_handler2_pre,
};

static struct kprobe input_mt_sync_frame_kp = {
    .symbol_name = "input_mt_sync_frame",
    .pre_handler = input_mt_sync_frame_pre,
};

int init_input_dev(void) {
    int ret;

    pr_info("[ovo_debug] init_input_dev started at jiffies=%lu\n", jiffies);

    ret = resolve_input_list_and_mutex();
    if (ret) {
        pr_err("[ovo_debug] failed to resolve input_dev_list or input_mutex: %d\n", ret);
        return ret;
    }

    ret = init_my_input_handle_event();
    if (ret) {
        pr_err("[ovo_debug] failed to initialize input_handle_event: %d at jiffies=%lu\n", ret, jiffies);
        return ret;
    }

    pr_info("[ovo_debug] input_handle_event resolved at %p at jiffies=%lu\n", my_input_handle_event, jiffies);

    ret = register_kprobe(&input_event_kp);
    pr_info("[ovo_debug] input_event_kp registration result: %d at jiffies=%lu\n", ret, jiffies);
    if (ret)
        return ret;

    ret = register_kprobe(&input_inject_event_kp);
    pr_info("[ovo_debug] input_inject_event_kp registration result: %d at jiffies=%lu\n", ret, jiffies);
    if (ret) {
        unregister_kprobe(&input_event_kp);
        return ret;
    }

    ret = register_kprobe(&input_mt_sync_frame_kp);
    pr_info("[ovo_debug] input_mt_sync_frame_kp registration result: %d at jiffies=%lu\n", ret, jiffies);
    if (ret) {
        unregister_kprobe(&input_event_kp);
        unregister_kprobe(&input_inject_event_kp);
        return ret;
    }

    pool = kvmalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool) {
        pr_err("[ovo_debug] failed to allocate event pool at jiffies=%lu\n", jiffies);
        unregister_kprobe(&input_event_kp);
        unregister_kprobe(&input_inject_event_kp);
        unregister_kprobe(&input_mt_sync_frame_kp);
        return -ENOMEM;
    }
    pool->size = 0;
    spin_lock_init(&pool->event_lock);

    pr_info("[ovo_debug] event pool allocated at %p at jiffies=%lu\n", pool, jiffies);

    pr_info("[ovo_debug] init_input_dev completed successfully at jiffies=%lu\n", jiffies);

    return 0;
}

void exit_input_dev(void) {
    pr_info("[ovo_debug] exit_input_dev start at jiffies=%lu\n", jiffies);

    unregister_kprobe(&input_event_kp);
    unregister_kprobe(&input_inject_event_kp);
    unregister_kprobe(&input_mt_sync_frame_kp);

    if (pool) {
        kfree(pool);
        pool = NULL;
    }

    pr_info("[ovo_debug] input_dev exited and resources freed at jiffies=%lu\n", jiffies);
}
