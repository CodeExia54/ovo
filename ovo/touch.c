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

// Function pointer for internal input_handle_event
static void (*my_input_handle_event)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value) = NULL;

// Kprobe-based resolver for unexported symbols
static void *resolve_symbol_with_kprobe(const char *name)
{
    struct kprobe kp = { .symbol_name = (char *)name };
    void *addr = NULL;
    int ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (void *)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

// Initialize my_input_handle_event once at module init
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

// Safe wrapper replacing direct calls
int input_event_no_lock(struct input_dev *dev,
                        unsigned int type, unsigned int code, int value)
{
    if (!my_input_handle_event) {
        pr_err("[ovo_debug] input_handle_event not initialized\n");
        return -EINVAL;
    }
    if (!dev) {
        pr_err("[ovo_debug] input_event_no_lock called with NULL dev\n");
        return -EINVAL;
    }
    if (is_event_supported(type, dev->evbit, EV_MAX)) {
        pr_info("[ovo_debug] input_event_no_lock: sending type=%u code=%u value=%d to device=%s\n",
                type, code, value, dev->name ? dev->name : "NULL");
        my_input_handle_event(dev, type, code, value);
    }
    return 0;
}

struct input_dev* find_touch_device(void) {
    static struct input_dev* CACHE = NULL;
    struct input_dev *dev;
    struct list_head *input_dev_list;
    struct mutex *input_mutex;

    if (CACHE)
        return CACHE;

    input_dev_list = (struct list_head *)resolve_symbol_with_kprobe("input_dev_list");
    input_mutex = (struct mutex *)resolve_symbol_with_kprobe("input_mutex");
    if (!input_dev_list || !input_mutex) {
        pr_err("[ovo_debug] Failed to find input_dev_list or input_mutex\n");
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
    pr_info("[ovo_debug] cached event: type=%u code=%u value=%d pool_size=%u\n",
            type, code, value, pool->size);

    if (lock)
        spin_unlock_irqrestore(&pool->event_lock, flags);

    return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return 0;
    }

    struct input_dev *dev = find_touch_device();
    struct input_mt *mt      = dev ? dev->mt : NULL;
    struct input_mt_slot *slot;
    int id;

    if (!mt || mt->slot < 0 || mt->slot > mt->num_slots)
        return -1;

    slot = &mt->slots[mt->slot];
    id   = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
    if (id < 0)
        id = input_mt_new_trkid(mt);

    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);
    return id;
}

bool input_mt_report_slot_state_with_id_cache(unsigned int tool_type,
                                              bool active, int id, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return false;
    }
    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);
    return true;
}

static void handle_cache_events(struct input_dev* dev) {
    struct input_mt *mt = dev->mt;
    struct input_mt_slot *slot;
    unsigned long flags1, flags2;
    int id;

    if (!mt || mt->slot < 0 || mt->slot > mt->num_slots) {
        pr_err("[ovo_debug] handle_cache_events invalid mt or slot, dev=%s\n",
               dev->name ? dev->name : "NULL");
        return;
    }

    slot = &mt->slots[mt->slot];
    spin_lock_irqsave(&pool->event_lock, flags2);
    if (pool->size == 0) {
        pr_info("[ovo_debug] handle_cache_events: empty event pool\n");
        spin_unlock_irqrestore(&pool->event_lock, flags2);
        return;
    }

    spin_lock_irqsave(&dev->event_lock, flags1);
    pr_info("[ovo_debug] handle_cache_events: processing %u events on device %s\n",
            pool->size, dev->name ? dev->name : "NULL");

    int i;
    for (i = 0; i < pool->size; ++i) {
        struct ovo_touch_event event = pool->events[i];
        if (event.type == EV_ABS &&
            event.code == ABS_MT_TRACKING_ID &&
            event.value == -114514) {
            id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
            if (id < 0)
                id = input_mt_new_trkid(mt);
            event.value = id;
        }
        pr_info("[ovo_debug] handle_cache_events: sending event type=%u code=%u value=%d\n",
                event.type, event.code, event.value);
        input_event_no_lock(dev, event.type, event.code, event.value);
    }

    spin_unlock_irqrestore(&dev->event_lock, flags1);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags2);
}

static int input_handle_event_handler_pre(struct kprobe *p,
                                          struct pt_regs *regs)
{
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];
    int value = (int)regs->regs[3];
    struct input_dev* dev = (struct input_dev*)regs->regs[0];

    // Filter only your target input device
    if (!dev || !dev->name || strcmp(dev->name, "fts_ts") != 0) {
        return 0;
    }

    // Only log relevant touch events
    if (type == EV_ABS &&
        (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y || code == ABS_MT_TRACKING_ID)) {
        pr_info("[ovo_debug_user] Userspace touch event seen: type=%u code=%u value=%d\n",
                type, code, value);
    }

    if (type != EV_SYN)
        return 0;

    // Flush cached events on sync
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

    if (type == EV_ABS &&
        (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y || code == ABS_MT_TRACKING_ID)) {
        pr_info("[ovo_debug_user] Userspace injected event via input_inject_event: type=%u code=%u value=%d\n",
                type, code, value);
    }

    if (type != EV_SYN)
        return 0;

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

int init_input_dev(void) {
    int ret;

    pr_info("[ovo_debug] init_input_dev started\n");

    ret = init_my_input_handle_event();
    if (ret) {
        pr_err("[ovo_debug] failed to initialize input_handle_event: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&input_event_kp);
    pr_info("[ovo_debug] input_event_kp registration: %d\n", ret);
    if (ret)
        return ret;

    ret = register_kprobe(&input_inject_event_kp);
    pr_info("[ovo_debug] input_inject_event_kp registration: %d\n", ret);
    if (ret) {
        unregister_kprobe(&input_event_kp);
        return ret;
    }

    pool = kvmalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool) {
        pr_err("[ovo_debug] failed to allocate event pool\n");
        unregister_kprobe(&input_event_kp);
        unregister_kprobe(&input_inject_event_kp);
        return -ENOMEM;
    }
    pool->size = 0;
    spin_lock_init(&pool->event_lock);
    pr_info("[ovo_debug] event pool allocated at %p\n", pool);

    pr_info("[ovo_debug] init_input_dev completed successfully\n");
    return 0;
}

void exit_input_dev(void) {
    unregister_kprobe(&input_event_kp);
    unregister_kprobe(&input_inject_event_kp);
    if (pool) {
        kfree(pool);
        pool = NULL;
    }
    pr_info("[ovo_debug] input dev exited and resources freed\n");
}

