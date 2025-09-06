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
        pr_err("[ovo_debug] dev is null\n");
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
    if (!is_event_supported(type, dev->evbit, EV_MAX)) {
        pr_warn("[ovo_debug] Unsupported event: type=%u code=%u for device=%s\n",
                type, code, dev->name ? dev->name : "NULL");
        return -EINVAL;
    }
    pr_info("[ovo_debug] input_event_no_lock: sending type=%u code=%u value=%d to device=%s at jiffies=%lu\n",
            type, code, value, dev->name ? dev->name : "NULL", jiffies);

    my_input_handle_event(dev, type, code, value);

    pr_info("[ovo_debug] input_event_no_lock: sent event type=%u code=%u value=%d to device=%s\n",
            type, code, value, dev->name ? dev->name : "NULL");

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
            pr_info("[ovo_debug] Device ranges: X=(%d,%d) Y=(%d,%d) Slot=(%d,%d)\n",
                    dev->absinfo[ABS_MT_POSITION_X].minimum,
                    dev->absinfo[ABS_MT_POSITION_X].maximum,
                    dev->absinfo[ABS_MT_POSITION_Y].minimum,
                    dev->absinfo[ABS_MT_POSITION_Y].maximum,
                    dev->absinfo[ABS_MT_SLOT].minimum,
                    dev->absinfo[ABS_MT_SLOT].maximum);
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
    if (lock)
        spin_unlock_irqrestore(&pool->event_lock, flags);

    pr_info("[ovo_debug] input_event_cache: cached event type=%u code=%u value=%d, pool size=%u\n",
            type, code, value, pool->size);

    return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
    int id;

    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        pr_info("[ovo_debug] reporting inactive slot at jiffies=%lu\n", jiffies);
        return 0;
    }

    struct input_dev *dev = find_touch_device();
    if (!dev) {
        pr_err("[ovo_debug] no device found\n");
        return -EINVAL;
    }
    struct input_mt *mt = dev->mt;
    if (!mt) {
        pr_err("[ovo_debug] dev->mt is NULL\n");
        return -EINVAL;
    }

    if (mt->slot < 0 || mt->slot >= mt->num_slots) {
        pr_err("[ovo_debug] invalid slot %d\n", mt->slot);
        return -EINVAL;
    }

    struct input_mt_slot *slot = &mt->slots[mt->slot];
    id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
    if (id < 0) {
        id = input_mt_new_trkid(mt);
        pr_info("[ovo_debug] new tracking id %d assigned at slot %d\n", id, mt->slot);
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
        pr_info("[ovo_debug] reporting inactive slot with id at jiffies=%lu\n", jiffies);
        return false;
    }

    pr_info("[ovo_debug] reporting active id=%d at jiffies=%lu\n", id, jiffies);

    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);

    return true;
}

static void handle_cache_events(struct input_dev* dev) {
    struct input_mt *mt = dev ? dev->mt : NULL;
    struct input_mt_slot *slot;
    unsigned long flags1, flags2;
    int id = 0;

    if (!dev) {
        pr_err("[ovo_debug] handle_cache_events: dev NULL\n");
        return;
    }
    if (!mt) {
        pr_err("[ovo_debug] handle_cache_events: dev->mt NULL\n");
        return;
    }
    if (mt->slot < 0 || mt->slot >= mt->num_slots) {
        pr_err("[ovo_debug] handle_cache_events: invalid slot %d\n", mt->slot);
        return;
    }

    slot = &mt->slots[mt->slot];

    pr_info("[ovo_debug] Flushing events for device: %s, slot: %d, TRACKING_ID: %d\n",
            dev->name, mt->slot, input_mt_get_value(slot, ABS_MT_TRACKING_ID));

    spin_lock_irqsave(&pool->event_lock, flags2);
    if (pool->size == 0) {
        pr_info("[ovo_debug] No events to flush\n");
        spin_unlock_irqrestore(&pool->event_lock, flags2);
        return;
    }
    spin_lock_irqsave(&dev->event_lock, flags1);

         int i;
        for (i = 0; i < pool->size; ++i) {
        struct ovo_touch_event event = pool->events[i];
        if (event.type == EV_ABS && event.code == ABS_MT_TRACKING_ID && event.value == -114514) {
            id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
            if (id < 0)
                id = input_mt_new_trkid(mt);
            event.value = id;
            pr_info("[ovo_debug] replaced sentinel with new tracking id %d\n", id);
        }

        pr_info("[ovo_debug] sending event #%d: type=0x%x code=0x%x value=%d\n",
                i, event.type, event.code, event.value);

        int ret = input_event_no_lock(dev, event.type, event.code, event.value);
        if (ret)
            pr_err("[ovo_debug] input_event_no_lock returned %d for event #%d\n", ret, i);
    }

    // Send sync event to commit frame
    input_event_no_lock(dev, EV_SYN, SYN_REPORT, 0);
    pr_info("[ovo_debug] EV_SYN SYN_REPORT sent\n");

    spin_unlock_irqrestore(&dev->event_lock, flags1);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags2);
}

static int input_handle_event_handler_pre(struct kprobe *p,
                                          struct pt_regs *regs)
{
    unsigned int type = (unsigned int)regs->regs[1];
    struct input_dev* dev = (struct input_dev*)regs->regs[0];

    if (!dev || type != EV_SYN)
        return 0;

    pr_info("[ovo_debug] input_event EV_SYN on device %s\n", dev->name);
    handle_cache_events(dev);

    return 0;
}

static int input_handle_event_handler2_pre(struct kprobe *p,
                                           struct pt_regs *regs)
{
    unsigned int type = (unsigned int)regs->regs[1];
    struct input_handle* handle = (struct input_handle*)regs->regs[0];
    struct input_dev* dev = handle ? handle->dev : NULL;

    if (!dev || type != EV_SYN)
        return 0;

    pr_info("[ovo_debug] input_inject_event EV_SYN on device %s\n", dev->name);
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

int init_input_dev(void)
{
    int ret;

    ret = init_my_input_handle_event();
    if (ret) {
        pr_err("[ovo_debug] failed to init input_handle_event\n");
        return ret;
    }

    ret = register_kprobe(&input_event_kp);
    if (ret) {
        pr_err("[ovo_debug] failed to register input_event_kp\n");
        return ret;
    }

    ret = register_kprobe(&input_inject_event_kp);
    if (ret) {
        unregister_kprobe(&input_event_kp);
        pr_err("[ovo_debug] failed to register input_inject_event_kp\n");
        return ret;
    }

    pool = kvmalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool) {
        unregister_kprobe(&input_event_kp);
        unregister_kprobe(&input_inject_event_kp);
        pr_err("[ovo_debug] failed to allocate event pool\n");
        return -ENOMEM;
    }
    pool->size = 0;
    spin_lock_init(&pool->event_lock);

    pr_info("[ovo_debug] module initialized\n");
    return 0;
}

void exit_input_dev(void)
{
    unregister_kprobe(&input_event_kp);
    unregister_kprobe(&input_inject_event_kp);
    if (pool)
        kfree(pool);

    pr_info("[ovo_debug] module exited and resources freed\n");
}
