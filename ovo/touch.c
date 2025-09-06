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
        pr_err("[ovo-debug] wtf? dev is null\n");
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
static void (*my_input_handle_event)(struct input_dev* dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value) = NULL;

// Kprobe resolver
static void* resolve_symbol_with_kprobe(const char* name)
{
    struct kprobe kp = { .symbol_name = (char *)name };
    void* addr = NULL;
    int ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (void*)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

static int init_my_input_handle_event(void)
{
    my_input_handle_event = (void (*)(struct input_dev*, unsigned int, unsigned int, int))
        resolve_symbol_with_kprobe("input_handle_event");
    if (!my_input_handle_event) {
        pr_err("[ovo-debug] Failed to resolve input_handle_event\n");
        return -ENOENT;
    }
    pr_info("[ovo-debug] input_handle_event resolved at %p\n", my_input_handle_event);
    return 0;
}

int input_event_no_lock(struct input_dev* dev,
                        unsigned int type,
                        unsigned int code,
                        int value)
{
    if (!my_input_handle_event) {
        pr_err("[ovo-debug] input_handle_event not initialized\n");
        return -EINVAL;
    }
    if (!dev) {
        pr_err("[ovo-debug] input_event_no_lock called with NULL dev\n");
        return -EINVAL;
    }
    if (is_event_supported(type, dev->evbit, EV_MAX))
        my_input_handle_event(dev, type, code, value);
    return 0;
}

struct input_dev* find_touch_device(void)
{
    static struct input_dev* CACHE = NULL;
    struct input_dev* dev;
    struct list_head* head;
    struct mutex* mut;

    if (CACHE)
        return CACHE;

    head = (struct list_head*)resolve_symbol_with_kprobe("input_dev_list");
    mut = (struct mutex*)resolve_symbol_with_kprobe("input_mutex");

    if (!head || !mut) {
        pr_err("[ovo-debug] failed to find input_dev_list or input_mutex\n");
        return NULL;
    }

    mutex_lock(mut);
    list_for_each_entry(dev, head, node) {
        if (test_bit(EV_ABS, dev->evbit) &&
            (test_bit(ABS_MT_POSITION_X, dev->absbit) ||
             test_bit(ABS_X, dev->absbit))) {
            pr_info("[ovo-debug] Detected device: %s\n", dev->name);
            mutex_unlock(mut);
            CACHE = dev;
            return dev;
        }
    }
    mutex_unlock(mut);
    return NULL;
}

static struct event_pool* pool = NULL;

struct event_pool* get_event_pool(void)
{
    return pool;
}

int input_event_cache(unsigned int type, unsigned int code, int value, int lock)
{
    if (!my_input_handle_event) {
        pr_err("[ovo-debug] input_handle_event not initialized\n");
        return -EINVAL;
    }
    unsigned long flags;
    if (lock)
        spin_lock_irqsave(&pool->event_lock, flags);
    if (pool->size >= MAX_EVENTS) {
        if (lock)
            spin_unlock_irqrestore(&pool->event_lock, flags);
        return -ENOSPC;
    }
    pool->events[pool->size++] = (struct ovo_touch_event){ type, code, value };
    if (lock)
        spin_unlock_irqrestore(&pool->event_lock, flags);
    return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
    struct input_dev* dev = find_touch_device();
    struct input_mt* mt = dev ? dev->mt : NULL;
    int id = 0;
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return 0;
    }
    if (!mt || mt->slot < 0 || mt->slot >= mt->num_slots)
        return -EINVAL;

    struct input_mt_slot* slot = &mt->slots[mt->slot];
    id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);

    if (id < 0)
        id = input_mt_new_trkid(mt);

    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);
    return id;
}

bool input_mt_report_slot_state_with_id_cache(unsigned int tool_type, bool active, int id, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return false;
    }
    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);
    return true;
}

static void print_abs_info(const char* prefix, struct input_dev* dev)
{
    if (!dev || !dev->absinfo)
        return;
    pr_info("%s: abs X: [%d, %d], Y: [%d, %d], Slot: [%d, %d]\n", prefix,
            dev->absinfo[ABS_X].minimum, dev->absinfo[ABS_X].maximum,
            dev->absinfo[ABS_Y].minimum, dev->absinfo[ABS_Y].maximum,
            dev->absinfo[ABS_MT_SLOT].minimum, dev->absinfo[ABS_MT_SLOT].maximum);
}

static void handle_cache_events(struct input_dev* dev)
{
    struct input_mt* mt = dev ? dev->mt : NULL;
    struct input_mt_slot* slot = NULL;
    unsigned long flags1, flags2;
    int id;
    bool need_close = false;
    bool synthetic = false;

    if (!mt || mt->slot < 0 || mt->slot >= mt->num_slots)
        return;

    slot = &mt->slots[mt->slot];
    pr_info("[ovo-debug] Flushing frame for device: %s, slot: %d, tracking_id: %d\n",
        dev->name, mt->slot, input_mt_get_value(slot, ABS_MT_TRACKING_ID));
    print_abs_info("Device ABS Info", dev);

    spin_lock_irqsave(&pool->event_lock, flags2);
    if (pool->size == 0) {
        pr_info("[ovo-debug] No events to flush for device: %s\n", dev->name);
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
            synthetic = true;
            pr_info("[ovo-debug] Synthetic Tracking ID assigned: %d\n", id);
        }

        if (event.type == EV_ABS && event.code == ABS_MT_PRESSURE && event.value == 0) {
            need_close = true;
            pr_info("[ovo-debug] Pressure 0 received, will close tracking id\n");
        }

        pr_info("[ovo-debug] Sending event type: 0x%x, code: 0x%x, value: %d, %s\n",
            event.type, event.code, event.value,
            synthetic ? "Synthetic" : "Original");

        input_event_no_lock(dev, event.type, event.code, event.value);
    }

    if (need_close) {
        pr_info("[ovo-debug] Closing tracking id (sending -1)\n");
        input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
    }

    input_event_no_lock(dev, EV_SYN, SYN_REPORT, 0);
    pr_info("[ovo-debug] Sent EV_SYN (frame commit)\n");

    spin_unlock_irqrestore(&dev->event_lock, flags1);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags2);
}

static int input_handle_event_handler_pre(struct kprobe* p, struct pt_regs* regs)
{
    struct input_dev* dev = (struct input_dev*)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];

    if (!dev || type != EV_SYN)
        return 0;

    pr_info("[ovo-debug] input_event fired: EV_SYN on %s\n", dev->name);
    handle_cache_events(dev);
    return 0;
}

static int input_handle_event_handler2_pre(struct kprobe* p, struct pt_regs* regs)
{
    struct input_handle* handle = (struct input_handle*)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];

    if (!handle || type != EV_SYN)
        return 0;

    pr_info("[ovo-debug] input_inject_event fired: EV_SYN on %s\n", handle->dev ? handle->dev->name : "NULL");
    handle_cache_events(handle->dev);
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
    if (ret)
        return ret;

    ret = register_kprobe(&input_event_kp);
    pr_info("[ovo-debug] input_event_kp: %d\n", ret);
    if (ret)
        return ret;

    ret = register_kprobe(&input_inject_event_kp);
    pr_info("[ovo-debug] input_inject_event_kp: %d\n", ret);
    if (ret) {
        unregister_kprobe(&input_event_kp);
        return ret;
    }

    pool = kcalloc(1, sizeof(*pool), GFP_KERNEL);
    if (!pool) {
        unregister_kprobe(&input_event_kp);
        unregister_kprobe(&input_inject_event_kp);
        return -ENOMEM;
    }

    spin_lock_init(&pool->event_lock);
    pool->size = 0;

    pr_info("[ovo-debug] Module initialized successfully\n");
    return 0;
}

void exit_input_dev(void)
{
    unregister_kprobe(&input_event_kp);
    unregister_kprobe(&input_inject_event_kp);
    if (pool)
        kfree(pool);
    pr_info("[ovo-debug] Module cleanup complete\n");
}
