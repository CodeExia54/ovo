//
// Created by fuqiuluo on 25-2-9.
//
#pragma GCC diagnostic ignored "-Wdeclaration-after-statements"

#include "touch.h"
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/input/mt.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/input-event-codes.h>
#include "kkit.h"

// Forward declaration
static void handle_cache_events(struct input_dev* dev);

// Module param: target device name
static char *touch_name = "fts_ts";
module_param(touch_name, charp, 0644);
MODULE_PARM_DESC(touch_name, "Target input device name");

// Global device pointer latched by kprobe
static struct input_dev *g_touch_dev;

// Max slots, tracking per slot
#define MAX_SLOTS 64
static int  mt_slot_trkid[MAX_SLOTS];    // -1 = free
static bool mt_slot_active[MAX_SLOTS];
static int  mt_next_trkid = 1;

// Resolve non-exported function by kprobe
static void *resolve_symbol_with_kprobe(const char *name)
{
    struct kprobe kp = { .symbol_name = (char *)name };
    void *addr = NULL;
    if (register_kprobe(&kp) == 0) {
        addr = (void *)kp.addr;
        unregister_kprobe(&kp);
    } else {
        pr_err("[ovo] Failed to resolve %s\n", name);
    }
    return addr;
}

// Pointer to input_handle_event function
static void (*my_input_handle_event)(struct input_dev*, unsigned, unsigned, int);

// Initialize input_handle_event pointer
static int init_my_input_handle_event(void)
{
    my_input_handle_event = (void(*)(struct input_dev*, unsigned, unsigned, int))
        resolve_symbol_with_kprobe("input_handle_event");
    if (!my_input_handle_event) {
        pr_err("[ovo] Failed to resolve input_handle_event\n");
        return -ENOENT;
    }
    pr_info("[ovo] input_handle_event at %p\n", my_input_handle_event);
    return 0;
}

// Check if event supported by device
static inline int is_event_supported(unsigned code, unsigned long *bm, unsigned max)
{
    return code <= max && test_bit(code, bm);
}

// Emit event through input_handle_event
int input_event_no_lock(struct input_dev *dev, unsigned type, unsigned code, int value)
{
    if (!my_input_handle_event || !dev)
        return -EINVAL;
    if (!is_event_supported(type, dev->evbit, EV_MAX))
        return -EINVAL;
    pr_info("[ovo] emit: dev=%s type=%u code=%u value=%d\n", dev->name ?: "NULL", type, code, value);
    my_input_handle_event(dev, type, code, value);
    return 0;
}

// Provide find function matching header
struct input_dev* find_touch_device(void)
{
    return g_touch_dev;
}

// Event pool definition (should be in header included elsewhere)
#define MAX_EVENTS 256 // safe max events in pool
struct ovo_touch_event { unsigned type; unsigned code; int value; };
struct event_pool {
    spinlock_t event_lock;
    unsigned size;
    struct ovo_touch_event events[MAX_EVENTS];
};
static struct event_pool *pool;

struct event_pool *get_event_pool(void) { return pool; }

// Cache event for later flush
int input_event_cache(unsigned type, unsigned code, int value, int lock)
{
    unsigned long flags;
    if (!pool) return -ENOMEM;
    if (lock)
        spin_lock_irqsave(&pool->event_lock, flags);

    if (pool->size >= MAX_EVENTS) {
        if (lock)
            spin_unlock_irqrestore(&pool->event_lock, flags);
        pr_err("[ovo] event pool overflow\n");
        return -EBUSY;
    }
    pool->events[pool->size++] = (struct ovo_touch_event){type, code, value};
    if (lock)
        spin_unlock_irqrestore(&pool->event_lock, flags);

    // Optional: flush immediately if device ready for responsiveness
    {
        struct input_dev *dev = find_touch_device();
        if (dev)
            handle_cache_events(dev);
    }
    return 0;
}

// Mark slot as occupied/free
static inline void mt_mark_down(int slot, int id)
{
    if (slot < 0 || slot >= MAX_SLOTS)
        return;
    mt_slot_trkid[slot] = id;
    mt_slot_active[slot] = true;
}

static inline void mt_mark_up(int slot)
{
    if (slot < 0 || slot >= MAX_SLOTS)
        return;
    mt_slot_trkid[slot] = -1;
    mt_slot_active[slot] = false;
}

// Flush all cached events as a full frame with proper slots and IDs
static void handle_cache_events(struct input_dev *dev)
{
    struct input_mt *mt = dev->mt;
    unsigned long flags1, flags2;
    int i, cur_slot;

    if (!mt)
        return;

    // Initialize slot state if not already
    for (i = 0; i < MAX_SLOTS && i < mt->num_slots; i++) {
        if (mt_slot_trkid[i] == 0)
            mt_slot_trkid[i] = -1;
    }

    spin_lock_irqsave(&pool->event_lock, flags2);
    if (pool->size == 0) {
        spin_unlock_irqrestore(&pool->event_lock, flags2);
        return;
    }

    spin_lock_irqsave(&dev->event_lock, flags1);

    cur_slot = (dev->absinfo && dev->absinfo[ABS_MT_SLOT].value >= 0)
               ? dev->absinfo[ABS_MT_SLOT].value : 0;

    pr_info("[ovo] flushing %u events on %s starting from slot %d\n",
        pool->size, dev->name, cur_slot);

    for (i = 0; i < pool->size; i++) {
        struct ovo_touch_event *ev = &pool->events[i];

        pr_info("[ovo] ev[%d]: type %u code %u val %d slot %d\n",
            i, ev->type, ev->code, ev->value, cur_slot);

        if (ev->type == EV_ABS && ev->code == ABS_MT_SLOT) {
            cur_slot = ev->value;
            if (cur_slot < 0)
                cur_slot = 0;
            input_event_no_lock(dev, ev->type, ev->code, ev->value);
            continue;
        }

        if (ev->type == EV_ABS &&
          (ev->code == ABS_MT_POSITION_X ||
           ev->code == ABS_MT_POSITION_Y ||
           ev->code == ABS_MT_PRESSURE ||
           ev->code == ABS_MT_TOUCH_MAJOR)) {
            if (cur_slot >= 0 && cur_slot < MAX_SLOTS && mt_slot_trkid[cur_slot] == -1) {
                int tid = mt_next_trkid++;
                pr_info("[ovo] assign new TRACKING_ID %d for slot %d\n", tid, cur_slot);
                input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, tid);
                mt_mark_down(cur_slot, tid);
            }
        }

        if (ev->type == EV_ABS && ev->code == ABS_MT_TRACKING_ID && ev->value == -114514) {
            int tid = mt_next_trkid++;
            pr_info("[ovo] sentinel TRACKING_ID assigned %d slot %d\n", tid, cur_slot);
            input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, tid);
            mt_mark_down(cur_slot, tid);
            continue;
        }

        input_event_no_lock(dev, ev->type, ev->code, ev->value);

        if (ev->type == EV_ABS && ev->code == ABS_MT_PRESSURE && ev->value == 0) {
            if (cur_slot >= 0 && cur_slot < MAX_SLOTS && mt_slot_trkid[cur_slot] != -1) {
                pr_info("[ovo] lift slot %d, TRACKING_ID -1\n", cur_slot);
                input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                mt_mark_up(cur_slot);
            }
        }
    }

    input_event_no_lock(dev, EV_SYN, SYN_REPORT, 0);
    pr_info("[ovo] Emit EV_SYN (frame end)\n");

    spin_unlock_irqrestore(&dev->event_lock, flags1);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags2);
}

// Optional helpers
int input_mt_report_state(struct input_dev *dev, int slot, bool active, int id, unsigned tool_type, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_SLOT, slot, lock);
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return 0;
    }
    if (!input_mt_valid_slot(dev->mt, slot))
        return -EINVAL;

    input_event_cache(EV_ABS, ABS_MT_SLOT, slot, lock);
    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);
    return id;
}

// Kprobe handlers
static int input_register_device_handler(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_dev *dev = (struct input_dev *)regs->regs[0];
#else
    struct input_dev *dev = NULL;
#endif
    if (dev && !g_touch_dev && dev->name && strcmp(dev->name, touch_name) == 0) {
        pr_info("[ovo] Latched device: %s\n", dev->name);
        g_touch_dev = dev;
    }
    return 0;
}

static int input_event_handler(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_dev *dev = (struct input_dev *)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];
    int value = (int)regs->regs[3];
#else
    struct input_dev *dev = NULL;
    unsigned int type = 0, code = 0;
    int value = 0;
#endif
    if (dev && !g_touch_dev && dev->name && strcmp(dev->name, touch_name) == 0) {
        pr_info("[ovo] Latched device via event: %s\n", dev->name);
        g_touch_dev = dev;
    }
    pr_info("[ovo] Event: dev=%s type=%u code=%u value=%d\n",
        dev ? dev->name : "NULL", type, code, value);
    
    if (dev == g_touch_dev && type == EV_SYN && code == SYN_REPORT) {
        handle_cache_events(dev);
    }
    return 0;
}

static int input_inject_handler(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_handle *handle = (struct input_handle *)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[2];
    int value = (int)regs->regs[3];
    struct input_dev *dev = handle ? handle->dev : NULL;
#else
    struct input_handle *handle = NULL;
    unsigned int type = 0, code = 0;
    int value = 0;
    struct input_dev *dev = NULL;
#endif
    if (dev && !g_touch_dev && dev->name && strcmp(dev->name, touch_name) == 0) {
        pr_info("[ovo] Latched device via inject: %s\n", dev->name);
        g_touch_dev = dev;
    }
    pr_info("[ovo] Inject event: dev=%s type=%u code=%u value=%d\n",
        dev ? dev->name : "NULL", type, code, value);
    
    if (dev == g_touch_dev && type == EV_SYN && code == SYN_REPORT) {
        handle_cache_events(dev);
    }
    return 0;
}

static int input_sync_handler(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_dev *dev = (struct input_dev *)regs->regs[0];
#else
    struct input_dev *dev = NULL;
#endif
    if (dev == g_touch_dev) {
        pr_info("[ovo] Sync event on %s\n", dev->name);
        handle_cache_events(dev);
    }
    return 0;
}

static struct kprobe kp_register = {
    .symbol_name = "input_register_device",
    .pre_handler = input_register_device_handler,
};

static struct kprobe kp_event = {
    .symbol_name = "input_event",
    .pre_handler = input_event_handler,
};

static struct kprobe kp_inject = {
    .symbol_name = "input_inject_event",
    .pre_handler = input_inject_handler,
};

static struct kprobe kp_sync = {
    .symbol_name = "input_mt_sync_frame",
    .pre_handler = input_sync_handler,
};

// Module init and exit
int init_module(void)
{
    int ret, i;
    pr_info("[ovo] Module init starting\n");

    // Init tracking
    for (i = 0; i < MAX_SLOTS; i++) {
        mt_slot_trkid[i] = -1;
        mt_slot_active[i] = false;
    }
    mt_next_trkid = 1;

    ret = init_my_input_handle_event();
    if (ret)
        return ret;

    ret = register_kprobe(&kp_register);
    if (ret)
        return ret;

    ret = register_kprobe(&kp_event);
    if (ret) {
        unregister_kprobe(&kp_register);
        return ret;
    }

    ret = register_kprobe(&kp_inject);
    if (ret) {
        unregister_kprobe(&kp_register);
        unregister_kprobe(&kp_event);
        return ret;
    }

    ret = register_kprobe(&kp_sync);
    if (ret) {
        unregister_kprobe(&kp_register);
        unregister_kprobe(&kp_event);
        unregister_kprobe(&kp_inject);
        return ret;
    }

    pool = kvmalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool) {
        unregister_kprobe(&kp_register);
        unregister_kprobe(&kp_event);
        unregister_kprobe(&kp_inject);
        unregister_kprobe(&kp_sync);
        return -ENOMEM;
    }
    pool->size = 0;
    spin_lock_init(&pool->event_lock);

    pr_info("[ovo] Module init complete\n");
    return 0;
}

void cleanup_module(void)
{
    unregister_kprobe(&kp_register);
    unregister_kprobe(&kp_event);
    unregister_kprobe(&kp_inject);
    unregister_kprobe(&kp_sync);

    if (pool) {
        kfree(pool);
        pool = NULL;
    }
    pr_info("[ovo] Module cleanup complete\n");
}
