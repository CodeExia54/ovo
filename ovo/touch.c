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

// Forward declaration
static void handle_cache_events(struct input_dev* dev);

// =============== Global state (no kallsyms, kprobe-only) ===============
static struct input_dev *g_touch_dev;   // cached fts_ts once discovered via kprobes

// Minimal MT-B tracking state
#define MAX_SLOTS 64
static int  mt_slot_trkid[MAX_SLOTS];    // -1 if free (0 means uninit)
static bool mt_slot_active[MAX_SLOTS];
static int  mt_next_trkid = 1;

// =============== Helper: resolve function via kprobe ===============
static void *resolve_symbol_with_kprobe(const char *name)
{
    struct kprobe kp = { .symbol_name = (char *)name };
    void *addr = NULL;
    if (register_kprobe(&kp) == 0) {
        addr = (void *)kp.addr;
        unregister_kprobe(&kp);
    } else {
        pr_err("[ovo_debug] resolve_symbol_with_kprobe failed for %s\n", name);
    }
    return addr;
}

// =============== input_handle_event (no-lock) via kprobe ===============
static void (*my_input_handle_event)(struct input_dev*, unsigned, unsigned, int);

static int init_my_input_handle_event(void)
{
    my_input_handle_event =
        (void(*)(struct input_dev*,unsigned,unsigned,int))
        resolve_symbol_with_kprobe("input_handle_event");
    if (!my_input_handle_event) {
        pr_err("[ovo_debug] failed to resolve input_handle_event\n");
        return -ENOENT;
    }
    pr_info("[ovo_debug] input_handle_event at %p\n", my_input_handle_event);
    return 0;
}

static inline int is_event_supported(unsigned int code,
                                     unsigned long *bm, unsigned int max)
{
    return code <= max && test_bit(code, bm);
}

int input_event_no_lock(struct input_dev *dev,
                        unsigned int type, unsigned int code, int value)
{
    if (!my_input_handle_event || !dev) return -EINVAL;
    if (!is_event_supported(type, dev->evbit, EV_MAX)) return -EINVAL;
    my_input_handle_event(dev, type, code, value);
    return 0;
}

// =============== Device discovery without kallsyms ===============
static struct input_dev* find_touch_device(void)
{
    return g_touch_dev; // set by kprobes below
}

// =============== Event pool and caching (keep API semantics) ===============
static struct event_pool *pool = NULL;
struct event_pool *get_event_pool(void) { return pool; }

// Keep helper intact: cache immediately; we will flush coherently in handle_cache_events
int input_event_cache(unsigned int type, unsigned int code, int value, int lock)
{
    unsigned long flags;

    if (!pool) return -ENOMEM;

    if (lock) spin_lock_irqsave(&pool->event_lock, flags);
    if (pool->size >= MAX_EVENTS) {
        if (lock) spin_unlock_irqrestore(&pool->event_lock, flags);
        return -EFAULT;
    }
    pool->events[pool->size++] = (struct ovo_touch_event){ type, code, value };
    if (lock) spin_unlock_irqrestore(&pool->event_lock, flags);

    // Respect your current behavior: try to flush right away if device known
    // Coherency is enforced inside handle_cache_events to build a proper MT-B frame
    {
        struct input_dev *dev = find_touch_device();
        if (dev) handle_cache_events(dev);
    }

    return 0;
}

// =============== Slot/ID lifecycle helpers ===============
static inline void mt_mark_down(int slot, int id)
{
    if (slot < 0 || slot >= MAX_SLOTS) return;
    mt_slot_trkid[slot] = id;
    mt_slot_active[slot] = true;
}

static inline void mt_mark_up(int slot)
{
    if (slot < 0 || slot >= MAX_SLOTS) return;
    mt_slot_trkid[slot] = -1;
    mt_slot_active[slot] = false;
}

// =============== Coherent frame flusher with MT-B semantics ===============
static void handle_cache_events(struct input_dev* dev)
{
    struct input_mt *mt;
    unsigned long flags_dev, flags_pool;
    int i;
    int cur_slot = 0;

    if (!dev) return;
    mt = dev->mt;
    if (!mt) return;

    // Init per-slot state lazily
    if (mt->num_slots > 0) {
        int n = mt->num_slots < MAX_SLOTS ? mt->num_slots : MAX_SLOTS;
        for (i = 0; i < n; ++i) {
            if (mt_slot_trkid[i] == 0) mt_slot_trkid[i] = -1;
        }
    }

    spin_lock_irqsave(&pool->event_lock, flags_pool);
    if (pool->size == 0) {
        spin_unlock_irqrestore(&pool->event_lock, flags_pool);
        return;
    }

    spin_lock_irqsave(&dev->event_lock, flags_dev);

    // Try to start with current device slot
    cur_slot = (dev->absinfo && dev->absinfo[ABS_MT_SLOT].value >= 0)
               ? dev->absinfo[ABS_MT_SLOT].value : 0;

    for (i = 0; i < pool->size; ++i) {
        struct ovo_touch_event ev = pool->events[i];

        // Track slot changes from cached events
        if (ev.type == EV_ABS && ev.code == ABS_MT_SLOT) {
            cur_slot = ev.value;
            if (cur_slot < 0) cur_slot = 0;
            input_event_no_lock(dev, ev.type, ev.code, ev.value);
            continue;
        }

        // Auto-inject TRACKING_ID for DOWN/MOVE if slot not active yet
        if (ev.type == EV_ABS &&
           (ev.code == ABS_MT_POSITION_X ||
            ev.code == ABS_MT_POSITION_Y ||
            ev.code == ABS_MT_PRESSURE  ||
            ev.code == ABS_MT_TOUCH_MAJOR)) {

            if (cur_slot >= 0 && cur_slot < MAX_SLOTS) {
                if (mt_slot_trkid[cur_slot] < 0) {
                    int new_id = mt_next_trkid++;
                    input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, new_id);
                    mt_mark_down(cur_slot, new_id);
                }
            }
        }

        // Preserve sentinel behavior: -114514 means "assign new id now"
        if (ev.type == EV_ABS && ev.code == ABS_MT_TRACKING_ID && ev.value == -114514) {
            int injected = mt_next_trkid++;
            input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, injected);
            mt_mark_down(cur_slot, injected);
            continue;
        }

        // Emit the cached event
        input_event_no_lock(dev, ev.type, ev.code, ev.value);

        // If pressure is zero, close the contact in the same frame
        if (ev.type == EV_ABS && ev.code == ABS_MT_PRESSURE && ev.value == 0) {
            if (cur_slot >= 0 && cur_slot < MAX_SLOTS && mt_slot_trkid[cur_slot] >= 0) {
                input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                mt_mark_up(cur_slot);
            }
        }
    }

    // End of frame
    input_event_no_lock(dev, EV_SYN, SYN_REPORT, 0);

    spin_unlock_irqrestore(&dev->event_lock, flags_dev);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags_pool);
}

// =============== Optional helpers (unchanged signatures) ===============
int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return 0;
    }
    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -114514, lock); // sentinel: assign in flusher
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE,    tool_type, lock);
    return 0;
}

bool input_mt_report_slot_state_with_id_cache(unsigned int tool_type,
                                              bool active, int id, int lock)
{
    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return false;
    }
    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE,    tool_type, lock);
    return true;
}

// =============== kprobe pre-handlers (device discovery + flush triggers) ===============
// 1) Discover and cache fts_ts when driver registers the input device
static int input_register_device_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_dev *dev = (struct input_dev *)regs->regs;
#else
    struct input_dev *dev = NULL;
#endif
    if (!dev || g_touch_dev) return 0;
    if (dev->name && strcmp(dev->name, "fts_ts") == 0 &&
        test_bit(EV_ABS, dev->evbit) && test_bit(ABS_MT_POSITION_X, dev->absbit)) {
        g_touch_dev = dev;
        pr_info("[ovo_debug] cached touch dev via input_register_device: %s\n", dev->name);
    }
    return 0;
}

// 2) Also latch device lazily when first events flow through input_event
static int input_event_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_dev* dev = (struct input_dev*)regs->regs;
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[3];
#else
    struct input_dev* dev = NULL; unsigned int type = 0, code = 0;
#endif
    if (dev && !g_touch_dev && dev->name && strcmp(dev->name, "fts_ts") == 0) {
        g_touch_dev = dev;
        pr_info("[ovo_debug] cached touch dev via input_event: %s\n", dev->name);
    }
    // Let EV_SYN also trigger a flush if needed
    if (g_touch_dev == dev && type == EV_SYN && code == SYN_REPORT) handle_cache_events(dev);
    return 0;
}

// 3) Userspace injected path: same lazy latch and flush-on-sync
static int input_inject_event_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_handle* handle = (struct input_handle*)regs->regs;
    unsigned int type = (unsigned int)regs->regs[1];
    unsigned int code = (unsigned int)regs->regs[3];
    struct input_dev* dev = handle ? handle->dev : NULL;
#else
    struct input_dev* dev = NULL; unsigned int type=0, code=0;
#endif
    if (dev && !g_touch_dev && dev->name && strcmp(dev->name, "fts_ts") == 0) {
        g_touch_dev = dev;
        pr_info("[ovo_debug] cached touch dev via input_inject_event: %s\n", dev->name);
    }
    if (g_touch_dev == dev && type == EV_SYN && code == SYN_REPORT) handle_cache_events(dev);
    return 0;
}

// 4) Optional: frame sync hook can also flush
static int input_mt_sync_frame_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
    struct input_dev* dev = (struct input_dev*)regs->regs;
#else
    struct input_dev* dev = NULL;
#endif
    if (dev && dev == g_touch_dev) handle_cache_events(dev);
    return 0;
}

// =============== Kprobe descriptors ===============
static struct kprobe kp_input_register_device = {
    .symbol_name = "input_register_device",
    .pre_handler = input_register_device_pre,
};

static struct kprobe kp_input_event = {
    .symbol_name = "input_event",
    .pre_handler = input_event_pre,
};

static struct kprobe kp_input_inject_event = {
    .symbol_name = "input_inject_event",
    .pre_handler = input_inject_event_pre,
};

static struct kprobe kp_input_mt_sync_frame = {
    .symbol_name = "input_mt_sync_frame",
    .pre_handler = input_mt_sync_frame_pre,
};

// =============== Module init/exit ===============
int init_input_dev(void)
{
    int ret, i;

    // init per-slot state
    for (i = 0; i < MAX_SLOTS; ++i) { mt_slot_trkid[i] = -1; mt_slot_active[i] = false; }
    mt_next_trkid = 1;

    ret = init_my_input_handle_event();
    if (ret) return ret;

    ret = register_kprobe(&kp_input_register_device);
    if (ret) return ret;

    ret = register_kprobe(&kp_input_event);
    if (ret) { unregister_kprobe(&kp_input_register_device); return ret; }

    ret = register_kprobe(&kp_input_inject_event);
    if (ret) {
        unregister_kprobe(&kp_input_event);
        unregister_kprobe(&kp_input_register_device);
        return ret;
    }

    ret = register_kprobe(&kp_input_mt_sync_frame);
    if (ret) {
        unregister_kprobe(&kp_input_inject_event);
        unregister_kprobe(&kp_input_event);
        unregister_kprobe(&kp_input_register_device);
        return ret;
    }

    pool = kvmalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool) {
        unregister_kprobe(&kp_input_mt_sync_frame);
        unregister_kprobe(&kp_input_inject_event);
        unregister_kprobe(&kp_input_event);
        unregister_kprobe(&kp_input_register_device);
        return -ENOMEM;
    }
    pool->size = 0;
    spin_lock_init(&pool->event_lock);

    pr_info("[ovo_debug] init_input_dev OK (kprobe-only resolution)\n");
    return 0;
}

void exit_input_dev(void)
{
    unregister_kprobe(&kp_input_mt_sync_frame);
    unregister_kprobe(&kp_input_inject_event);
    unregister_kprobe(&kp_input_event);
    unregister_kprobe(&kp_input_register_device);

    if (pool) { kfree(pool); pool = NULL; }
    pr_info("[ovo_debug] exit_input_dev done\n");
}

