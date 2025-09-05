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
    } else {
        pr_err("[ovo_debug] resolve_symbol_with_kprobe failed for %s, ret = %d\n", name, ret);
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

/* Synthetic tracking id counter: kernel will use these to avoid calling non-existent helpers.
 * Start at a high value to minimize collision with hardware-generated ids. */
static int synthetic_trkid = 1000000;

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
        pr_info("[ovo_debug] input_event_cache: acquiring pool lock at jiffies=%lu\n", jiffies);

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

    return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock)
{
    int id;   // Declare id here to fix undeclared usage

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
        /* replaced input_mt_new_trkid with module counter */
        synthetic_trkid++;
        id = synthetic_trkid;
        pr_info("[ovo_debug] input_mt_report_slot_state_cache: kernel generated tracking id %d at slot %d, jiffies=%lu\n",
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
    int id = 0;  // Declare id here

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

    pr_info("[ovo_debug] handle_cache_events: processing %u event(s) on device %s slot=%d at jiffies=%lu\n",
            pool->size, dev->name, mt->slot, jiffies);

    spin_lock_irqsave(&dev->event_lock, flags1);

    /*
     * Strategy:
     * - Track the current ABS_MT_SLOT value while iterating events.
     * - If userspace did not provide ABS_MT_TRACKING_ID for a slot and the slot is currently free,
     *   allocate a tracking id (synthetic_trkid++) and inject it before position/pressure events.
     * - If userspace requested a slot that is already occupied by hardware, remap to a free slot.
     * - After processing all events, automatically release (ABS_MT_TRACKING_ID = -1) only those
     *   tracking IDs that the kernel allocated in this frame.
     */

    int current_slot = -1;
    int num_slots = mt->num_slots;
    bool *kernel_allocated = NULL; /* which slots got a kernel allocated tracking id this frame */
    int *alloc_id = NULL;          /* store the id allocated for each slot (if any) */

    /* Allocate per-frame bookkeeping arrays with GFP_ATOMIC since kprobe context may be atomic */
    kernel_allocated = kcalloc(num_slots, sizeof(bool), GFP_ATOMIC);
    alloc_id = kcalloc(num_slots, sizeof(int), GFP_ATOMIC);
    if (!kernel_allocated || !alloc_id) {
        pr_err("[ovo_debug] handle_cache_events: allocation failed for bookkeeping arrays\n");
        kfree(kernel_allocated);
        kfree(alloc_id);
        spin_unlock_irqrestore(&dev->event_lock, flags1);
        pool->size = 0;
        spin_unlock_irqrestore(&pool->event_lock, flags2);
        return;
    }

    int i;
    for (i = 0; i < pool->size; ++i) {
        struct ovo_touch_event event = pool->events[i];

        /* Update current_slot when ABS_MT_SLOT seen */
        if (event.type == EV_ABS && event.code == ABS_MT_SLOT) {
            int requested_slot = event.value;
            current_slot = requested_slot;

            /* If requested slot in range, check occupancy and remap if occupied */
            if (requested_slot >= 0 && requested_slot < num_slots) {
                int existing = input_mt_get_value(&mt->slots[requested_slot], ABS_MT_TRACKING_ID);
                if (existing >= 0) {
                    /* requested slot already occupied by hardware or other active touch -> find free slot */
                    int free_slot = -1;
                    int s;
                    for (s = 0; s < num_slots; ++s) {
                        int v = input_mt_get_value(&mt->slots[s], ABS_MT_TRACKING_ID);
                        if (v < 0 && !kernel_allocated[s]) {
                            free_slot = s;
                            break;
                        }
                    }
                    if (free_slot >= 0) {
                        pr_info("[ovo_debug] handle_cache_events: remapping requested slot %d -> free slot %d because requested occupied (existing id=%d)\n",
                                requested_slot, free_slot, existing);
                        current_slot = free_slot;
                    } else {
                        /* No free slot found: choose requested_slot but warn (risk of stomping). */
                        pr_warn("[ovo_debug] handle_cache_events: no free slot found to remap requested slot %d; using it anyway (existing id=%d)\n",
                                requested_slot, existing);
                        current_slot = requested_slot;
                    }
                } else {
                    /* requested slot is free; OK to use as-is */
                    pr_info("[ovo_debug] handle_cache_events: using requested slot %d (free)\n", requested_slot);
                }
            } else {
                pr_err("[ovo_debug] handle_cache_events: ABS_MT_SLOT value %d out of range\n", requested_slot);
            }

            /* Emit the (possibly remapped) ABS_MT_SLOT event */
            pr_info("[ovo_debug] handle_cache_events: emitting ABS_MT_SLOT=%d (event #%d)\n", current_slot, i);
            input_event_no_lock(dev, EV_ABS, ABS_MT_SLOT, current_slot);
            continue;
        }

        /* If event is TRACKING_ID and positive, user provided it: mark alloc arrays accordingly (do not auto-release) */
        if (event.type == EV_ABS && event.code == ABS_MT_TRACKING_ID) {
            pr_info("[ovo_debug] handle_cache_events: saw ABS_MT_TRACKING_ID=%d for current_slot=%d (event #%d)\n",
                    event.value, current_slot, i);
            /* emit whatever userspace provided */
            input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, event.value);
            /* If userspace provided a positive id, we should NOT auto-release it later */
            if (current_slot >= 0 && current_slot < num_slots && event.value >= 0) {
                kernel_allocated[current_slot] = false;
                alloc_id[current_slot] = event.value;
            } else if (current_slot >= 0 && current_slot < num_slots && event.value < 0) {
                /* userspace explicitly released the slot; ensure we don't auto-release */
                kernel_allocated[current_slot] = false;
                alloc_id[current_slot] = -1;
            }
            continue;
        }

        /* For position, pressure, tool_type, etc:
         * If current slot has no tracking id and the userspace hasn't provided one earlier in this frame,
         * allocate one now and emit it.
         */
        if (event.type == EV_ABS &&
            (event.code == ABS_MT_POSITION_X || event.code == ABS_MT_POSITION_Y ||
             event.code == ABS_MT_PRESSURE || event.code == ABS_MT_TOOL_TYPE)) {

            if (current_slot >= 0 && current_slot < num_slots) {
                int existing = input_mt_get_value(&mt->slots[current_slot], ABS_MT_TRACKING_ID);
                if (existing < 0 && !kernel_allocated[current_slot] && alloc_id[current_slot] <= 0) {
                    /*
                     * No tracking id currently for this slot and userspace didn't give one earlier in this frame:
                     * allocate and emit a new tracking id now using synthetic_trkid.
                     */
                    synthetic_trkid++;
                    int newtrkid = synthetic_trkid;
                    alloc_id[current_slot] = newtrkid;
                    kernel_allocated[current_slot] = true;
                    pr_info("[ovo_debug] handle_cache_events: kernel allocated new synthetic tracking id %d for slot %d at event #%d\n",
                            newtrkid, current_slot, i);
                    /* Emit the tracking id for this slot before position/pressure */
                    input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, newtrkid);
                    /* Emit a tool type if driver expects it */
                    input_event_no_lock(dev, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
                } else {
                    pr_info("[ovo_debug] handle_cache_events: slot %d already has existing tracking id %d or was allocated earlier in this frame\n",
                            current_slot, existing);
                }
            } else {
                pr_warn("[ovo_debug] handle_cache_events: position/pressure event with no current_slot (event #%d)\n", i);
            }

            /* Emit the original position/pressure/tool event */
            pr_info("[ovo_debug] handle_cache_events: emitting event #%d: type=%u code=%u value=%d\n",
                    i, event.type, event.code, event.value);
            input_event_no_lock(dev, event.type, event.code, event.value);
            continue;
        }

        /* Other events (EV_KEY, EV_SYN variants etc.) just forward */
        pr_info("[ovo_debug] handle_cache_events: emitting other event #%d: type=%u code=%u value=%d\n",
                i, event.type, event.code, event.value);
        input_event_no_lock(dev, event.type, event.code, event.value);
    }

    /*
     * After iterating events: auto-release any slots for which we allocated a tracking id this frame.
     * This turns a single press frame into press+immediate-release (a tap).
     * We only auto-release those IDs that kernel_allocated[] is true.
     */
    int s;
    for (s = 0; s < num_slots; ++s) {
        if (kernel_allocated[s]) {
            int allocated_trkid = alloc_id[s];
            pr_info("[ovo_debug] handle_cache_events: auto-releasing slot %d synthetic tracking id %d\n", s, allocated_trkid);
            /* ensure slot selection is emitted */
            input_event_no_lock(dev, EV_ABS, ABS_MT_SLOT, s);
            /* send tracking id = -1 to release */
            input_event_no_lock(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        }
    }

    /* Synchronize MT frame properly for protocol B consumers, then send SYN_REPORT */
    input_mt_sync_frame(dev); /* keep MT bookkeeping consistent */
    pr_info("[ovo_debug] handle_cache_events: sending EV_SYN (SYN_REPORT) at jiffies=%lu\n", jiffies);
    int ret_sync = input_event_no_lock(dev, EV_SYN, SYN_REPORT, 0);
    if (ret_sync != 0)
        pr_err("[ovo_debug] handle_cache_events: input_event_no_lock returned %d for EV_SYN\n", ret_sync);
    else
        pr_info("[ovo_debug] handle_cache_events: EV_SYN sent successfully at jiffies=%lu\n", jiffies);

    /* cleanup per-frame bookkeeping */
    kfree(kernel_allocated);
    kfree(alloc_id);

    spin_unlock_irqrestore(&dev->event_lock, flags1);
    pool->size = 0;
    spin_unlock_irqrestore(&pool->event_lock, flags2);

    pr_info("[ovo_debug] handle_cache_events exit for device %s at jiffies=%lu\n", dev->name, jiffies);
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

    if (type == EV_ABS && (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y || code == ABS_MT_TRACKING_ID)) {
        pr_info("[ovo_debug_user] Userspace touch event seen: type=%u code=%u value=%d at jiffies=%lu\n",
                type, code, value, jiffies);
    }

    if (type != EV_SYN) {
        return 0;
    }

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

    pr_info("[ovo_debug_kprobe] input_inject_event fired: dev=%s type=%u code=%u value=%d at jiffies=%lu\n",
            dev->name, type, code, value, jiffies);

    if (type == EV_ABS && (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y || code == ABS_MT_TRACKING_ID)) {
        pr_info("[ovo_debug_user] Userspace injected event via input_inject_event: type=%u code=%u value=%d at jiffies=%lu\n",
                type, code, value, jiffies);
    }

    if (type != EV_SYN) {
        return 0;
    }

    handle_cache_events(dev);

    return 0;
}

static int input_mt_sync_frame_pre(struct kprobe *p, struct pt_regs *regs) {
    struct input_dev* dev = (struct input_dev*)regs->regs[0];
    if(!dev) {
        return 0;
    }
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
