/*
 * Copyright (C) 2010-2011, Andreas Sandberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <assert.h>

#include "expect.h"
#include "perf_argp.h"

static const char prefix_sw_event[] = "sw:";
static const char prefix_hw_event[] = "hw:";
static const char prefix_hwc_event[] = "hwc:";
static const char prefix_raw_event[] = "raw:";

typedef struct {
    const char *name;
    const uint64_t id;
} event_name_id_t;

const event_name_id_t sw_events[] = {
    { "cpu_clock", PERF_COUNT_SW_CPU_CLOCK },
    { "task_clock", PERF_COUNT_SW_TASK_CLOCK },
    { "page_faults", PERF_COUNT_SW_PAGE_FAULTS },
    { "context_switches", PERF_COUNT_SW_CONTEXT_SWITCHES },
    { "cpu_migrations", PERF_COUNT_SW_CPU_MIGRATIONS },
    { "page_faults_min", PERF_COUNT_SW_PAGE_FAULTS_MIN },
    { "page_faults_maj", PERF_COUNT_SW_PAGE_FAULTS_MAJ },

    { NULL, 0 }
};

const event_name_id_t hw_events[] = {
    { "cpu_cycles", PERF_COUNT_HW_CPU_CYCLES },
    { "instructions", PERF_COUNT_HW_INSTRUCTIONS },
    { "cache_references", PERF_COUNT_HW_CACHE_REFERENCES },
    { "cache_misses", PERF_COUNT_HW_CACHE_MISSES },
    { "branch_instructions", PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
    { "branch_misses", PERF_COUNT_HW_BRANCH_MISSES },
    { "bus_cycles", PERF_COUNT_HW_BUS_CYCLES },

    { NULL, 0 }
};

const event_name_id_t hwc_events[] = {
    { "l1d", PERF_COUNT_HW_CACHE_L1D },
    { "l1i", PERF_COUNT_HW_CACHE_L1I },
    { "ll", PERF_COUNT_HW_CACHE_LL },
    { "dtlb", PERF_COUNT_HW_CACHE_DTLB },
    { "itlb", PERF_COUNT_HW_CACHE_ITLB },
    { "bpu", PERF_COUNT_HW_CACHE_BPU },

    { NULL, 0 }
};

struct perf_event_attr perf_base_attr = {
    .disabled = 0,
    .inherit = 0,

    /* The following should only be set for the group leader */
    .pinned = 0,
    .exclusive = 0,

    .exclude_user = 0,
    .exclude_kernel = 1,
    .exclude_hv = 1,
    .exclude_idle = 1,

    .mmap = 0,
    .comm = 0,
    .freq = 0,
    .inherit_stat = 0,
    .enable_on_exec = 0,
    .task = 0,
    .watermark = 0,
#ifdef HAVE_PRECISE_IP
    .precise_ip = 0,
#endif
};

ctr_list_t perf_ctrs = { NULL, NULL };
 
enum {
    KEY_PINNED = -1,
    KEY_EXCLUSIVE = -2,
    KEY_SAMPLE_PERIOD = -3,
    KEY_SAMPLE_FREQ = -4,
#ifdef HAVE_PRECISE_IP
    KEY_PRECISE_IP = -5,
#endif
};

static struct argp_option options[] = {
    { NULL, 0, NULL, 0,
      "Counter group settings:", 1 },
    { "pinned", KEY_PINNED, NULL, 0, "Must always be on PMU (see perf docs)", 1 },
    { "exclusive", KEY_EXCLUSIVE, NULL, 0, "Only group on PMU (see perf docs)", 1 },

    { NULL, 0, NULL, 0,
      "Per event settings (sets defaults if no event has been specified):", 2 },
    { "event", 'e', "EVENT", 0,
      "Use raw performance event EVENT (creates a new event)", 0 },
    { "sample-period", KEY_SAMPLE_PERIOD, "N", 0, "Use sample period N", 2 },
    { "sample-freq", KEY_SAMPLE_FREQ, "N", 0, "Use sample frequency N", 2 },
#ifdef HAVE_PRECISE_IP
    { "precise-ip", KEY_PRECISE_IP, "N", 0, "Set the precise_ip field to N", 2 },
#endif
    { 0 }
};

static ctr_t *
init_ctr(uint64_t type, uint64_t config)
{
    ctr_t *ctr;

    ctr = ctr_create(&perf_base_attr);
    EXPECT(ctr != NULL);

    ctr->attr.type = type;
    ctr->attr.config = config;

    if (perf_ctrs.head) {
        /* These should only be set for the group leader */
        ctr->attr.pinned = 0;
        ctr->attr.exclusive = 0;
    }

    return ctrs_add(&perf_ctrs, ctr);
}

long
perf_argp_parse_long(const char *name, const char *arg, struct argp_state *state)
{
    char *endptr;
    long value;

    errno = 0;
    value = strtol(arg, &endptr, 0);
    if (errno)
        argp_failure(state, EXIT_FAILURE, errno,
                     "Invalid %s", name);
    else if (*arg == '\0' || *endptr != '\0')
        argp_error(state, "Invalid %s: '%s' is not a number.\n", name, arg);

    return value;
}

static const event_name_id_t *
find_event(const event_name_id_t *list, const char *name, int extended)
{
    assert(list);
    assert(name);

    for (const event_name_id_t *cur = list; cur->name; cur++) {
        const int cur_len = strlen(cur->name);
        if (!strncmp(cur->name, name, cur_len) &&
            (name[cur_len] == '\0' || (extended && name[cur_len] == ':')))
            return cur;
    }

    return NULL;
}

static int
is_sw_event(const char *arg)
{
    return !strncmp(prefix_sw_event, arg, sizeof(prefix_sw_event) - 1);
}

static void
init_sw_ctr(const char *arg, struct argp_state *state)
{
    assert(is_sw_event(arg));
    const char *ctr = arg + sizeof(prefix_sw_event) - 1;
    const event_name_id_t *event = find_event(sw_events, ctr, 0);

    if (event)
        init_ctr(PERF_TYPE_SOFTWARE, event->id);
    else
        argp_error(state, "Invalid software event specified.\n");
}

static int
is_hw_event(const char *arg)
{
    return !strncmp(prefix_hw_event, arg, sizeof(prefix_hw_event) - 1);
}

static void
init_hw_ctr(const char *arg, struct argp_state *state)
{
    assert(is_hw_event(arg));
    const char *ctr = arg + sizeof(prefix_hw_event) - 1;
    const event_name_id_t *event = find_event(hw_events, ctr, 0);

    if (event)
        init_ctr(PERF_TYPE_HARDWARE, event->id);
    else
        argp_error(state, "Invalid hardware event specified.\n");
}

static int
is_hwc_event(const char *arg)
{
    return !strncmp(prefix_hwc_event, arg, sizeof(prefix_hwc_event) - 1);
}

static void
init_hwc_ctr(const char *arg, struct argp_state *state)
{
    assert(is_hwc_event(arg));
    const char *ctr = arg + sizeof(prefix_hwc_event) - 1;
    const event_name_id_t *event = find_event(hwc_events, ctr, 1);

    if (event) {
        const int event_name_len = strlen(event->name);
        const char *cur = ctr + event_name_len;
        uint8_t cache_id = (uint8_t)event->id;
        uint8_t op_id;
        uint8_t res_id;

        if (cur[0] != ':' || cur[1] == '\0')
            argp_error(state, "No cache op specified.\n");

        switch (*(++cur)) {
        case 'r':
            op_id = PERF_COUNT_HW_CACHE_OP_READ;
            break;
        case 'w':
            op_id = PERF_COUNT_HW_CACHE_OP_WRITE;
            break;
        case 'p':
            op_id = PERF_COUNT_HW_CACHE_OP_PREFETCH;
            break;
        default:
            argp_error(state, "Invalid cache op specified.\n");
        }

        cur++;
        if (cur[0] != ':' || cur[1] == '\0')
            argp_error(state, "No cache result specified.\n");

        switch (*(++cur)) {
        case 'a':
            res_id = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
            break;
        case 'm':
            res_id = PERF_COUNT_HW_CACHE_RESULT_MISS;
            break;
        default:
            argp_error(state, "Invalid cache result specified.\n");
        }

        cur++;
        if (cur[0] != '\0')
            argp_error(state, "Illegal HWC string specified.\n");

        init_ctr(PERF_TYPE_HW_CACHE,
                 (res_id << 16) | (op_id << 8) | cache_id);
    } else
        argp_error(state, "Invalid cache specified.\n");
}

static int
is_raw_event(const char *arg)
{
    return !strncmp(prefix_raw_event, arg, sizeof(prefix_raw_event) - 1);
}

static void
init_raw_ctr(const char *arg, struct argp_state *state)
{
    assert(is_raw_event(arg));
    const char *ctr = arg + sizeof(prefix_raw_event) - 1;
    long event = perf_argp_parse_long("EVENT", ctr, state);
    init_ctr(PERF_TYPE_RAW, event);
}

static void
events_usage()
{
    printf("Software events:\n");
    for (const event_name_id_t *cur = sw_events; cur->name; cur++)
        printf("  sw:%s\n", cur->name);
    printf("\n");
    printf("Hardware events:\n");
    for (const event_name_id_t *cur = hw_events; cur->name; cur++)
        printf("  hw:%s\n", cur->name);
    printf("\n");
    printf("Hardware cache events:\n");
    printf("  Specified on the form 'hwc:cache:operation:result'.\n");
    printf("  Available cache levels:\n");
    for (const event_name_id_t *cur = hwc_events; cur->name; cur++)
        printf("    %s\n", cur->name);
    printf("  Available operations:\n");
    printf("    r - Read\n");
    printf("    w - Write\n");
    printf("    p - Prefetch\n");
    printf("  Available results:\n");
    printf("    a - Access\n");
    printf("    m - Miss\n");
    printf("\n");
    printf("Raw events:\n");
    printf("  Raw events are specified on the form 'raw:NUM' where NUM "
           "is the event number.\n");

    exit(EXIT_SUCCESS);
}

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct perf_event_attr *current_attr =
        perf_ctrs.tail ? &perf_ctrs.tail->attr : &perf_base_attr;

    switch (key)
    {
    case 'e':
        if (!strcmp("help", arg))
            events_usage();
        else if (is_sw_event(arg))
            init_sw_ctr(arg, state);
        else if (is_hw_event(arg))
            init_hw_ctr(arg, state);
        else if (is_hwc_event(arg))
            init_hwc_ctr(arg, state);
        else if (is_raw_event(arg))
            init_raw_ctr(arg, state);
        else
            argp_error(state,
                       "Invalid event specified, use 'help' to list "
                       "available events.\n");
        break;

    case KEY_PINNED:
        perf_base_attr.pinned = 1;
        break;

    case KEY_EXCLUSIVE:
        perf_base_attr.exclusive = 1;
        break;

    case KEY_SAMPLE_PERIOD:
        current_attr->sample_period =
            perf_argp_parse_long("sample period", arg, state);
        current_attr->freq = 0;
        break;

    case KEY_SAMPLE_FREQ:
        current_attr->sample_freq =
            perf_argp_parse_long("sample freq", arg, state);
        current_attr->freq = 1;
        break;

#ifdef HAVE_PRECISE_IP
    case KEY_PRECISE_IP:
        current_attr->precise_ip =
            perf_argp_parse_long("precise ip", arg, state);
        break;
#endif

    case ARGP_KEY_END:
        if (!perf_ctrs.head) {
            fprintf(stderr, "No performance counters specified.\n");
            argp_usage(state);
        }

        break;
     
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp perf_argp = {
    .options = options,
    .parser = parse_opt,
};

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
