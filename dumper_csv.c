/*
 * Copyright (c) 2010, Andreas Sandberg
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "expect.h"

#include "dumpers.h"

static dumper_config_t conf;

static struct perf_event_attr *attr;
static uint64_t sample_no;
static uint64_t no_counters;
static uint64_t start_time = -1;

static uint64_t *old_values = NULL;

static void
dump_printf(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

static void
dump_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(conf.output, fmt, ap);
    va_end(ap);
}

static void
dump_sample(void *data, uint32_t type, uint16_t misc, uint16_t size)
{
    const uint64_t sample_type = attr->sample_type;

    if (sample_type & PERF_SAMPLE_IP)
        skip_uint64_t(&data, &size);
    if (sample_type & PERF_SAMPLE_TID) {
        skip_uint32_t(&data, &size);
        skip_uint32_t(&data, &size);
    }
    if (sample_type & PERF_SAMPLE_TIME) {
        uint64_t time = read_uint64_t(&data, &size);
        if (start_time == -1)
            start_time = time;
        dump_printf("%" PRIu64, time - start_time);
    } else
        dump_printf("%" PRIu64, sample_no);

    if (sample_type & PERF_SAMPLE_ADDR)
        skip_uint64_t(&data, &size);
    if (sample_type & PERF_SAMPLE_ID)
        skip_uint64_t(&data, &size);
    if (sample_type & PERF_SAMPLE_STREAM_ID)
        skip_uint64_t(&data, &size);
    if (sample_type & PERF_SAMPLE_CPU) {
        skip_uint32_t(&data, &size);
        skip_uint32_t(&data, &size);
    }
    if (sample_type & PERF_SAMPLE_PERIOD)
        skip_uint64_t(&data, &size);

    if (sample_type & PERF_SAMPLE_READ) {
        const uint64_t read_format = attr->read_format;
        if (!(read_format & PERF_FORMAT_GROUP)) {
            uint64_t value = read_uint64_t(&data, &size);
            dump_printf(",%" PRIu64 "\n", value);
        } else {
            uint64_t nr = read_uint64_t(&data, &size);
            assert(no_counters == nr);

            if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
                skip_uint64_t(&data, &size);
            if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
                skip_uint64_t(&data, &size);

            for (int i = 0; i < nr; i++) {
                uint64_t value = read_uint64_t(&data, &size);
                if (read_format & PERF_FORMAT_ID)
                    skip_uint64_t(&data, &size);

                if (conf.delta) {
                    dump_printf(",%" PRIu64, value - old_values[i]);
                    old_values[i] = value;
                } else
                    dump_printf(",%" PRIu64, value);
            }
            dump_printf("\n");
        }
    }

    sample_no++;
}

static void
dump_unknown(void *data, uint32_t type, uint16_t misc, uint16_t size)
{
}

static void
init(const ctr_list_t *ctrs, const dumper_config_t *_conf)
{
    attr = &ctrs->head->attr;
    const uint64_t sample_type = attr->sample_type;

    conf = *_conf;

    sample_no = 0;

    dump_printf("#");
    if (sample_type & PERF_SAMPLE_TIME)
        dump_printf("time");
    else
        dump_printf("number");

    no_counters = 0;
    for (ctr_t *ctr = ctrs->head; ctr; ctr = ctr->next) {
        no_counters++;
        switch (ctr->attr.type) {
        case PERF_TYPE_HARDWARE:
            dump_printf(",hw:%" PRIu64, (uint64_t)ctr->attr.config);
            break;
        case PERF_TYPE_SOFTWARE:
            dump_printf(",sw:%" PRIu64, (uint64_t)ctr->attr.config);
            break;
        case PERF_TYPE_HW_CACHE:
            dump_printf(",hwc:0x%" PRIx64, (uint64_t)ctr->attr.config);
            break;
        case PERF_TYPE_RAW:
            dump_printf(",0x%" PRIx64, (uint64_t)ctr->attr.config);
            break;
        default:
            dump_printf(",%" PRIu32 ":%" PRIu64,
                        (uint32_t)ctr->attr.type, (uint64_t)ctr->attr.config);
            break;
        }
    }

    if (conf.delta) {
        EXPECT(old_values = malloc(sizeof(*old_values) * no_counters));
        memset(old_values, 0, sizeof(*old_values) * no_counters);
    }

    dump_printf("\n");
}

dumper_t dumper_csv = {
    .init = &init,

    .event_unknown = { .type = -1, .f = &dump_unknown },
    .events = {
        { .type = PERF_RECORD_SAMPLE, .f = &dump_sample },

        { .type = -1, .f = NULL }
    }
};

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
