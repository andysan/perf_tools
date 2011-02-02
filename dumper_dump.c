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

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "dumpers.h"
#include "perf_types.h"

static dumper_config_t conf;

static struct perf_event_attr *attr;

#define DUMP_IMPL(n)                                                    \
    static void dump_ ## n (void *data,                                 \
                            uint32_t type, uint16_t misc, uint16_t size)


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

DUMP_IMPL(PERF_RECORD_MMAP)
{
    assert(size >= sizeof(perf_record_mmap_t));
    perf_record_mmap_t *rec = (perf_record_mmap_t *)data;

    dump_printf("[MMAP] pid: %" PRIu32 " tid: %" PRIu32
                " addr: 0x%" PRIx64 " len: 0x%" PRIx64
                " pgoff: 0x%" PRIx64 " file: %s\n",
                rec->pid, rec->tid,
                rec->addr, rec->len,
                rec->pgoff, rec->filename);
}

DUMP_IMPL(PERF_RECORD_LOST)
{
    assert(size >= sizeof(perf_record_lost_t));
    perf_record_lost_t *rec = (perf_record_lost_t *)data;

    dump_printf("[LOST] id: %" PRIu64 " lost: %" PRIu64 "\n",
                rec->id, rec->lost);
}

DUMP_IMPL(PERF_RECORD_COMM)
{
    assert(size >= sizeof(perf_record_comm_t));
    perf_record_comm_t *rec = (perf_record_comm_t *)data;

    // TODO: DATA
    dump_printf("[COMM] pid: %" PRIu32 " tid: %" PRIu32 " DATA\n",
                rec->pid, rec->tid);
}

DUMP_IMPL(PERF_RECORD_EXIT)
{
    assert(size >= sizeof(perf_record_exit_t));
    perf_record_exit_t *rec = (perf_record_exit_t *)data;

    dump_printf("[EXIT] pid: %" PRIu32 " tid: %" PRIu32
                " ppid: %" PRIu32 " ptid: %" PRIu32
                " time: %" PRIu64 "\n",
                rec->pid, rec->tid, rec->ppid, rec->ptid, rec->time);
}

DUMP_IMPL(PERF_RECORD_THROTTLE)
{
    assert(size >= sizeof(perf_record_throttle_t));
    perf_record_throttle_t *rec = (perf_record_throttle_t *)data;

    dump_printf("[THROTTLE] time: %" PRIu64 " id: %" PRIu64
                " stream_id: %" PRIu64 "\n",
                rec->time, rec->id, rec->stream_id);
}

DUMP_IMPL(PERF_RECORD_UNTHROTTLE)
{
    assert(size >= sizeof(perf_record_unthrottle_t));
    perf_record_unthrottle_t *rec = (perf_record_unthrottle_t *)data;

    dump_printf("[UNTHROTTLE] time: %" PRIu64 " id: %" PRIu64
                " stream_id: %" PRIu64 "\n",
                rec->time, rec->id, rec->stream_id);
}

DUMP_IMPL(PERF_RECORD_FORK)
{
    assert(size >= sizeof(perf_record_fork_t));
    perf_record_fork_t *rec = (perf_record_fork_t *)data;

    dump_printf("[FORK] pid: %" PRIu32 " tid: %" PRIu32 "\n",
                rec->pid, rec->tid);
}

static void
dump_read_format(void **data, uint16_t *size, struct perf_event_attr *attr)
{
    const uint64_t read_format = attr->read_format;
    dump_printf("  ---\n");
    if (!(read_format & PERF_FORMAT_GROUP)) {
        dump_printf("  value: %" PRIu64 "\n", read_uint64_t(data, size));
        if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
            dump_printf("  time_enabled: %" PRIu64 "\n", read_uint64_t(data, size));
        if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
            dump_printf("  time_running: %" PRIu64 "\n", read_uint64_t(data, size));
        if (read_format & PERF_FORMAT_ID)
            dump_printf("  id: %" PRIu64 "\n", read_uint64_t(data, size));
        dump_printf("  ---\n");
    } else {
        uint64_t nr = read_uint64_t(data, size);

        if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
            dump_printf("  time_enabled: %" PRIu64 "\n", read_uint64_t(data, size));
        if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
            dump_printf("  time_running: %" PRIu64 "\n", read_uint64_t(data, size));

        dump_printf("  ---\n");

        for (int i = 0; i < nr; i++) {
            dump_printf("  value: %" PRIu64 "\n", read_uint64_t(data, size));
            if (read_format & PERF_FORMAT_ID)
                dump_printf("  id: %" PRIu64 "\n", read_uint64_t(data, size));
            dump_printf("  ---\n");
        }
    }
}

DUMP_IMPL(PERF_RECORD_READ)
{
    assert(size >= sizeof(perf_record_read_t));
    perf_record_read_t *rec = (perf_record_read_t *)data;
    void *read_data = (void *)rec->data;
    uint16_t data_size = size - sizeof(perf_record_read_t);

    dump_printf("[READ] pid: %" PRIu32 " tid: %" PRIu32,
                rec->pid, rec->tid);

    dump_read_format(&read_data, &data_size, attr);
}

DUMP_IMPL(PERF_RECORD_SAMPLE)
{
    const uint64_t sample_type = attr->sample_type;
    dump_printf("[SAMPLE]\n");

    if (sample_type & PERF_SAMPLE_IP)
        dump_printf("  IP: 0x%" PRIx64 "\n", read_uint64_t(&data, &size));
    if (sample_type & PERF_SAMPLE_TID) {
        uint32_t pid = read_uint32_t(&data, &size);
        uint32_t tid = read_uint32_t(&data, &size);
        dump_printf("  PID: %" PRIu32 " TID: %" PRIu32 "\n", pid, tid);
    }
    if (sample_type & PERF_SAMPLE_TIME)
        dump_printf("  TIME: %" PRIu64 "\n", read_uint64_t(&data, &size));
    if (sample_type & PERF_SAMPLE_ADDR)
        dump_printf("  ADDR: 0x%" PRIx64 "\n", read_uint64_t(&data, &size));
    if (sample_type & PERF_SAMPLE_ID)
        dump_printf("  ID: %" PRIu64 "\n", read_uint64_t(&data, &size));
    if (sample_type & PERF_SAMPLE_STREAM_ID)
        dump_printf("  STREAM_ID: %" PRIu64 "\n", read_uint64_t(&data, &size));
    if (sample_type & PERF_SAMPLE_CPU) {
        uint32_t cpu = read_uint32_t(&data, &size);
        uint32_t res = read_uint32_t(&data, &size);
        dump_printf("  CPU: %" PRIu32 " RES: %" PRIu32 "\n", cpu, res);
    }
    if (sample_type & PERF_SAMPLE_PERIOD)
        dump_printf("  PERIOD: %" PRIu64 "\n", read_uint64_t(&data, &size));

    if (sample_type & PERF_SAMPLE_READ)
        dump_read_format(&data, &size, attr);

    if (sample_type & PERF_SAMPLE_CALLCHAIN) {
        uint64_t nr = read_uint64_t(&data, &size);
        dump_printf("  Call Chain:");
        for (int i = 0; i < nr; i++)
            dump_printf(" 0x%" PRIx64, read_uint64_t(&data, &size));
        dump_printf("\n");
    }

    if (sample_type & PERF_SAMPLE_RAW)
        dump_printf("  Raw Sample - Unhandled\n");
}

static void
dump_unknown(void *data, uint32_t type, uint16_t misc, uint16_t size)
{
    dump_printf("[UNKNOWN:0x%" PRIx32 "] "
                "Misc: %" PRIu16 " Size: %" PRIu16 "\n",
                type, misc, size);
}

static void
init(const ctr_list_t *ctrs, const dumper_config_t *_conf)
{
    conf = *_conf;
    attr = &ctrs->head->attr;

    if (conf.delta)
        dump_printf("Warning: Delta mode not supported by this data dumper.\n");
}

#define DUMP_RECORD(n) { .type = n, .f = & dump_ ## n }

dumper_t dumper_dump = {
    .init = &init,

    .event_unknown = { .type = -1, .f = &dump_unknown },
    .events = {
        DUMP_RECORD(PERF_RECORD_MMAP),
        DUMP_RECORD(PERF_RECORD_LOST),
        DUMP_RECORD(PERF_RECORD_COMM),
        DUMP_RECORD(PERF_RECORD_EXIT),
        DUMP_RECORD(PERF_RECORD_THROTTLE),
        DUMP_RECORD(PERF_RECORD_UNTHROTTLE),
        DUMP_RECORD(PERF_RECORD_FORK),
        DUMP_RECORD(PERF_RECORD_READ),
        DUMP_RECORD(PERF_RECORD_SAMPLE),

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
