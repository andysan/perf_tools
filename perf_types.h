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

#ifndef PERF_TYPES_H
#define PERF_TYPES_H

/* Types for some of the perf ring buffer events. The types of some of
 * the events can't be determined statically and needs configuration
 * data from perf. Such events are not included in this file.
 */

#include <stdint.h>

typedef struct {
    uint32_t pid, tid;
    uint64_t addr;
    uint64_t len;
    uint64_t pgoff;
    char filename[];
} perf_record_mmap_t;

typedef struct {
    uint64_t id;
    uint64_t lost;
} perf_record_lost_t;

typedef struct {
    uint32_t pid, tid;
    char comm[];
} perf_record_comm_t;

typedef struct {
    uint32_t pid, ppid;
    uint32_t tid, ptid;
    uint64_t time;
} perf_record_exit_t;

typedef struct {
    uint64_t time;
    uint64_t id;
    uint64_t stream_id;
} perf_record_throttle_t;

typedef perf_record_throttle_t perf_record_unthrottle_t;

typedef struct {
    uint32_t pid, ppid;
    uint32_t tid, ptid;
    uint64_t time;
} perf_record_fork_t;

typedef struct {
    uint32_t pid, tid;
    uint64_t data[];
} perf_record_read_t;

#endif

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
