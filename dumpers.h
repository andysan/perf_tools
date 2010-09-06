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

#ifndef DUMPERS_H
#define DUMPERS_H

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include "perf_common.h"

typedef struct {
    uint32_t type;
    void (*f)(void *data, uint32_t type, uint16_t misc, uint16_t size);
} event_dumper_t;

typedef struct {
    /**
     * Output file. Pointer must be valid throughout the lifetime of
     * the dumper
     */
    FILE *output;
    /**
     * Output the difference in the counter values rather than the
     * actual counter values.
     */
    int delta;
} dumper_config_t;

typedef struct {
    void (*init)(const ctr_list_t *ctrs,
		 const dumper_config_t *conf);
    event_dumper_t event_unknown;
    event_dumper_t events[];
} dumper_t;

extern dumper_t dumper_dump;
extern dumper_t dumper_csv;

#define READ_TYPE_IMPL(T)						\
    static inline T read_ ## T(void **data, uint16_t *size) {		\
	assert(*size >= sizeof(T));					\
	*size -= sizeof(T);						\
	return *(*(T **)data)++;					\
    }

#define SKIP_TYPE_IMPL(T)						\
    static inline void skip_ ## T(void **data, uint16_t *size) {	\
	assert(*size >= sizeof(T));					\
	*size -= sizeof(T);						\
	(*(T **)data)++;						\
    }

READ_TYPE_IMPL(uint64_t)
READ_TYPE_IMPL(uint32_t)

SKIP_TYPE_IMPL(uint64_t)
SKIP_TYPE_IMPL(uint32_t)

#endif
