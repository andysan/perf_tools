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

#ifndef PERF_COMPAT_H
#define PERF_COMPAT_H

#include <unistd.h>
#include <sys/syscall.h> 

#ifndef PERFH
#include <linux/perf_event.h>
#else
#include PERFH
#endif

#ifndef __NR_perf_event_open

#ifdef __powerpc__
#define __NR_perf_event_open  319
#elif defined(__x86_64__)
#define __NR_perf_event_open  298
#elif defined(__i386__)
#define __NR_perf_event_open  336
#endif

#endif

static inline int
compat_sys_perf_event_open(struct perf_event_attr *attr,
                           pid_t pid, int cpu, int group_fd,
                           unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu,
                   group_fd, flags);
}

#endif

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
