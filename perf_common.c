/*
 * Copyright (C) 2010-2012, Andreas Sandberg
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>

#include "util.h"
#include "perf_common.h"
#include "expect.h"

typedef enum {
    SYNC_WAITING = 0,
    SYNC_GO,
    SYNC_ABORT,
} sync_type_t;

typedef struct {
    sync_type_t type;
} sync_msg_t;


ctr_t *
ctr_create(const struct perf_event_attr *base_attr)
{
    ctr_t *ctr;
    ctr = malloc(sizeof(ctr_t));
    if (!ctr)
        return NULL;

    if (!base_attr)
        memset(ctr, 0, sizeof(ctr_t));
    else
        ctr->attr = *base_attr;

    ctr->fd = -1;
    ctr->next = NULL;

    return ctr;
}


int
ctr_attach(ctr_t *ctr, pid_t pid, int cpu, int group_fd, int flags)
{
    assert(ctr->fd == -1);

    ctr->attr.size = PERF_ATTR_SIZE_VER0;
    ctr->fd = compat_sys_perf_event_open(&ctr->attr, pid, cpu, group_fd, flags);

    if (ctr->fd == -1) {
        perror("Failed to attach performance counter");
        return -1;
    }

    return ctr->fd;
}

int
ctrs_attach(ctr_list_t *list, pid_t pid, int cpu, int flags)
{
    for (ctr_t *cur = list->head; cur; cur = cur->next) {
        /* Use the first counter as the group_fd */
        ctr_attach(cur, pid, cpu,
                   cur != list->head ? list->head->fd : -1,
                   flags);

        if (cur->fd == -1) {
            ctrs_close(list);
            return -1;
        }
    }

    return 0;
}

void
ctrs_close(ctr_list_t *list)
{
    for (ctr_t *cur = list->head; cur; cur = cur->next) {
        if (cur->fd != -1) {
            close(cur->fd);
            cur->fd = -1;
        }
    }
}

ctr_t *
ctrs_add(ctr_list_t *list, ctr_t *ctr)
{
    ctr->next = NULL;

    if (list->tail) {
        assert(list->head);
        list->tail->next = ctr;
        list->tail = ctr;
    } else {
        list->head = ctr;
        list->tail = ctr;
    }

    return ctr;
}

int
ctrs_len(ctr_list_t *list)
{
    int count = 0;
    for (ctr_t *cur = list->head; cur; cur = cur->next)
        count++;
    return count;
}

static void
sync_send(int fd, const sync_msg_t *msg)
{
    EXPECT_ERRNO(send(fd, msg, sizeof(sync_msg_t), 0) == sizeof(sync_msg_t));
}

static void
sync_wait(int fd, sync_msg_t *msg)
{
    EXPECT_ERRNO(recv(fd, msg, sizeof(sync_msg_t), MSG_WAITALL) == sizeof(sync_msg_t));
}

static void
sync_send_simple(int fd, sync_type_t type)
{
    sync_msg_t msg = {
        .type = type,
    };

    sync_send(fd, &msg);
}

static void
sync_wait_simple(int fd, sync_type_t type)
{
    sync_msg_t msg;

    sync_wait(fd, &msg);
    if (msg.type == SYNC_ABORT) {
        fprintf(stderr, "Abort signalled while doing child synchronization.\n");
        exit(EXIT_FAILURE);
    }
    EXPECT(msg.type == type);
}

pid_t
ctrs_execvp_cb(ctr_list_t *list, int cpu, int flags,
               void (*child_callback)(void *data), void *callback_data,
               const char *file, char *const argv[])
{
    pid_t pid;
    int fds[2];

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds)) {
        perror("Failed to setup socket pair");
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        perror("fork failed");
        return -1;
    }

    if (pid == 0) {
        close(fds[0]);

        if (child_callback)
            child_callback(callback_data);

        sync_send_simple(fds[1], SYNC_WAITING);
        sync_wait_simple(fds[1], SYNC_GO);

        close(fds[1]);

        execvp(file, argv);
        fprintf(stderr, "%s: %s", file, strerror(errno));
        exit(EXIT_FAILURE);
    } else {
        close(fds[1]);
        sync_wait_simple(fds[0], SYNC_WAITING);

        if (ctrs_attach(list, pid, cpu, flags) == -1) {
            sync_send_simple(fds[0], SYNC_ABORT);
            exit(EXIT_FAILURE);
        }

        sync_send_simple(fds[0], SYNC_GO);
        close(fds[0]);

        return pid;
    }
}

pid_t
ctrs_execvp(ctr_list_t *list,
            int cpu, int flags,
            const char *file, char *const argv[])
{
    return ctrs_execvp_cb(list, cpu, flags, NULL, NULL, file, argv);
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
