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

#define _GNU_SOURCE

#include <sys/wait.h>
#include <sys/signalfd.h>
#include <poll.h>
#include <sched.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include <argp.h>

#include "perf_compat.h"
#include "perf_common.h"
#include "perf_argp.h"
#include "expect.h"
#include "util.h"

/* Constant for the no-such-pid number, we can't use -1 since that has
 * a special meaning in perf. */
#define NO_PID INT_MIN

/* Configuration options */
int attach_pid = NO_PID;
char **exec_argv = NULL;
int monitor_cpu = -1;
int force_cpu = -1;
int scale = 0;
FILE *fout = NULL;

static void
print_event(const struct perf_event_attr *attr, uint64_t value)
{
    switch (attr->type) {
    case PERF_TYPE_HARDWARE:
        fprintf(fout, "hw %" PRIu64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    case PERF_TYPE_SOFTWARE:
        fprintf(fout, "sw %" PRIu64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    case PERF_TYPE_HW_CACHE:
        fprintf(fout, "hwc 0x%" PRIx64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    case PERF_TYPE_RAW:
        fprintf(fout, "raw 0x%" PRIx64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    default:
        fprintf(fout, "unknown event (%" PRIu32 ":%" PRIu64 "): %" PRIu64 "\n",
                (uint32_t)attr->type, (uint64_t)attr->config, value);
        break;
    }
}

static void
print_counters()
{
    int no_counters, data_size, ret;
    struct read_format {
        uint64_t nr;
        uint64_t time_enabled;
        uint64_t time_running;
        struct ctr_data {
            uint64_t val;
        } ctr[];
    } *data;

    no_counters = ctrs_len(&perf_ctrs);
    data_size = sizeof(struct read_format) + sizeof(struct ctr_data) * no_counters;
    EXPECT(data = malloc(data_size));
    memset(data, '\0', data_size);

    EXPECT((ret = read(perf_ctrs.head->fd, data, data_size)) != -1);
    if (ret == 0) {
        fprintf(stderr, "Got EOF while reading counter\n");
        exit(EXIT_FAILURE);
    } else if (ret != data_size)
        fprintf(stderr,
                "Warning: Got short read. Expected %i bytes, "
                "but got %i bytes.\n",
                data_size, ret);

    int i = 0;
    const double scaling_factor = scale ? data->time_enabled / data->time_running : 1.0;
    for (ctr_t *cur = perf_ctrs.head; cur; cur = cur->next) {
        assert(i < data->nr);
        struct ctr_data *ctr = &data->ctr[i++];

        print_event(&cur->attr, (uint64_t)(ctr->val * scaling_factor));
    }

    free(data);
}


static int
create_signal_fd()
{
    sigset_t mask;
    int sfd;

    /* Setup a signal fd for SIGINT, SIGCHLD and SIGUSR1 */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGUSR1);
    EXPECT(sigprocmask(SIG_BLOCK, &mask, NULL) != -1);
    sfd = signalfd(-1, &mask, 0);
    EXPECT(sfd != -1);

    return sfd;
}


static void
do_attach()
{
    int sfd;
    int done = 0;

    sfd = create_signal_fd();

    printf("Attaching to PID %i...\n", attach_pid);
    if (ctrs_attach(&perf_ctrs, attach_pid, monitor_cpu, 0 /* flags */) == -1)
        exit(EXIT_FAILURE);

    while (!done) {
        struct pollfd pfd[] = {
            { sfd, POLLIN, 0 }
        };
        EXPECT_ERRNO(poll(pfd, sizeof(pfd) / sizeof(*pfd), -1) != -1);

        if (pfd[0].revents & POLLIN) {
            struct signalfd_siginfo fdsi;
            EXPECT(read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi));
            
            switch (fdsi.ssi_signo) {
            case SIGINT:
                done = 1;
                break;
            case SIGUSR1:
                print_counters();
                break;
            default:
                /* Ignore other signals */
                break;
            }
        }
    }

    print_counters();
}

static void
setup_child(void *data)
{
    if (force_cpu != -1) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(force_cpu, &cpu_set);
        EXPECT_ERRNO(sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) != -1);
    }
}

static void
do_start()
{
    pid_t pid;
    int sfd;
    int done = 0;
    

    sfd = create_signal_fd();

    if (perf_ctrs.head) {
        perf_ctrs.head->attr.disabled = 1;
        perf_ctrs.head->attr.enable_on_exec = 1;
    }

    pid = ctrs_execvp_cb(&perf_ctrs, monitor_cpu /* cpu */, 0 /* flags */,
                         &setup_child, NULL,
                         exec_argv[0], exec_argv);
    EXPECT(pid != -1);

    while (!done) {
        struct pollfd pfd[] = {
            { sfd, POLLIN, 0 }
        };
        EXPECT_ERRNO(poll(pfd, sizeof(pfd) / sizeof(*pfd), -1) != -1);

        if (pfd[0].revents & POLLIN) {
            struct signalfd_siginfo fdsi;
            EXPECT(read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi));
            
            switch (fdsi.ssi_signo) {
            case SIGINT:
                /* Try to terminate the child, if this succeeds, we'll
                 * get a SIGCHLD and terminate ourselves. */
                fprintf(stderr, "Sending SIGTERM to child.\n");
                kill(pid, SIGTERM);
                break;
            case SIGUSR1:
                print_counters();
                break;
            case SIGCHLD: {
                int status;
                print_counters();

                EXPECT(waitpid(pid, &status, 0) != -1);

                if (!WIFEXITED(status)) {
                    fprintf(stderr, "Child processes did not exit normally\n");
                    exit(EXIT_FAILURE);
                }

                done = 1;
            } break;
            default:
                /* Ignore other signals */
                break;
            }
        }
    }
}


/*** argument handling ************************************************/
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    static char *output_name = NULL;

    switch (key)
    {
    case 'p':
        attach_pid = perf_argp_parse_long("PID", arg, state);
        break;

    case 'c':
        force_cpu = perf_argp_parse_long("CPU", arg, state);
        if (force_cpu < 0)
            argp_error(state, "CPU number must be positive\n");
        break;

    case 's':
        scale = 0;
        break;

    case 'o':
        output_name = arg;
        break;

    case ARGP_KEY_ARG:
        if (!state->quoted)
            argp_error(state, "Invalid argument.");
        break;
     
    case ARGP_KEY_END:
        if (state->quoted && state->quoted < state->argc)
            exec_argv = &state->argv[state->quoted];

        if (exec_argv && attach_pid != NO_PID)
            argp_error(state,
                       "Both a command to execute and a PID to attach have\n"
                       "been specified. Make up your mind!");
        else if (!exec_argv && attach_pid == NO_PID)
            argp_error(state,
                       "Neither a command to execute, nor a PID to attach have\n"
                       "been specified. Don't know what to do.");

        if (output_name) {
            fout = fopen(output_name, "w");
            if (!fout)
                argp_failure(state, EXIT_FAILURE, errno,
                             "Failed to open output file");
        } else
            fout = exec_argv ? stderr : stdout;

        break;
     
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

const char *argp_program_version =
    "rawperf\n"
    "\n"
    "  Copyright (C) 2010-2011, Andreas Sandberg\n"
    "\n"
    "  This program is free software; you can redistribute it and/or modify\n"
    "  it under the terms set out in the COPYING file, which is included\n"
    "  in the perf_tools source distribution.\n";

const char *argp_program_bug_address =
    "andreas.sandberg@it.uu.se";

static struct argp_option arg_options[] = {
    { "pid", 'p', "PID", 0, "Trace process PID", 0 },
    { "scale", 's', NULL, 0, "Enable counter scaling", 0 },
    { "force-cpu", 'c', "CPU", 0,
      "Pin child process to CPU. This option does not work with attach.", 0 },

    { "output", 'o', "FILE", 0,
      "Output file. Defaults to stdout if attaching to target, stderr "
      "otherwise.", 0 },

    { 0 }
};

static struct argp_child arg_children[] = {
    { &perf_argp, 0, "Event options:", 0 },
    { 0 }
};

static struct argp argp = {
    .options = arg_options,
    .parser = parse_opt,
    .args_doc = "[-- command [arg ...]]",
    .doc = "Simple interface for monitoring performance counters"
    "\v"
    "rawperf prints the state of the performance counters when the target "
    "application exits or is detached. To dump the counters before the exit "
    "or detach, send SIGUSR1 to the rawperf process.\n"
    "\n"
    "SIGINT handling is mode dependent. If rawperf started the target "
    "application, it is terminated before rawperf terminates. If the "
    "target was not started, i.e. it was attached, rawperf will simply detach "
    "from the process and leave it running.",
    .children = arg_children,
};

int
main(int argc, char **argv)
{
    perf_base_attr.read_format = 
        PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING |
        PERF_FORMAT_GROUP;

    argp_parse (&argp, argc, argv,
                ARGP_IN_ORDER,
                0,
                NULL);

    if (exec_argv)
        do_start();
    else
        do_attach();

    if (fout != stderr && fout != stdout)
        fclose(fout);

    exit(EXIT_SUCCESS);
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
