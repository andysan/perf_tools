/*
 * Copyright (c) 2011, Andreas Sandberg
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

#define MAX_CPUS 64
#define CPU_DELIM ','

enum {
    OPT_NO_SPLIT_LOGS = 1,
};

typedef enum {
    /* Initial state, child processes are about to start */
    RUN_STATE_STARTING,
    /* All child processes running */
    RUN_STATE_RUNNING,
    /* At least one child process has terminated. Waiting for the rest
     * to terminate */
    RUN_STATE_WAITING,
    /* All child processes have terminated */
    RUN_STATE_EXIT,
} run_state_t;

typedef struct {
    int cpu;
    pid_t pid;
    int zombie;

    FILE *stdout; 
    FILE *stderr;
    FILE *stdin;

    char **argv;
    int argc;

    ctr_list_t ctrs;
} bench_process_t;

static run_state_t run_state = RUN_STATE_STARTING;

/* Configuration options */
static int scale = 0;
static const char *log_base = NULL;
static int quiet = 0;
static int split_logs = 1;

static bench_process_t processes[MAX_CPUS];
static int num_processes = 0;

static int cpu_map[MAX_CPUS];
static int num_mappings = 0;


static bench_process_t *
process_find(pid_t pid)
{
    for (int i = 0; i < num_processes; i++) {
	bench_process_t *p = processes + i;
	if (p->pid == pid)
	    return p;
    }

    return NULL;
}

static void
process_kill(bench_process_t *p, int sig)
{
    /* We kill the process group instead of the process, this
     * eliminates some nastiness when the child has fork'ed. */
    if (kill(-p->pid, sig) == -1) {
	perror("Kill failed");
	abort();
    }
}

static int
process_running(bench_process_t *p)
{
    return p->pid > 0 && !p->zombie;
}

static void
processes_kill(int sig)
{
    for (int i = 0; i < num_processes; i++) {
	bench_process_t *p = processes + i;
	if (process_running(p))
	    process_kill(p, sig);
    }
}

static int
processes_running()
{
    int count = 0;

    for (int i = 0; i < num_processes; i++) {
	bench_process_t *p = processes + i;
	if (process_running(p))
	    ++count;
    }

    return count;
}

static void
print_event(FILE *out, const struct perf_event_attr *attr, uint64_t value)
{
    switch (attr->type) {
    case PERF_TYPE_HARDWARE:
        fprintf(out, "hw %" PRIu64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    case PERF_TYPE_SOFTWARE:
        fprintf(out, "sw %" PRIu64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    case PERF_TYPE_HW_CACHE:
        fprintf(out, "hwc 0x%" PRIx64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    case PERF_TYPE_RAW:
        fprintf(out, "raw 0x%" PRIx64 ": %" PRIu64 "\n",
                (uint64_t)attr->config, value);
        break;

    default:
        fprintf(out, "unknown event (%" PRIu32 ":%" PRIu64 "): %" PRIu64 "\n",
                (uint32_t)attr->type, (uint64_t)attr->config, value);
        break;
    }
}

static void
print_counter_list(FILE *out, ctr_list_t *list)
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

    no_counters = ctrs_len(list);
    data_size = sizeof(struct read_format) + sizeof(struct ctr_data) * no_counters;
    EXPECT(data = malloc(data_size));
    memset(data, '\0', data_size);

    EXPECT((ret = read(list->head->fd, data, data_size)) != -1);
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
    for (ctr_t *cur = list->head; cur; cur = cur->next) {
        assert(i < data->nr);
        struct ctr_data *ctr = &data->ctr[i++];

        print_event(out, &cur->attr, (uint64_t)(ctr->val * scaling_factor));
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
print_counters(FILE *out)
{
    for (int i = 0; i < num_processes; i++) {
        bench_process_t *p = processes + i;
        fprintf(out, "%i -- %s:\n", i, p->argv[0]);
        print_counter_list(out, &p->ctrs);
        fprintf(out, "\n");
    }
}

static void
setup_child(void *_p)
{
    bench_process_t *p = (bench_process_t *)_p;
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(p->cpu, &cpu_set);
    EXPECT_ERRNO(sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) != -1);

    /* Setup a process group so we can kill all child processes
     * easily */
    EXPECT_ERRNO(setpgid(0, 0) != -1);

    if (p->stdout)
        fredirect(p->stdout, STDOUT_FILENO);
    if (p->stderr)
        fredirect(p->stderr, STDERR_FILENO);
    if (p->stdin)
        fredirect(p->stdin, STDIN_FILENO);
}

static void
handle_signal(struct signalfd_siginfo *fdsi)
{
    switch (fdsi->ssi_signo) {
    case SIGINT:
        /* Try to terminate the child processes, if this
         * succeeds, we'll get a SIGCHLD for each child
         * process and eventually terminate ourselves. */
        fprintf(stderr, "Sending SIGTERM to child processes.\n");
        processes_kill(SIGTERM);
        break;
    case SIGUSR1:
        print_counters(stderr);
        break;
    case SIGCHLD: {
        bench_process_t *p = process_find(fdsi->ssi_pid);
        assert(p);
        p->zombie = 1;

        if (run_state == RUN_STATE_RUNNING)
            /* Kill all running child processes */
            processes_kill(SIGTERM);

        run_state = processes_running() == 0 ? RUN_STATE_EXIT : RUN_STATE_WAITING;
    } break;
    default:
        /* Ignore other signals */
        break;
    }
}

static int
do_start()
{
    int sfd;
    int exit_status = EXIT_SUCCESS;

    sfd = create_signal_fd();

    for (int i = 0; i < num_processes; i++) {
        bench_process_t *p = processes + i;
        p->pid = ctrs_execvp_cb(&p->ctrs, -1 /* cpu */, 0 /* flags */,
                                &setup_child, p,
                                p->argv[0], p->argv);
        EXPECT(p->pid != -1);
    }

    run_state = RUN_STATE_RUNNING;
    while (run_state != RUN_STATE_EXIT) {
        struct pollfd pfd[] = {
            { sfd, POLLIN, 0 }
        };
        EXPECT_ERRNO(poll(pfd, sizeof(pfd) / sizeof(*pfd), -1) != -1);

        if (pfd[0].revents & POLLIN) {
            struct signalfd_siginfo fdsi;
            EXPECT(read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi));

            handle_signal(&fdsi);
        }
    }

    print_counters(stderr);

    for (int i = 0; i < num_processes; i++) {
        bench_process_t *p = processes + i;
        int status;

        EXPECT(waitpid(p->pid, &status, 0) != -1);
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status))
                fprintf(stderr, "Child %i: Exit status %i\n",
                        i, WEXITSTATUS(status));
            exit_status = EXIT_FAILURE;
        } else if (WIFSIGNALED(status)) {
            if (WTERMSIG(status) != SIGTERM)
                fprintf(stderr, "Child %i: Unexpected exit signal: %i\n",
                        i, WTERMSIG(status));
            exit_status = EXIT_FAILURE;
        } else {
            fprintf(stderr, "Child %i: Unhandled exit status\n", i);
            exit_status = EXIT_FAILURE;
        }
    }

    return exit_status;
}


/*** argument handling ************************************************/
static void
parse_cpu_map(const char *arg, struct argp_state *state)
{
    errno = 0;
	
    const char *s = arg;
    while (*s) {
        char *endptr;
        long cpu;

        if (num_mappings >= MAX_CPUS)
            argp_error(state, "Unsupported number of CPU mappings, only "
                       "%i CPUs supported", MAX_CPUS);

        cpu = strtol(s, &endptr, 0);
        if (s == endptr || errno != 0)
            argp_error(state, "Invalid CPU map specification");

        if (cpu > INT_MAX || cpu < INT_MIN)
            argp_error(state, "CPU number out of range");

        if (*endptr != '\0' && *endptr != CPU_DELIM)
            argp_error(state, "Invalid character in CPU map specification");

        if (*endptr == CPU_DELIM)
            endptr++;

        cpu_map[num_mappings++] = (int)cpu;
        s = endptr;
    }
}

static int
parse_exec_spec_get_cpu(int logical_cpu, struct argp_state *state)
{
    if (!num_mappings)
	return logical_cpu;

    if (logical_cpu >= num_mappings)
	argp_error(state, "Error: No mapping for logical CPU '%i'.\n",
                   logical_cpu);

    return cpu_map[logical_cpu];
}

static void
parse_exec_spec(int argc, char *argv[], struct argp_state *state)
{
    bench_process_t *p = processes;
    while (argc) {
        if (num_processes >= MAX_CPUS)
            argp_error(state, "Unsupported number of processes, only "
                       "%i processes supported", MAX_CPUS);

        memset(p, '\0', sizeof(bench_process_t));
        p->cpu = parse_exec_spec_get_cpu(p - processes, state);
        p->pid = 0;
        p->argc = 0;
        p->argv = argv;
        while (argc) {
            if (!strcmp("--", *argv)) {
                *argv = NULL;
                ++argv;
                --argc;
                break;
            } else {
                ++p->argc;
                ++argv;
                --argc;
            }
        }

        ++p;
        ++num_processes;
    }
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 's':
        scale = 0;
        break;

    case 'c':
        parse_cpu_map(arg, state);
        break;

    case 'l':
        log_base = arg;
        break;

    case 'q':
        quiet = 1;
        break;

    case OPT_NO_SPLIT_LOGS:
        split_logs = 0;
        break;

    case ARGP_KEY_ARG:
        if (!state->quoted)
            argp_error(state, "Invalid argument.");
        break;
     
    case ARGP_KEY_END:
        if (state->quoted && state->quoted < state->argc)
            parse_exec_spec(state->argc - state->quoted,
                            state->argv + state->quoted,
                            state);

        if (num_processes == 0)
            argp_error(state, "No target processes specified");

        break;
     
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

const char *argp_program_version =
    "perfgroup";

const char *argp_program_bug_address =
    "andreas.sandberg@it.uu.se";

static struct argp_option arg_options[] = {
    { "scale", 's', NULL, 0, "Enable counter scaling", 0 },
    { "cpu-list", 'c', "CPUs", 0,
      "Comma separated list of CPUs to run on", 0 },
    { "log-base", 'l', "PATH", 0,
      "Base file name for log files", 0 },
    { "no-split-logs", OPT_NO_SPLIT_LOGS, NULL, 0,
      "Don't use different log files for STDERR and STDOUT", 0},
    { "quiet", 'q', NULL, 0,
      "Silence target output. Does not silence STDERR if the split "
      "logs option is active.", 0},
    { 0 }
};

static struct argp_child arg_children[] = {
    { &perf_argp, 0, "Event options:", 0 },
    { 0 }
};

static struct argp argp = {
    .options = arg_options,
    .parser = parse_opt,
    .args_doc = "-- command [arg ...] [-- command [arg ...]]...",
    .doc = "Run a group of applications and monitor their behavior "
    "using perf event"
    "\v"
    "The normal behavior of this application is to start the group of "
    "applications and enable the configured counters. When the first "
    "application terminates, the counters are read for all of the applications "
    "and applications still running are terminated.",
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

    if (perf_ctrs.head) {
        perf_ctrs.head->attr.disabled = 1;
        perf_ctrs.head->attr.enable_on_exec = 1;
    }

    for (int i = 0; i < num_processes; i++) {
	bench_process_t *p = processes + i;

        /* Setup log redirection */
        if (log_base || quiet) {
            char name[1024];

            if (!quiet)
                snprintf(name, sizeof(name), "%s.%i.stdout", log_base, i);
            else 
                snprintf(name, sizeof(name), "/dev/null");
            p->stdout = fopen(name, "w");
            EXPECT_ERRNO(p->stdout);

            if (split_logs) {
                snprintf(name, sizeof(name), "%s.%i.stderr", log_base, i);
                p->stderr = fopen(name, "w");
                EXPECT_ERRNO(p->stderr);
            } else
                p->stderr = p->stdout;
        } else {
            p->stdout = NULL;
            p->stderr = NULL;
        }

        /* Create a private copy of the counter configuration for each
         * target */
        for (ctr_t *cur = perf_ctrs.head; cur; cur = cur->next) {
            ctr_t *c = ctr_create(&cur->attr);
            assert(c);
            ctrs_add(&p->ctrs, c);
        }
    }

    return do_start();
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * c-file-style: "k&r"
 * End:
 */
