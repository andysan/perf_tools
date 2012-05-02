/*
 * Copyright (C) 2012, Andreas Sandberg
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
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <pthread.h>

#include <argp.h>

#include "perf_compat.h"
#include "perf_common.h"
#include "perf_file.h"
#include "perf_argp.h"
#include "expect.h"
#include "util.h"

typedef struct {
    void *data;
    int size;
    int stride;
    int cpu;
} pirate_conf_t;

typedef enum {
    TARGET_WAIT_EXEC,
    TARGET_RUNNING,
} target_state_t;

#define DEFAULT_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)

#define NO_PID -1

#define RING_BUF_NUM_PAGES 17
static long page_size;

static struct perf_event_mmap_page *perf_header = NULL;
static unsigned char *perf_buf = NULL;

/* Configuration options */
static char **exec_argv = NULL;
static int target_output_fd = -1;
static char *target_output_name = "perfpirate.out";
static int pirate_output_fd = -1;
static char *pirate_output_name = "perfpirate.pout";

static int target_cpu = 1;
static pid_t target_pid = NO_PID;
static target_state_t target_state = TARGET_WAIT_EXEC;
static int target_ctrs_len = 0;

static ctr_list_t pirate_ctrs;
static int pirate_ctrs_len = 0;

#define NO_PIRATES (1)
static pthread_t pirate_thread;
static pirate_conf_t pirate_conf = {
    .data = NULL,
    .size = 512*1024,
    .stride = 64,
    .cpu = 0,
};
static pthread_barrier_t pirate_barrier;

static inline void
barrier()
{
    __sync_synchronize();
}

static uint64_t
read_head()
{
    long head;

    head = perf_header->data_head;
    barrier();

    return head;
}

static void
write_tail(uint64_t tail)
{
    barrier();
    perf_header->data_tail = tail;
}

static void
dump_events(int fd_out, int fd_in, int no_counters)
{
    /* Reset ring buffer */
    uint64_t new_head = read_head();
    write_tail(new_head);

    int data_size, ret;
    struct read_format {
        uint64_t nr;
        uint64_t time_enabled;
        uint64_t time_running;
        struct ctr_data {
            uint64_t val;
        } ctr[];
    } *data;

    struct perf_event_header header = {
        .type = PERF_RECORD_SAMPLE,
        .misc = 0,
    };

    data_size = sizeof(struct read_format) + sizeof(struct ctr_data) * no_counters;
    header.size = sizeof(struct perf_event_header) + data_size;

    data = alloca(data_size);
    memset(data, '\0', data_size);

    EXPECT_ERRNO((ret = read(fd_in, data, data_size)) != -1);
    if (ret == 0) {
        perror("Got EOF while reading counter\n");
        exit(EXIT_FAILURE);
    } else if (ret != data_size)
        fprintf(stderr,
                "Warning: Got short read. Expected %i bytes, "
                "but got %i bytes.\n",
                data_size, ret);

    write_all(fd_out, &header, sizeof(header));
    write_all(fd_out, data, data_size);
}

static void
dump_all_events()
{
    dump_events(target_output_fd,
                perf_ctrs.head->fd, target_ctrs_len);
    dump_events(pirate_output_fd,
                pirate_ctrs.head->fd, pirate_ctrs_len);
}

static void
my_ptrace_cont(int pid, int signal)
{
    if (ptrace(PTRACE_CONT, pid, NULL, (void *)((long)signal)) == -1) {
        perror("Failed to continue child process");
        abort();
    }
}

static void
handle_child_signal(const int pid, int signal)
{
    assert(target_pid == pid);

    switch (target_state) {
    case TARGET_WAIT_EXEC:
        switch (signal) {
        case SIGTRAP:
            target_state = TARGET_RUNNING;
            my_ptrace_cont(pid, 0);
            break;

        default:
            fprintf(stderr,
                    "Unexpected signal (%i) in target while in "
                    "the TARGET_WAIT_EXEC state.\n", signal);
            my_ptrace_cont(pid, signal);
            break;
        };
        break;

    case TARGET_RUNNING:
        switch (signal) {
        case SIGIO:
            dump_all_events();
            my_ptrace_cont(pid, 0);
            break;

        case SIGTRAP:
            fprintf(stderr, "Unexpected SIGTRAP in target.\n");
            /* FALL THROUGH */

        default:
            my_ptrace_cont(pid, signal);
            break;
        };
        break;
    }
}

static void
handle_child_event(const int pid, const int status)
{
    assert(target_pid != NO_PID);
    assert(target_pid == pid);

    if (WIFEXITED(status)) {
        fprintf(stderr, "Child exited with status '%i'.\n",
                WEXITSTATUS(status));
        dump_all_events();
        exit(WEXITSTATUS(status) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Child terminated by signal '%i'.\n",
                WTERMSIG(status));
        dump_all_events();
        if (WCOREDUMP(status))
            fprintf(stderr, "Core dumped.\n");
        exit(EXIT_FAILURE);
    } else if (WIFSTOPPED(status)) {
        handle_child_signal(pid, WSTOPSIG(status));
    } else
        EXPECT(0);
}

static void
handle_signal(int sfd)
{
    struct signalfd_siginfo fdsi;
    EXPECT(read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi));

    switch (fdsi.ssi_signo) {
    case SIGINT:
        dump_all_events();
        /* Try to terminate the child, if this succeeds, we'll
         * get a SIGCHLD and terminate ourselves. */
        fprintf(stderr, "Killing target process...\n");
        kill(target_pid, SIGKILL);
        break;

    case SIGCHLD: {
        int status;

        EXPECT_ERRNO(waitpid(fdsi.ssi_pid, &status, WNOHANG) > 0);
        handle_child_event(fdsi.ssi_pid, status);
    } break;


    default:
        fprintf(stderr, "Unhandled signal: %i\n", fdsi.ssi_signo);
        break;
    }
}

static int
create_sig_fd()
{
    sigset_t mask;
    int sfd;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    EXPECT_ERRNO(sigprocmask(SIG_BLOCK, &mask, NULL) != -1);
    EXPECT_ERRNO((sfd = signalfd(-1, &mask, 0)) != -1);

    return sfd;
}

static void
pin_process(pid_t pid, int cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(cpu, &cpu_set);
    EXPECT_ERRNO(sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_set) != -1);
}

static void
setup_target(void *data)
{
    if (target_cpu != -1)
        pin_process(0, target_cpu);

    EXPECT_ERRNO(ptrace(PTRACE_TRACEME, 0, NULL, NULL) != -1);
}

static void *
pirate_main(void *_conf)
{
    pirate_conf_t *conf = (pirate_conf_t *)_conf;

    volatile char *data = (volatile char *)conf->data;
    const int size = conf->size;
    const int stride = conf->stride;

    pthread_t thread;
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(conf->cpu, &cpu_set);
    thread = pthread_self();
    EXPECT(pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpu_set) == 0);

    /* TODO: Check if this is a PID or TID */
    EXPECT(ctrs_attach(&pirate_ctrs,
                       0 /* pid */,
                       conf->cpu,
                       0 /* flags */) != -1);

    pthread_barrier_wait(&pirate_barrier);

    while (1) {
        for (int i = 0; i < size; i += stride) {
            char discard;
            discard = data[i];
        }
    }
}

static void
do_start()
{
    int sfd;

    if (perf_ctrs.head) {
        perf_ctrs.head->attr.disabled = 1;
        perf_ctrs.head->attr.enable_on_exec = 1;
    }

    sfd = create_sig_fd();

    /* Start pirate */
    fprintf(stderr, "Starting pirate...\n");
    EXPECT(pthread_barrier_init(&pirate_barrier, NULL, NO_PIRATES + 1) == 0);
    EXPECT(pthread_create(&pirate_thread, NULL,
                          &pirate_main, &pirate_conf) == 0);
    pthread_barrier_wait(&pirate_barrier);


    /* Start target */
    fprintf(stderr, "Starting target...\n");
    target_pid = ctrs_execvp_cb(&perf_ctrs, -1 /* cpu */, 0 /* flags */,
                                &setup_target, NULL,
                                exec_argv[0], exec_argv);
    EXPECT(target_pid != -1);

    /* TODO: This is not optimal and causes a potential race with the child */
    perf_header = mmap(NULL,
                       page_size * RING_BUF_NUM_PAGES,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED,
                       perf_ctrs.head->fd, 0);

    EXPECT_ERRNO(perf_header != MAP_FAILED);
    perf_buf = (void *)((char *)perf_header + page_size);

    /* Route SIGIO from the perf FD to the child process */
    EXPECT_ERRNO(fcntl(perf_ctrs.head->fd, F_SETOWN, target_pid) != -1);
    EXPECT_ERRNO(fcntl(perf_ctrs.head->fd, F_SETFL, O_ASYNC) != -1);

    while (1) {
        struct pollfd pfd[] = {
            { sfd, POLLIN, 0 }
        };
        if (poll(pfd, sizeof(pfd) / sizeof(*pfd), -1) != -1) {
            if (pfd[0].revents & POLLIN)
                handle_signal(sfd);
        } else if (errno != EINTR)
            EXPECT_ERRNO(0);
    }
}


/*** argument handling ************************************************/
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'o':
        target_output_name = arg;
        break;

    case 'O':
        pirate_output_name = arg;
        break;

    case 'c':
        target_cpu = perf_argp_parse_long("CPU", arg, state);
        if (target_cpu < 0)
            argp_error(state, "CPU number must be positive\n");
        break;

    case 'C':
        pirate_conf.cpu = perf_argp_parse_long("CPU", arg, state);
        if (pirate_conf.cpu < 0)
            argp_error(state, "CPU number must be positive\n");
        break;

    case 's':
        pirate_conf.size = perf_argp_parse_long("SIZE", arg, state);
        if (pirate_conf.size < 0)
            argp_error(state, "Size must be positive\n");
        break;

    case 'S':
        pirate_conf.stride = perf_argp_parse_long("SIZE", arg, state);
        if (pirate_conf.stride < 0)
            argp_error(state, "Stride must be positive\n");
        break;

    case ARGP_KEY_ARG:
        if (!state->quoted)
            argp_error(state, "Illegal argument\n");
        break;
     
    case ARGP_KEY_END:
        if (state->quoted && state->quoted < state->argc)
            exec_argv = &state->argv[state->quoted];

        if (!exec_argv)
            argp_error(state,
                       "No target command specified.\n");

        target_output_fd = open(target_output_name,
                                O_WRONLY | O_CREAT | O_TRUNC,
                                DEFAULT_MODE);
        if (target_output_fd == -1)
            argp_failure(state, EXIT_FAILURE, errno,
                         "Failed to open target output file");

        pirate_output_fd = open(pirate_output_name,
                                O_WRONLY | O_CREAT | O_TRUNC,
                                DEFAULT_MODE);
        if (pirate_output_fd == -1)
            argp_failure(state, EXIT_FAILURE, errno,
                         "Failed to open pirate output file");


        pirate_conf.data = mem_huge_alloc(pirate_conf.size);
        if (!pirate_conf.data)
            argp_failure(state, EXIT_FAILURE, errno,
                         "Failed to allocate memory for pirate");

        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

const char *argp_program_version =
    "perfpirate\n"
    "\n"
    "  Copyright (C) 2012, Andreas Sandberg\n"
    "\n"
    "  This program is free software; you can redistribute it and/or modify\n"
    "  it under the terms set out in the COPYING file, which is included\n"
    "  in the perf_tools source distribution.\n";

const char *argp_program_bug_address =
    "andreas.sandberg@it.uu.se";

static struct argp_option arg_options[] = {
    { "output", 'o', "FILE", 0, "Target output file", 0 },
    { "pirate-output", 'O', "FILE", 0, "Pirate output file", 0 },
    { "target-cpu", 'c', "CPU", 0,
      "Pin target process to CPU.", 0 },
    { "pirate-cpu", 'C', "CPU", 0,
      "Pin pirate to CPU.", 0 },
    { "pirate-size", 's', "SIZE", 0,
      "Pirate data set size.", 0 },
    { "pirate-stride", 'S', "SIZE", 0,
      "Pirate pirate stride length.", 0 },

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
    .doc = "Simple cache pirating implementation for perf events"
    "\v"
    "perfpirate runs a target application and a stress microbenchmark, the "
    "pirate. Both applications are monitored simultaneously, when a user "
    "defined event overflow, the counters from both applications are "
    "dumped to disk.\n",
    .children = arg_children,
};

int
main(int argc, char **argv)
{
    perf_base_attr.sample_type =
        PERF_SAMPLE_READ;
    perf_base_attr.read_format = 
        PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING |
        PERF_FORMAT_GROUP;

    argp_parse (&argp, argc, argv,
                ARGP_IN_ORDER,
                0,
                NULL);

    ctrs_cpy_conf(&pirate_ctrs, &perf_ctrs);


    /* Force events configured for sampling to generate a fd activity
     * on every counter overflow */
    for (ctr_t *cur = perf_ctrs.head; cur; cur = cur->next) {
        if (cur->attr.sample_period > 0 || cur->attr.sample_freq > 0)
            cur->attr.wakeup_events = 1;
    }

    /* Disable sampling of the pirate */
    for (ctr_t *cur = pirate_ctrs.head; cur; cur = cur->next) {
        cur->attr.sample_period = 0;
        cur->attr.freq = 0;
    }

    page_size = sysconf(_SC_PAGE_SIZE);
    EXPECT_ERRNO(page_size != -1);

    target_ctrs_len = ctrs_len(&perf_ctrs);
    pirate_ctrs_len = ctrs_len(&pirate_ctrs);

    EXPECT(ctrs_write_header(&perf_ctrs, target_output_fd) == 1);
    EXPECT(ctrs_write_header(&pirate_ctrs, pirate_output_fd) == 1);

    do_start();

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
