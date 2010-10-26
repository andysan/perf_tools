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

#define _GNU_SOURCE

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/signalfd.h>

#include <sched.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include <argp.h>

#include "perf_compat.h"
#include "perf_common.h"
#include "perf_file.h"
#include "perf_argp.h"
#include "expect.h"
#include "util.h"

#undef DEBUG

#define NO_PID -1

#define RING_BUF_NUM_PAGES 17
static long page_size;

static struct perf_event_mmap_page *perf_header = NULL;
static unsigned char *perf_buf = NULL;
static uint64_t buf_mask = 0;
static uint64_t my_head = 0;

/* Configuration options */
pid_t attach_pid = NO_PID;
char **exec_argv = NULL;
FILE *output;
char *output_name;
int force_cpu = -1;

int monitor_cpu = -1;
pid_t exec_pid = NO_PID;

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
dump_events()
{
    uint64_t new_head = read_head();
    size_t size, start;

    assert(new_head >= my_head);
    /* This can happen when flushing buffers when a child exits,
     * i.e. this situation is completely normal */
    if (new_head == my_head)
	return;

    size = new_head - my_head;
    start = my_head & buf_mask;

#ifdef DEBUG
    fprintf(stderr,
	    "size: 0x%" PRIx64 " start: 0x%" PRIx64 " buf_mask: 0x%" PRIx64 "\n",
	    size, start, buf_mask);
#endif

    /* Does the data wrap, i.e. is start + size larger than the buffer size? */
    if ((start + size - 1) & (~buf_mask)) {
	size_t start_size = (start + size) & buf_mask;
#ifdef DEBUG
	fprintf(stderr, "Buffer wrap.\n");
#endif
	fwrite(perf_buf + start, size - start_size, 1, output);
	start = 0;
	size = start_size;
    }

    EXPECT(fwrite(perf_buf + start, size, 1, output) == 1);

    my_head = new_head;
    write_tail(new_head);
}

#ifdef DEBUG
static void
print_page_info()
{
    printf("MMAP buf:\n"
	   "  version: %" PRIu32 "\n"
	   "  compat_version: %" PRIu32 "\n"
	   "  lock: %" PRIu32 "\n"
	   "  index: %" PRIu32 "\n"
	   "  offset: %" PRIi64 "\n"
	   "  time_enabled: %" PRIu64 "\n"
	   "  time_running: %" PRIu64 "\n"
	   "  data_head: %" PRIu64 "\n"
	   "  data_tail: %" PRIu64 "\n",
	   perf_header->version,
	   perf_header->compat_version,
	   perf_header->lock,
	   perf_header->index,
	   perf_header->offset,
	   perf_header->time_enabled,
	   perf_header->time_running,
	   perf_header->data_head,
	   perf_header->data_tail);
}
#endif

static int
create_sig_fd()
{
    sigset_t mask;
    int sfd;

    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGUSR1);
    EXPECT(sigprocmask(SIG_BLOCK, &mask, NULL) != -1);
    sfd = signalfd(-1, &mask, 0);
    EXPECT(sfd != -1);

    return sfd;
}

static void
handle_signal(int sfd)
{
    struct signalfd_siginfo fdsi;
    EXPECT(read(sfd, &fdsi, sizeof(fdsi)) == sizeof(fdsi));

    switch (fdsi.ssi_signo) {
    case SIGINT:
	dump_events();
	if (exec_pid != NO_PID) {
	    /* Try to terminate the child, if this succeeds, we'll
	     * get a SIGCHLD and terminate ourselves. */
	    fprintf(stderr, "Sending SIGTERM to child.\n");
	    kill(exec_pid, SIGTERM);
	} else
	    exit(EXIT_SUCCESS);
	break;

    case SIGCHLD: {
	int status;

	assert(attach_pid == NO_PID);
	assert(exec_pid != NO_PID);
	assert(exec_pid == fdsi.ssi_pid);

	EXPECT_ERRNO(waitpid(fdsi.ssi_pid, &status, WNOHANG) > 0);
	dump_events();

	if (WIFEXITED(status)) {
	    fprintf(stderr, "Child exited with status '%i'.\n",
		    WEXITSTATUS(status));
	    exit(WEXITSTATUS(status) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	} else if (WIFSIGNALED(status)) {
	    fprintf(stderr, "Child terminated by signal '%i'.\n",
		    WTERMSIG(status));
	    if (WCOREDUMP(status))
		fprintf(stderr, "Core dumped.\n");
	    exit(EXIT_FAILURE);
	} else
	    EXPECT(0);
    } break;
    case SIGUSR1:
#ifdef DEBUG
	print_page_info();
#endif
	break;
    default:
	fprintf(stderr, "Unhandled signal: %i\n", fdsi.ssi_signo);
	break;
    }
}

static void
do_attach()
{
    int sfd;
    sfd = create_sig_fd();
    printf("Attaching to PID %i.\n", attach_pid);
    if (ctrs_attach(&perf_ctrs, attach_pid, monitor_cpu, 0 /* flags */) == -1)
	exit(EXIT_FAILURE);

    perf_header = mmap(NULL,
		       page_size * RING_BUF_NUM_PAGES,
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED,
		       perf_ctrs.head->fd, 0);
    EXPECT_ERRNO(perf_header != MAP_FAILED);
    perf_buf = (void *)((char *)perf_header + page_size);

    while (1) {
	struct pollfd pfd[] = {
	    { perf_ctrs.head->fd, POLLIN, 0 },
	    { sfd, POLLIN, 0 }
	};
#ifdef DEBUG
	print_page_info();
#endif
	EXPECT_ERRNO(poll(pfd, 2, -1) != -1);

	if (pfd[0].revents & POLLIN)
	    dump_events();
	
	if (pfd[1].revents & POLLIN)
	    handle_signal(sfd);
    }
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
setup_child(void *data)
{
    if (force_cpu != -1)
	pin_process(0, force_cpu);
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

    exec_pid = ctrs_execvp_cb(&perf_ctrs, monitor_cpu /* cpu */, 0 /* flags */,
			      &setup_child, NULL,
			      exec_argv[0], exec_argv);
    EXPECT(exec_pid != -1);

    perf_header = mmap(NULL,
		       page_size * RING_BUF_NUM_PAGES,
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED,
		       perf_ctrs.head->fd, 0);
    EXPECT_ERRNO(perf_header != MAP_FAILED);
    perf_buf = (void *)((char *)perf_header + page_size);

    while (1) {
#ifdef DEBUG
	print_page_info();
#endif
	struct pollfd pfd[] = {
	    { perf_ctrs.head->fd, POLLIN, 0 },
	    { sfd, POLLIN, 0 }
	};
	EXPECT_ERRNO(poll(pfd, 2, -1) != -1);

	if (pfd[0].revents & POLLIN)
	    dump_events();
	
	if (pfd[1].revents & POLLIN)
	    handle_signal(sfd);
    }
}


/*** argument handling ************************************************/
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'p':
	attach_pid = perf_argp_parse_long("PID", arg, state);
	break;

    case 'o':
	output_name = arg;
	break;

    case 'c':
	force_cpu = perf_argp_parse_long("CPU", arg, state);
	if (force_cpu < 0)
	    argp_error(state, "CPU number must be positive\n");
	break;

    case ARGP_KEY_ARG:
	if (!state->quoted)
	    argp_error(state, "Illegal argument\n");
	break;
     
    case ARGP_KEY_END:
	if (state->quoted && state->quoted < state->argc)
	    exec_argv = &state->argv[state->quoted];

	if (exec_argv && attach_pid != NO_PID)
	    argp_error(state,
		       "Both a command to execute and a PID to attach have\n"
		       "been specified. Make up your mind!\n");
	else if (!exec_argv && attach_pid == NO_PID)
	    argp_error(state,
		       "Neither a command to execute, nor a PID to attach have\n"
		       "been specified. Don't know what to do.\n");

	if (output_name) {
	    output = fopen(output_name, "w");
	    if (!output)
		argp_failure(state, EXIT_FAILURE, errno,
			     "Failed to open output file");
	} else
	    output = stdout;

	break;
     
    default:
	return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

const char *argp_program_version =
    "perfrecord";

const char *argp_program_bug_address =
    "andreas.sandberg@it.uu.se";

static struct argp_option arg_options[] = {
    { "output", 'o', "FILE", 0, "Output file", 0 },
    { "pid", 'p', "PID", 0, "Attach to process PID", 0 },
    { "force-cpu", 'c', "CPU", 0,
      "Pin child process to CPU. This option does not work with attach.", 0 },

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
    .doc = "Simple interface for monitoring performance counters",
    .children = arg_children,
};

int
main(int argc, char **argv)
{
    perf_base_attr.sample_type =
	PERF_SAMPLE_IP | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ;
    perf_base_attr.read_format =
	PERF_FORMAT_ID | PERF_FORMAT_GROUP;

    argp_parse (&argp, argc, argv,
		ARGP_IN_ORDER,
		0,
		NULL);

    page_size = sysconf(_SC_PAGE_SIZE);
    buf_mask = page_size * (RING_BUF_NUM_PAGES - 1) - 1;
    EXPECT_ERRNO(page_size != -1);

    EXPECT(ctrs_write_header(&perf_ctrs, output) == 1);

    if (exec_argv)
	do_start();
    else
	do_attach();

    exit(EXIT_SUCCESS);
}
