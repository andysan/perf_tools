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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include <argp.h>

#include "expect.h"
#include "perf_compat.h"
#include "perf_file.h"
#include "dumpers.h"

static FILE *input;
static char *output_name;
static char *input_name;

static dumper_config_t conf = {
    .output = NULL,
    .delta = 0,
};

static dumper_t *dumper = &dumper_dump;

static ctr_list_t ctrs;

static event_dumper_t *
find_dumper(uint32_t type)
{
    for (event_dumper_t *ed = dumper->events; ed->f; ed++)
        if (ed->type == type)
            return ed;

    return &dumper->event_unknown;
}

static int
dump_event()
{
    struct perf_event_header hdr;
    event_dumper_t *dumper;
    char data[0xFFFF];

    if (fread(&hdr, sizeof(hdr), 1, input) != 1)
        return -1;

    assert(hdr.size >= sizeof(hdr));
    if (fread(data, hdr.size - sizeof(hdr), 1, input) != 1)
        return -1;

    dumper = find_dumper(hdr.type);
    dumper->f(data, hdr.type, hdr.misc, hdr.size - sizeof(hdr));

    return 0;
}

static void
dump_events()
{
    while (dump_event() != -1)
        ;

    if (ferror(input)) {
        perror("Failed to read events");
        exit(EXIT_FAILURE);
    }
}

/*** argument handling ************************************************/
const char *argp_program_version =
    "perfdump";

const char *argp_program_bug_address =
    "andreas.sandberg@it.uu.se";

static char doc[] =
    "Test program to produce a human-readable dump of a perf file";

static char args_doc[] = "[FILE]";

static struct argp_option options[] = {
    { "output", 'o', "FILE", 0, "Write output to file", 0 },
    { "format", 'f', "FORMAT", 0, "Output format (dump/csv)" },
    { "delta", 'd', NULL, 0,
      "Output the deltas rather than the actual counter values" },
    { 0 }
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    switch (key)
    {
    case 'o':
        output_name = arg;
        break;

    case 'f':
        if (!strcmp("dump", arg))
            dumper = &dumper_dump;
        else if (!strcmp("csv", arg))
            dumper = &dumper_csv;
        else
            argp_error(state, "Illegal output format\n");
        break;

    case 'd':
        conf.delta = 1;
        break;

    case ARGP_KEY_ARG:
        if (state->arg_num == 0)
            input_name = arg;
        else
            argp_error(state, "Illegal argument\n");
            
        break;

    case ARGP_KEY_END:
        if (input_name) {
            input = fopen(input_name, "r");
            if (!input)
                argp_failure(state, EXIT_FAILURE, errno,
                             "Failed to open input file");
        } else
            input = stdin;

        if (output_name) {
            conf.output = fopen(output_name, "w");
            if (!conf.output)
                argp_failure(state, EXIT_FAILURE, errno,
                             "Failed to open output file");
        } else
            conf.output = stdout;

        break;
     
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int
main(int argc, char **argv)
{
    argp_parse (&argp, argc, argv,
                ARGP_IN_ORDER,
                0,
                NULL);


    EXPECT(ctrs_read_header(&ctrs, input) == 1);
    EXPECT(ctrs.head);

    dumper->init(&ctrs, &conf);
    dump_events();

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
