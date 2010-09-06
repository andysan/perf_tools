CC=gcc
LD=gcc
KERNEL_RELEASE=$(shell uname -r)
KERNEL_SRC=/lib/modules/$(KERNEL_RELEASE)/source
CFLAGS=-g -Wall -std=gnu99 -DPERFH=\"$(KERNEL_SRC)/include/linux/perf_event.h\"


all: rawperf perfrecord perfdump

%.o: %.c util.h expect.h perf_common.h perf_file.h dumpers.h perf_argp.h

rawperf: rawperf.o util.o perf_common.o perf_argp.o

perfrecord: perfrecord.o util.o perf_file.o perf_common.o perf_argp.o

perfdump: perfdump.o perf_file.o perf_common.o util.o dumper_csv.o dumper_dump.o

clean:
	$(RM) *.o rawperf perfrecord perfdump

.PHONY: all clean
