CC=gcc
LD=gcc
KERNEL_RELEASE=$(shell uname -r)
KERNEL_SRC=/lib/modules/$(KERNEL_RELEASE)/source

# Check if perf_event there is a perf_event.h available in the source
# of the running kernel. In that case, assume that it's newer and use
# that.
ifneq ($(wildcard $(KERNEL_SRC)/include/linux/perf_event.h),)
  PERF_EVENT_H=$(KERNEL_SRC)/include/linux/perf_event.h
  CONFIG+=-DPERFH=\"$(PERF_EVENT_H)\"
else
  PERF_EVENT_H=/usr/include/linux/perf_event.h
endif

ifeq ($(wildcard $(PERF_EVENT_H)),)
  $(error "Can't find a usable perf_event header file")
endif

# Check if the header file has support for the precise_ip option. This
# is not the case for old header files.
ifneq ($(shell grep '^[[:space:]]*precise_ip' $(PERF_EVENT_H) 2>/dev/null),)
CONFIG+=-DHAVE_PRECISE_IP
endif

CFLAGS=-g -Wall -std=gnu99 $(CONFIG)


all: rawperf perfrecord perfdump

%.o: %.c util.h expect.h perf_common.h perf_file.h dumpers.h perf_argp.h

rawperf: rawperf.o util.o perf_common.o perf_argp.o

perfrecord: perfrecord.o util.o perf_file.o perf_common.o perf_argp.o

perfdump: perfdump.o perf_file.o perf_common.o util.o dumper_csv.o dumper_dump.o

clean:
	$(RM) *.o rawperf perfrecord perfdump

.PHONY: all clean
