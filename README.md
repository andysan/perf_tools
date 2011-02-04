UART Perf Tools
===============

The UART Perf Tools project is a project to develop a small set of
tools to use the Linux perf_event framework. Most of the tools are
built to be used for data acquisition in our research projects.


rawperf
--------

Monitor an application and write performance counter statistics to
STDOUT. The tool dumps the statistics on exit or when receiving a
SIGUSR1.

We normally use this tool to test performance counter settings and to
measure whole-program statistics.


perfrecord
----------

Monitor an application and dump the raw perf event ring buffer data to
STDOUT or a file.

**NOTE:** The output file format is not considered stable. There is no
  guarantee that the output from two different versions of perfrecord
  will be compatible.

See perf_file.c for a description of the file header. Except for the
header, the file is simply a dump of the kernel ring buffer.

perfdump
--------

Process an output file from perfrecord and create a human readable
dump of the file.

