# Scheduler

This directory contains the implementations of scx schedulers. To use this scheduler, you need a kernel version **>= v6.12**.

## Directory Overview

### src/main.rs

A user-space application that loads the eBPF scheduler into the kernel and prints log messages sent from the eBPF side.

### src/bpf/*.bpf.c

The implementation of the scx scheduler is located in `src/bpf/`. This subdirectory contains `*.bpf.c`, with the scheduler implementation split into multiple files:

* **main.bpf.c**: Implements the `struct_ops` data structure and the process of collecting logs to be passed to Perfetto and writing them to a ring buffer.
* **sched.bpf.c**: Contains the core scheduling logic. You can implement a custom scheduling algorithm by modifying this file.
* **stat.bpf.c**: Implements functionality related to statistics.
* **logger.bpf.c**: Implements logging functionality. The `LOGGER` macro is defined here, enabling loging to userspace. Logs are output to `stdout` related to the eBPF loader.

## Core Implementation of the Scheduler

Currenty, an **isolcpus-based scheduler** is implemented in `src/bpf/sched.bpf.c`. This scheduler is aware of the kernel parameter `isolcpus`, and schedules based on its value.

### Kernel Restriction and Workaround

The current `sched_ext` implementation **prevents loading scx schedulers when `isolcpus` is specified**. For details, refer to [this commit](https://github.com/ruth561/linux/commit/9f391f94a1730232ad2760202755b2d9baf4688d). **To use the isolcpus scheduler, you must use a kernel where [these four lines](https://github.com/torvalds/linux/blob/c45323b7560ec87c37c729b703c86ee65f136d75/kernel/sched/ext.c#L5448-L5452) are commented out**.
