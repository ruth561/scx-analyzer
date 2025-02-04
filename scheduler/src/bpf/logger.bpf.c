// SPDX-License-Identifier: GPL-2.0
#include "logger.bpf.h"
#include "vmlinux.h"


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, LOGGER_BUF_SIZE);
} logger_rb SEC(".maps");

__hidden
void logger(void *data, u32 size)
{
	bpf_ringbuf_output(&logger_rb, data, size, 0);
}
