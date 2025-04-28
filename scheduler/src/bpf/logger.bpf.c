// SPDX-License-Identifier: GPL-2.0
#include "intf.h"
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

__hidden
void log_task_info(struct task_struct *p, u32 tid, u32 src_node_tid, u32 weight)
{
	struct task_info info;

	info.log_type = LOG_TYPE_TASK_INFO;
	info.tid = tid;
	info.src_node_tid = src_node_tid;
	info.weight = weight;
	*(u64 *) &info.comm[0] = *(u64 *)&p->comm[0];
	*(u64 *) &info.comm[8] = *(u64 *)&p->comm[8];

	LOGGER(&info);
}

__hidden
void log_work_info(u32 tid, u64 exectime, u64 weight)
{
	struct work_info info;

	info.log_type = LOG_TYPE_WORK_INFO;
	info.tid = tid;
	info.exectime = exectime;
	info.weight = weight;

	LOGGER(&info);
}
