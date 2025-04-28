// SPDX-License-Identifier: GPL-2.0
#ifndef __LOGGER_BPF_H
#define __LOGGER_BPF_H

#include <scx/common.bpf.h>


#define LOGGER_BUF_SIZE 0x1000000

void logger(void *data, u32 size);

#define LOGGER(data) logger(data, sizeof(*data))

void log_task_info(struct task_struct *p, u32 tid, u32 src_node_tid, u32 weight);
void log_work_info(u32 tid, u64 exectime, u64 weight);

#endif
