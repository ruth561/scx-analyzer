// SPDX-License-Identifier: GPL-2.0
#ifndef __STATS_BPF_H
#define __STATS_BPF_H

#include <scx/common.bpf.h>


void stat_per_task_init(struct task_struct *p);
void stat_per_cpu_init(s32 cpu);

void stat_at_runnable(struct task_struct *p, u64 enq_flags);
void stat_at_running(struct task_struct *p);
void stat_at_stopping(struct task_struct *p, bool runnable);
void stat_at_quiescent(struct task_struct *p, u64 deq_flags);

void stats_at_update_idle(s32 cpu, bool idle);

#endif
