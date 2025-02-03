// SPDX-License-Identifier: GPL-2.0
#ifndef __SCHED_BPF_H
#define __SCHED_BPF_H

#include <scx/common.bpf.h>


/*
 * Defined in sched.bpf.c
 */
s32 ops_init(void);
void ops_exit(struct scx_exit_info *ei);
s32 ops_init_task(struct task_struct *p, struct scx_init_task_args *args);
void ops_exit_task(struct task_struct *p, struct scx_exit_task_args *args);
void ops_enable(struct task_struct *p);
void ops_disable(struct task_struct *p);
void ops_runnable(struct task_struct *p, u64 enq_flags);
void ops_running(struct task_struct *p);
void ops_stopping(struct task_struct *p, bool runnable);
void ops_quiescent(struct task_struct *p, u64 deq_flags);
s32 ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
void ops_enqueue(struct task_struct *p, u64 enq_flags);
void ops_dispatch(s32 cpu, struct task_struct *prev);
void ops_set_cpumask(struct task_struct *p, const struct cpumask *cpumask);
void ops_set_weight(struct task_struct *p, u32 weight);
void ops_tick(struct task_struct *p);
void ops_update_idle(s32 cpu, bool idle);

/*
 * Defined in main.bpf.c
 */
void record_task_deadline(struct task_struct *p, u64 wake_up_time, u64 relative_deadline, u64 deadline);

#endif
