// SPDX-License-Identifier: GPL-2.0
#ifndef __STAT_BPF_H
#define __STAT_BPF_H

#include <scx/common.bpf.h>
#include "utils.bpf.h"

struct cpu_stat {
	u64	idl_time; 	/* Idle time */
	u64	svc_time; 	/* Service time */
	u64	timestamp;	/* The last timestamp */
	bool	is_idle;	/* The current CPU state */
	bool	is_initialized;
};

enum task_state {
	TASK_STAT_STATE_runnable,
	TASK_STAT_STATE_running,
	TASK_STAT_STATE_stopping,
	TASK_STAT_STATE_quiescent,
};

struct task_stat {
	u32	state;
	u64	timestamp;
	u64	runnable_time;
	u64	running_time;
	u64	stopping_time;
	u64	quiescent_time;

	/*
	 * The average exection time per work can be calculated using the following formula:
	 *   exectime_avg = exectime_sum / work_cnt
	 */
	u64	work_cnt;	/* Counter representing how often the thread wakes up to perform its work. */
	u64	exectime_acm;	/* Accmulated exectime from runnable to quiescent state */
	u64	exectime_sum;	/* Total CPU time consumed by the thread. */
};

void stat_per_task_init(struct task_struct *p);
void stat_per_cpu_init(s32 cpu);

struct task_stat *get_task_stat(struct task_struct *p);
struct cpu_stat *get_cpu_stat(s32 cpu);

/*
 * For more details about this macro, see the comment for get_cpu_stat_or_ret.
 */
#define get_task_stat_or_ret(p)					\
	({							\
		struct task_stat *stat = get_task_stat(p);	\
		assert_ret(stat);				\
		stat;						\
	})

#define update_stat_state(stat, prev_state, next_state, now)		\
	do {								\
		assert(stat->state == TASK_STAT_STATE_##prev_state);	\
		stat->prev_state##_time += now - stat->timestamp;	\
		stat->timestamp = now;					\
		stat->state = TASK_STAT_STATE_##next_state;		\
	} while (0)

/*
 * This macro attempts to retrieve a pointer to the struct cpu_stat.
 * If the pointer is NULL, it asserts and returns immediately.
 * This macro is inspired by Rust's `?` operator.
 */
#define get_cpu_stat_or_ret(cpu)				\
	({							\
		struct cpu_stat *stat = get_cpu_stat(cpu);	\
		assert_ret(stat);				\
		stat;						\
	})

void stat_at_runnable(struct task_struct *p, u64 enq_flags);
void stat_at_running(struct task_struct *p);
void stat_at_stopping(struct task_struct *p, bool runnable);
void stat_at_quiescent(struct task_struct *p, u64 deq_flags);

void stat_at_update_idle(s32 cpu, bool idle);

#endif
