// SPDX-License-Identifier: GPL-2.0
#include "stats.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "utils.bpf.h"


// MARK: cpu_stat
struct cpu_stat {
	u64	idl_time; 	/* Idle time */
	u64	svc_time; 	/* Service time */
	u64	timestamp;	/* The last timestamp */
	bool	is_idle;	/* The current CPU state */
	bool	is_initialized;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cpu_stat);
} cpu_stat SEC(".maps");

static struct cpu_stat *get_cpu_stat(s32 cpu)
{
	const s32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_stat, &idx, cpu);
}

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

__hidden
void stat_per_cpu_init(s32 cpu)
{
	struct cpu_stat *stat = get_cpu_stat_or_ret(cpu);

	bpf_printk("[*] stats_per_cpu_init: cpu=%d", cpu);

	stat->is_initialized = false;
	stat->idl_time = 0;
	stat->svc_time = 0;
}

__hidden
void stats_at_update_idle(s32 cpu, bool idle)
{
	struct cpu_stat *stat = get_cpu_stat_or_ret(cpu);
	u64 now = bpf_ktime_get_boot_ns();
	u64 elapsed_time;

	if (unlikely(!stat->is_initialized)) {
		stat->timestamp = now;
		stat->is_idle = idle;
		stat->is_initialized = true;
		return;
	}
	
	assert(stat->is_idle ^ idle);

	elapsed_time = now - stat->timestamp;
	if (stat->is_idle) {
		stat->idl_time += elapsed_time;
	} else {
		stat->svc_time += elapsed_time;
	}
	stat->timestamp = now;
	stat->is_idle = idle;
}

// MARK: task_stat
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
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, s32);
	__type(value, struct task_stat);
} task_stat SEC(".maps");

struct task_stat *get_task_stat(struct task_struct *p)
{
	return bpf_task_storage_get(&task_stat, p, 0, 0);
}

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
 * This function is called before the stats of @p are taken.
 */
__hidden
void stat_per_task_init(struct task_struct *p)
{
	struct task_stat *stat;
	
	stat = bpf_task_storage_get(&task_stat, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	assert_ret(stat);

	stat->state = TASK_STAT_STATE_quiescent;
	stat->timestamp = bpf_ktime_get_boot_ns();
	stat->runnable_time = 0;
	stat->running_time = 0;
	stat->stopping_time = 0;
	stat->quiescent_time = 0;
}

__hidden
void stat_at_runnable(struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_boot_ns();
	struct task_stat *stat = get_task_stat_or_ret(p);

	update_stat_state(stat, quiescent, runnable, now);
}

__hidden
void stat_at_running(struct task_struct *p)
{
	u64 now = bpf_ktime_get_boot_ns();
	struct task_stat *stat = get_task_stat_or_ret(p);

	if (stat->state == TASK_STAT_STATE_runnable) {
		update_stat_state(stat, runnable, running, now);
	} else {
		update_stat_state(stat, stopping, running, now);
	}
}

__hidden
void stat_at_stopping(struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_boot_ns();
	struct task_stat *stat = get_task_stat_or_ret(p);

	update_stat_state(stat, running, stopping, now);
}

__hidden
void stat_at_quiescent(struct task_struct *p, u64 deq_flags)
{
	u64 now = bpf_ktime_get_boot_ns();
	struct task_stat *stat = get_task_stat_or_ret(p);

	if (stat->state == TASK_STAT_STATE_runnable) {
		update_stat_state(stat, runnable, quiescent, now);
	} else {
		update_stat_state(stat, stopping, quiescent, now);
	}
}
