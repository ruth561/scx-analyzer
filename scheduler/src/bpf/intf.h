// SPDX-License-Identifier: GPL-2.0

/**
 * This header files contains common data structures and macros
 * used by both the BPF and application sides.
 */

#ifndef __INTF_H
#define __INTF_H

/**
 * The BPF map stats is defined in the BPF program.
 * The enum is used as the number of key in stats.
 */
enum stat_idx {
	CBID_NONE = 0,
	CBID_INIT,
	CBID_EXIT,
	CBID_INIT_TASK,
	CBID_EXIT_TASK,
	CBID_ENABLE,
	CBID_DISABLE,
	CBID_RUNNABLE,
	CBID_RUNNING,
	CBID_STOPPING,
	CBID_QUIESCENT,
	CBID_SELECT_CPU,
	CBID_ENQUEUE,
	CBID_DEQUEUE,
	CBID_DISPATCH,
	CBID_CPU_ONLINE,
	CBID_CPU_OFFLINE,
	CBID_SET_CPUMASK,
	CBID_SET_WEIGHT,
	CBID_TICK,
	CBID_UPDATE_IDLE,
	NR_CBID,

	TP_SCHED_SWITCH = 0x1000,

	TASK_DEADLINE = 0x2000,
};

static inline const char *get_string_from_cbid(int cbid)
{
	switch (cbid) {
	case CBID_SELECT_CPU:
		return "select_cpu";
	case CBID_ENQUEUE:
		return "enqueue";
	case CBID_DISPATCH:
		return "dispatch";
	case CBID_RUNNABLE:
		return "runnable";
	case CBID_RUNNING:
		return "running";
	case CBID_STOPPING:
		return "stopping";
	case CBID_QUIESCENT:
		return "quiescent";
	case CBID_INIT_TASK:
		return "init_task";
	case CBID_EXIT_TASK:
		return "exit_task";
	case CBID_ENABLE:
		return "enable";
	case CBID_DISABLE:
		return "disable";
	case CBID_INIT:
		return "init";
	case CBID_EXIT:
		return "exit";
	case CBID_SET_CPUMASK:
		return "set_cpumask";
	case CBID_SET_WEIGHT:
		return "set_weight";
	case CBID_TICK:
		return "tick";
	case CBID_UPDATE_IDLE:
		return "update_idle";
	case TP_SCHED_SWITCH:
		return "sched_switch";
	case TASK_DEADLINE:
		return "task deadline";
	default:
		return "UNKNOWN";
	}
}

typedef unsigned char u8;
typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;

struct entry_header {
	s32 cpu;
	s32 cbid;
	u64 start;
	u64 end;
	u8 aux[];
};

/*
 * Thread information.
 */
struct th_info {
	s32 pid;
	char comm[16];
};

struct select_cpu_aux {
	struct th_info th_info;
	s32 prev_cpu;
	u64 wake_flags;
	s32 selected_cpu;
};

struct enqueue_aux {
	struct th_info th_info;
	u64 enq_flags;
};

struct runnable_aux {
	struct th_info th_info;
	u64 enq_flags;
};

struct running_aux {
	struct th_info th_info;
};

struct stopping_aux {
	struct th_info th_info;
	s32 runnable; /* bool */
};

struct quiescent_aux {
	struct th_info th_info;
	u64 deq_flags;
};

struct init_task_aux {
	struct th_info th_info;
	s32 fork;
};

struct exit_task_aux {
	struct th_info th_info;
	s32 cancelled;
};

struct enable_aux {
	struct th_info th_info;
};

struct disable_aux {
	struct th_info th_info;
};

struct set_cpumask_aux {
	struct th_info th_info;
	u64 cpumask;
};

struct set_weight_aux {
	struct th_info th_info;
	u32 weight;
};

struct tick_aux {
	struct th_info th_info;
};

struct update_idle_aux {
	s32 cpu;
	s32 idle; /* bool */
};

struct tp_sched_switch_aux {
	struct th_info prev;
	struct th_info next;
};

struct task_deadline_aux {
	struct th_info th_info;
	u64 wake_up_time;
	u64 relative_deadline;
	u64 deadline;
};

static const u64 ENTRY_SIZE = sizeof(struct entry_header);

struct task_work_info {
	u64 exectime;
	u64 sched_hint;
};

#endif /* __INTF_H */
