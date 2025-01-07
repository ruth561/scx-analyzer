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
	NR_CBID,
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

const u64 ENTRY_SIZE = sizeof(struct entry_header);

#endif /* __INTF_H */
