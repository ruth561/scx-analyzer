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
	TUTORIAL_NR_STATS,
};

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

struct select_cpu_aux {
	s32 pid;
	s32 prev_cpu;
	u64 wake_flags;
};

const u64 ENTRY_SIZE = sizeof(struct entry_header);

#endif /* __INTF_H */
