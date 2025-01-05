#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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

static const char *get_string_from_cbid(int cbid)
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
	default:
		return "UNKNOWN";
	}
}

typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;

struct cb_history_entry {
	s32 cpu;
	s32 cbid;
	u64 start;
	u64 end;
};

struct ring_buffer *create_rb_subscriber(const char *map_name, ring_buffer_sample_fn cb);
