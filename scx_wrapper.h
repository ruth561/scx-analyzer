#pragma once

#include "scheduler/src/bpf/intf.h"

void init_perfetto(void);
void start_perfetto_trace(const char *output_file);
void stop_perfetto_trace(void);

void trace_select_cpu(struct entry_header *hdr, struct select_cpu_aux *aux);
void trace_enqueue(struct entry_header *hdr, struct enqueue_aux *aux);
void trace_normal(struct entry_header *hdr, void *_aux);

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
