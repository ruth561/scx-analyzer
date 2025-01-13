/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2024 Takumi Jin */
#include <perfetto.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>

#include <bpf/libbpf.h>

#include "ring_buffer.h"
#include "scx_wrapper.h"
#include "scheduler/src/bpf/intf.h"



static const char *output_file = "output.perfetto-trace";
static const char *ring_buffer_name = "cb_history_rb";

static volatile bool tracing_on = false;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

#define MIN_EVENT_WIDTH 100 /* ns */

int ring_buffer_handler(void *ctx, void *data, size_t size)
{
	struct entry_header *hdr = (struct entry_header *) data;
	void *aux = (u8 *) data + sizeof(struct entry_header);

	if (!tracing_on)
		return 0;

	switch (hdr->cbid) {
	case CBID_SELECT_CPU:
		trace_select_cpu(hdr, (struct select_cpu_aux *) aux);
		break;
	case CBID_ENQUEUE:
		trace_enqueue(hdr, (struct enqueue_aux *) aux);
		break;
	case CBID_RUNNABLE:
		trace_runnable(hdr, (struct runnable_aux *) aux);
		break;
	case CBID_RUNNING:
		trace_running(hdr, (struct running_aux *) aux);
		break;
	case CBID_STOPPING:
		trace_stopping(hdr, (struct stopping_aux *) aux);
		break;
	case CBID_QUIESCENT:
		trace_quiescent(hdr, (struct quiescent_aux *) aux);
		break;
	case CBID_INIT_TASK:
		trace_init_task(hdr, (struct init_task_aux *) aux);
		break;
	case CBID_EXIT_TASK:
		trace_exit_task(hdr, (struct exit_task_aux *) aux);
		break;
	case CBID_ENABLE:
		trace_enable(hdr, (struct enable_aux *) aux);
		break;
	case CBID_DISABLE:
		trace_disable(hdr, (struct disable_aux *) aux);
		break;
	case CBID_SET_CPUMASK:
		trace_set_cpumask(hdr, (struct set_cpumask_aux *) aux);
		break;
	case CBID_SET_WEIGHT:
		trace_set_weight(hdr, (struct set_weight_aux *) aux);
		break;
	case CBID_TICK:
		trace_tick(hdr, (struct tick_aux *) aux);
		break;
	case CBID_UPDATE_IDLE:
		trace_update_idle(hdr, (struct update_idle_aux *) aux);
		break;
	case TP_SCHED_SWITCH:
		trace_sched_switch(hdr, (struct tp_sched_switch_aux *) aux);
		break;
	case TASK_DEADLINE:
		trace_task_deadline(hdr, (struct task_deadline_aux *) aux);
		break;
	case CBID_DISPATCH:
		/* fallthrough */
	default:
		trace_normal(hdr, aux);
		break;
	}

	return 0;
}

int main(int argc, char** argv) {
	int err;
	struct ring_buffer *rb;

	/*
	 * Finds the ring buffer.
	 */
	printf("Finding the ring buffer named \"%s\"\n", ring_buffer_name);

	rb = create_rb_subscriber(ring_buffer_name, ring_buffer_handler);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer subscriber\n");
		return -1;
	}

	printf("Found the ring buffer!\n");

	/*
	 * Starts scx-analyzer.
	 */
	printf("Starting scx-analyzer\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	init_perfetto();

	printf("Consuming data in the ring buffer...\n");

	/*
	 * Consumes all data in rb before starting tracing.
	 */
	while (ring_buffer__consume(rb) > 0);

	printf("Collecting data, CTRL+c to stop\n");

	start_perfetto_trace(output_file);

	tracing_on = true;

	while (!exiting) {
		err = ring_buffer__poll(rb, 100); /* 100ms */
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "Failed to poll ring buffer\n");
			break;
		}
	}

	stop_perfetto_trace();

	printf("\rCollected %s\n", output_file);

	return err;
}
