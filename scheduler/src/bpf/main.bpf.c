// SPDX-License-Identifier: GPL-2.0

#include "intf.h"
#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#define SHARED_DSQ 0
UEI_DEFINE(uei);
char _license[] SEC("license") = "GPL";

#include "sched.bpf.c"

#define BPF_RINGBUF_SIZE (4096 * 4096)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BPF_RINGBUF_SIZE);
} cb_history_rb SEC(".maps");

static void set_header(struct entry_header *header, u32 cbid, u64 start, u64 end)
{
	s32 cpu = bpf_get_smp_processor_id();
	header->cpu = cpu;
	header->cbid = cbid;
	header->start = start;
	header->end = end;
}

static void set_thread_info(struct th_info *th_info, struct task_struct *p)
{
	th_info->pid = p->pid;
	__builtin_memcpy(&th_info->comm, &p->comm, 16);
}

static void record_select_cpu(u64 start, u64 end, struct task_struct *p, s32 prev_cpu, u64 wake_flags, s32 selected_cpu)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct select_cpu_aux);

	u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct select_cpu_aux *aux = (struct select_cpu_aux *) &buf[hdr_size];

	set_header(hdr, CBID_SELECT_CPU, start, end);
	set_thread_info(&aux->th_info, p);
	aux->prev_cpu = prev_cpu;
	aux->wake_flags = wake_flags;
	aux->selected_cpu = selected_cpu;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_enqueue(u64 start, u64 end, struct task_struct *p, u64 enq_flags)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct enqueue_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct enqueue_aux *aux = (struct enqueue_aux *) &buf[hdr_size];

	set_header(hdr, CBID_ENQUEUE, start, end);
	set_thread_info(&aux->th_info, p);
	aux->enq_flags = enq_flags;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_runnable(u64 start, u64 end, struct task_struct *p, u64 enq_flags)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct runnable_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct runnable_aux *aux = (struct runnable_aux *) &buf[hdr_size];

	set_header(hdr, CBID_RUNNABLE, start, end);
	set_thread_info(&aux->th_info, p);
	aux->enq_flags = enq_flags;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_stopping(u64 start, u64 end, struct task_struct *p, s32 runnable)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct stopping_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct stopping_aux *aux = (struct stopping_aux *) &buf[hdr_size];

	set_header(hdr, CBID_STOPPING, start, end);
	set_thread_info(&aux->th_info, p);
	aux->runnable = runnable;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_running(u64 start, u64 end, struct task_struct *p)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct running_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct running_aux *aux = (struct running_aux *) &buf[hdr_size];

	set_header(hdr, CBID_RUNNING, start, end);
	set_thread_info(&aux->th_info, p);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_quiescent(u64 start, u64 end, struct task_struct *p, u64 deq_flags)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct quiescent_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct quiescent_aux *aux = (struct quiescent_aux *) &buf[hdr_size];

	set_header(hdr, CBID_QUIESCENT, start, end);
	set_thread_info(&aux->th_info, p);
	aux->deq_flags = deq_flags;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_init_task(u64 start, u64 end, struct task_struct *p, s32 fork)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct init_task_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct init_task_aux *aux = (struct init_task_aux *) &buf[hdr_size];

	set_header(hdr, CBID_INIT_TASK, start, end);
	set_thread_info(&aux->th_info, p);
	aux->fork = fork;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_exit_task(u64 start, u64 end, struct task_struct *p, s32 cancelled)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct exit_task_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct exit_task_aux *aux = (struct exit_task_aux *) &buf[hdr_size];

	set_header(hdr, CBID_EXIT_TASK, start, end);
	set_thread_info(&aux->th_info, p);
	aux->cancelled = cancelled;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_enable(u64 start, u64 end, struct task_struct *p)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct enable_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct enable_aux *aux = (struct enable_aux *) &buf[hdr_size];

	set_header(hdr, CBID_ENABLE, start, end);
	set_thread_info(&aux->th_info, p);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_disable(u64 start, u64 end, struct task_struct *p)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct disable_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct disable_aux *aux = (struct disable_aux *) &buf[hdr_size];

	set_header(hdr, CBID_DISABLE, start, end);
	set_thread_info(&aux->th_info, p);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

/*
 * Without auxiliary information.
 */
static void record_normal(s32 cbid, u64 start, u64 end)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size;

	u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;

	set_header(hdr, cbid, start, end);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

/*******************************************************************************
 * Callbacks for initialization and deinitialization
 */

s32 BPF_STRUCT_OPS_SLEEPABLE(scheduler_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS_SLEEPABLE(scheduler_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(scheduler_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_init_task(start, end, p, args->fork);
	return 0;
}

void BPF_STRUCT_OPS(scheduler_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_exit_task(start, end, p, args->cancelled);
}

void BPF_STRUCT_OPS(scheduler_enable, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_enable(start, end, p);
}

void BPF_STRUCT_OPS(scheduler_disable, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_disable(start, end, p);
}

/*******************************************************************************
 * Callbacks for inspecting task state transitions
 */

void BPF_STRUCT_OPS(scheduler_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_runnable(start, end, p, enq_flags);
}

void BPF_STRUCT_OPS(scheduler_running, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_running(start, end, p);
}

void BPF_STRUCT_OPS(scheduler_stopping, struct task_struct *p, bool runnable)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_stopping(start, end, p, runnable);
}

void BPF_STRUCT_OPS(scheduler_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_quiescent(start, end, p, deq_flags);
}

/*******************************************************************************
 * Callbacks for scheduling decisions
 */

s32 BPF_STRUCT_OPS(scheduler_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 ret;
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ret = ops_select_cpu(p, prev_cpu, wake_flags);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_select_cpu(start, end, p, prev_cpu, wake_flags, ret);

	return ret;
}

void BPF_STRUCT_OPS(scheduler_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 slice;
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	slice = 5000000u / scx_bpf_dsq_nr_queued(SHARED_DSQ);
	scx_bpf_dispatch(p, SHARED_DSQ, slice, enq_flags);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_enqueue(start, end, p, enq_flags);
}

void BPF_STRUCT_OPS(scheduler_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	scx_bpf_consume(SHARED_DSQ);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_normal(CBID_DISPATCH, start, end);
}

SCX_OPS_DEFINE(scheduler_ops,
	.init		= (void *) scheduler_init,
	.exit		= (void *) scheduler_exit,

	.init_task	= (void *) scheduler_init_task,
	.exit_task	= (void *) scheduler_exit_task,
	.enable		= (void *) scheduler_enable,
	.disable	= (void *) scheduler_disable,

	.runnable	= (void *) scheduler_runnable,
	.running	= (void *) scheduler_running,
	.stopping	= (void *) scheduler_stopping,
	.quiescent	= (void *) scheduler_quiescent,

	.select_cpu	= (void *) scheduler_select_cpu,
	.enqueue	= (void *) scheduler_enqueue,
	.dispatch	= (void *) scheduler_dispatch,

	.name		= "scheduler");
