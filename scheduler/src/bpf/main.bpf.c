// SPDX-License-Identifier: GPL-2.0

#include "intf.h"
#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#define SHARED_DSQ 0
UEI_DEFINE(uei);
char _license[] SEC("license") = "GPL";

#define BPF_RINGBUF_SIZE (4096 * 4096)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BPF_RINGBUF_SIZE);
} cb_history_rb SEC(".maps");

void record_scx_cbs(void *ctx, u32 cbid, u64 start, u64 end)
{
	struct entry_header entry;
	s32 cpu = bpf_get_smp_processor_id();

	if (cpu != 0)
		return;

	entry.cpu = cpu;
	entry.cbid = cbid;
	entry.start = start;
	entry.end = end;
	
	bpf_ringbuf_output(&cb_history_rb, &entry, sizeof(entry), 0);
}

static void set_header(struct entry_header *header, u32 cbid, u64 start, u64 end)
{
	s32 cpu = bpf_get_smp_processor_id();

	if (cpu != 0)
		return;

	header->cpu = cpu;
	header->cbid = cbid;
	header->start = start;
	header->end = end;
}

static void record_select_cpu(u64 start, u64 end, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct select_cpu_aux);

	u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct select_cpu_aux *aux = (struct select_cpu_aux *) &buf[hdr_size];

	set_header(hdr, CBID_SELECT_CPU, start, end);
	aux->pid = p->pid;
	aux->prev_cpu = prev_cpu;
	aux->wake_flags = wake_flags;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_enqueue(u64 start, u64 end, struct task_struct *p, u64 enq_flags)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct enqueue_aux);

	u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct enqueue_aux *aux = (struct enqueue_aux *) &buf[hdr_size];

	set_header(hdr, CBID_ENQUEUE, start, end);
	aux->pid = p->pid;
	aux->enq_flags = enq_flags;

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
	record_scx_cbs(ctx, CBID_INIT_TASK, start, end);
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
	record_scx_cbs(ctx, CBID_EXIT_TASK, start, end);
}

void BPF_STRUCT_OPS(scheduler_enable, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_scx_cbs(ctx, CBID_ENABLE, start, end);
}

void BPF_STRUCT_OPS(scheduler_disable, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_scx_cbs(ctx, CBID_DISABLE, start, end);
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
	record_scx_cbs(ctx, CBID_RUNNABLE, start, end);
}

void BPF_STRUCT_OPS(scheduler_running, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_scx_cbs(ctx, CBID_RUNNING, start, end);
}

void BPF_STRUCT_OPS(scheduler_stopping, struct task_struct *p, bool runnable)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_scx_cbs(ctx, CBID_STOPPING, start, end);
}

void BPF_STRUCT_OPS(scheduler_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_scx_cbs(ctx, CBID_QUIESCENT, start, end);
}

/*******************************************************************************
 * Callbacks for scheduling decisions
 */

s32 BPF_STRUCT_OPS(scheduler_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 ret;
	bool is_idle;
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ret = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	// record_scx_cbs(ctx, CBID_SELECT_CPU, start, end);
	record_select_cpu(start, end, p, prev_cpu, wake_flags);

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
	record_scx_cbs(ctx, CBID_DISPATCH, start, end);
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
