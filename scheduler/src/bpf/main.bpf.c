// SPDX-License-Identifier: GPL-2.0

#include "intf.h"
#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
char _license[] SEC("license") = "GPL";

// #include "scheds/template.bpf.c"
#include "isolcpus.bpf.c"

#define BPF_RINGBUF_SIZE (4096 * 4096)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BPF_RINGBUF_SIZE);
} cb_history_rb SEC(".maps");

struct bpf_cpumask record_cpumask;

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

/*
 * Check if it should be recorded at this time?
 * TODO: Implement filtering for each ops callback
 */
static bool should_record(s32 cbid)
{
	s32 cpu = bpf_get_smp_processor_id();

	/*
	* Since bpf_cpumask_test_cpu cannot be invoked from a tracepoint,
	* the check is performed using the lower 64 bits.
	*/
	if (record_cpumask.cpumask.bits[0] & (1 << cpu)) {
		return true;
	}

	return false;
}

static void record_select_cpu(u64 start, u64 end, struct task_struct *p, s32 prev_cpu, u64 wake_flags, s32 selected_cpu)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct select_cpu_aux);

	u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct select_cpu_aux *aux = (struct select_cpu_aux *) &buf[hdr_size];

	if (!should_record(CBID_SELECT_CPU))
		return;

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

	if (!should_record(CBID_ENQUEUE))
		return;

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

	if (!should_record(CBID_RUNNABLE))
		return;

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

	if (!should_record(CBID_STOPPING))
		return;

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

	if (!should_record(CBID_RUNNING))
		return;

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

	if (!should_record(CBID_QUIESCENT))
		return;

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

	if (!should_record(CBID_INIT_TASK))
		return;

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

	if (!should_record(CBID_EXIT_TASK))
		return;

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

	if (!should_record(CBID_ENABLE))
		return;

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

	if (!should_record(CBID_DISABLE))
		return;

	set_header(hdr, CBID_DISABLE, start, end);
	set_thread_info(&aux->th_info, p);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_set_cpumask(u64 start, u64 end, struct task_struct *p, const struct cpumask *cpumask)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct set_cpumask_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct set_cpumask_aux *aux = (struct set_cpumask_aux *) &buf[hdr_size];

	if (!should_record(CBID_SET_CPUMASK))
		return;

	set_header(hdr, CBID_SET_CPUMASK, start, end);
	set_thread_info(&aux->th_info, p);
	aux->cpumask = cpumask->bits[0]; /* set only first 64-bit */

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_set_weight(u64 start, u64 end, struct task_struct *p, u32 weight)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct set_weight_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct set_weight_aux *aux = (struct set_weight_aux *) &buf[hdr_size];

	if (!should_record(CBID_SET_WEIGHT))
		return;

	set_header(hdr, CBID_SET_WEIGHT, start, end);
	set_thread_info(&aux->th_info, p);
	aux->weight = weight;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_tick(u64 start, u64 end, struct task_struct *p)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct tick_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct tick_aux *aux = (struct tick_aux *) &buf[hdr_size];

	if (!should_record(CBID_TICK))
		return;

	set_header(hdr, CBID_TICK, start, end);
	set_thread_info(&aux->th_info, p);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_update_idle(u64 start, u64 end, s32 cpu, bool idle)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct update_idle_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct update_idle_aux *aux = (struct update_idle_aux *) &buf[hdr_size];

	if (!should_record(CBID_UPDATE_IDLE))
		return;

	set_header(hdr, CBID_UPDATE_IDLE, start, end);
	aux->cpu = cpu;
	aux->idle = idle;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

static void record_task_deadline(struct task_struct *p, u64 wake_up_time, u64 relative_deadline, u64 deadline)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct task_deadline_aux);

	u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct task_deadline_aux *aux = (struct task_deadline_aux *) &buf[hdr_size];

	if (!should_record(TASK_DEADLINE))
		return;

	set_header(hdr, TASK_DEADLINE, deadline, deadline + 100); /* 100ns is dummy */
	set_thread_info(&aux->th_info, p);
	aux->wake_up_time = wake_up_time;
	aux->relative_deadline = relative_deadline;
	aux->deadline = deadline;

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

	if (!should_record(cbid))
		return;

	set_header(hdr, cbid, start, end);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}

// MARK: init/..
/*******************************************************************************
 * Callbacks for initialization and deinitialization
 */

s32 BPF_STRUCT_OPS_SLEEPABLE(scheduler_init)
{
	s32 ret;
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ret = ops_init();

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_normal(CBID_INIT, start, end);

	return ret;
}

void BPF_STRUCT_OPS_SLEEPABLE(scheduler_exit, struct scx_exit_info *ei)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_exit(ei);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_normal(CBID_EXIT, start, end);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(scheduler_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	s32 ret;
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ret = ops_init_task(p, args);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_init_task(start, end, p, args->fork);
	return ret;
}

void BPF_STRUCT_OPS(scheduler_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_exit_task(p, args);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_exit_task(start, end, p, args->cancelled);
}

// MARK: enable/..
void BPF_STRUCT_OPS(scheduler_enable, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_enable(p);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_enable(start, end, p);
}

void BPF_STRUCT_OPS(scheduler_disable, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_disable(p);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_disable(start, end, p);
}

// MARK: runnable/..
/*******************************************************************************
 * Callbacks for inspecting task state transitions
 */

void BPF_STRUCT_OPS(scheduler_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_runnable(p, enq_flags);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_runnable(start, end, p, enq_flags);
}

void BPF_STRUCT_OPS(scheduler_running, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_running(p);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_running(start, end, p);
}

void BPF_STRUCT_OPS(scheduler_stopping, struct task_struct *p, bool runnable)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_stopping(p, runnable);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_stopping(start, end, p, runnable);
}

void BPF_STRUCT_OPS(scheduler_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_quiescent(p, deq_flags);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_quiescent(start, end, p, deq_flags);
}

// MARK: select_cpu/..
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
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_enqueue(p, enq_flags);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_enqueue(start, end, p, enq_flags);
}

void BPF_STRUCT_OPS(scheduler_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_dispatch(cpu, prev);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_normal(CBID_DISPATCH, start, end);
}

// MARK: set_cpumask/..
/*******************************************************************************
 * Callbacks for changing the scheduling policy
 */

void BPF_STRUCT_OPS(scheduler_set_cpumask, struct task_struct *p,
                    const struct cpumask *cpumask)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_set_cpumask(p, cpumask);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_set_cpumask(start, end, p, cpumask);
}

void BPF_STRUCT_OPS(scheduler_set_weight, struct task_struct *p, u32 weight)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_set_weight(p, weight);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_set_weight(start, end, p, weight);
}

void BPF_STRUCT_OPS(scheduler_tick, struct task_struct *p)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_tick(p);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_tick(start, end, p);
}

void BPF_STRUCT_OPS(scheduler_update_idle, s32 cpu, bool idle)
{
	u64 start, end;

	start = bpf_ktime_get_boot_ns();

	// ================= implementation ===================== //

	ops_update_idle(cpu, idle);

	// ====================================================== //

	end = bpf_ktime_get_boot_ns();
	record_update_idle(start, end, cpu, idle);
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

	.set_cpumask	= (void *) scheduler_set_cpumask,
	.set_weight	= (void *) scheduler_set_weight,

	.tick		= (void *) scheduler_tick,
	.update_idle	= (void *) scheduler_update_idle,

	.timeout_ms	= 5000,

	.flags		= SCX_OPS_KEEP_BUILTIN_IDLE,
	// .flags		= SCX_OPS_ENQ_LAST,

	.name		= "scheduler");

// MARK: tracepoints

struct tp_sched_switch_format {
        u64 dummy;
        char prev_comm[16];
        s32 prev_pid;
        s32 prev_prio;
        s64 prev_state;
        char next_comm[16];
        s32 next_pid;
        s32 next_prio;
};

SEC("tp/sched/sched_switch")
void tp_sched_switch(struct tp_sched_switch_format *ctx)
{
	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct tp_sched_switch_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct tp_sched_switch_aux *aux = (struct tp_sched_switch_aux *) &buf[hdr_size];
	u64 now = bpf_ktime_get_boot_ns();

	if (!should_record(TP_SCHED_SWITCH))
		return;

	set_header(hdr, TP_SCHED_SWITCH, now, now + 100); /* 1000 is dummy */
	
	aux->prev.pid = ctx->prev_pid;
	__builtin_memcpy(&aux->prev.comm, &ctx->prev_comm, 16);
	aux->next.pid = ctx->next_pid;
	__builtin_memcpy(&aux->next.comm, &ctx->next_comm, 16);

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}
