// SPDX-License-Identifier: GPL-2.0
/*
 * Main implementation of the scheduler.
 */

#include "intf.h"
#include "vmlinux.h"
#include <scx/common.bpf.h>

#define SHARED_DSQ 0
UEI_DEFINE(uei);

// MARK: init/exit
/*******************************************************************************
 * Callbacks for initialization and deinitialization
 */

s32 ops_init()
{
        bpf_printk("[*] scheduler starts");
        return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void ops_exit(struct scx_exit_info *ei)
{
        UEI_RECORD(uei, ei);
        bpf_printk("[*] scheduler exits");
}

s32 ops_init_task(struct task_struct *p, struct scx_init_task_args *args)
{
        return 0;
}

void ops_exit_task(struct task_struct *p, struct scx_exit_task_args *args)
{
        return;
}

// MARK: enable/disable
void ops_enable(struct task_struct *p)
{
}

void ops_disable(struct task_struct *p)
{
}

// MARK: state transition
/*******************************************************************************
 * Callbacks for inspecting task state transitions
 */

void ops_runnable(struct task_struct *p, u64 enq_flags)
{
}

void ops_running(struct task_struct *p)
{
}

void ops_stopping(struct task_struct *p, bool runnable)
{
}

void ops_quiescent(struct task_struct *p, u64 deq_flags)
{
}

// MARK: select_cpu
/*******************************************************************************
 * Callbacks for scheduling decisions
 */

s32 ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
        bool is_idle;
        
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

void ops_enqueue(struct task_struct *p, u64 enq_flags)
{
        u64 slice;

        slice = 5000000u / scx_bpf_dsq_nr_queued(SHARED_DSQ);
	scx_bpf_dispatch(p, SHARED_DSQ, slice, enq_flags);
}

void ops_dispatch(s32 cpu, struct task_struct *prev)
{
        scx_bpf_consume(SHARED_DSQ);
}
