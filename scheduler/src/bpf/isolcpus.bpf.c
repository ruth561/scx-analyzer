// SPDX-License-Identifier: GPL-2.0
/*
 * Main implementation of the scheduler.
 */

#include "intf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <scx/common.bpf.h>

#define SHARED_DSQ 0
UEI_DEFINE(uei);

#define MAX_NR_CPUS 512
s32 nr_cpus;
struct bpf_cpumask isolated_cpumask;
struct bpf_cpumask housekeeping_cpumask;

struct task_ctx {
	struct bpf_cpumask __kptr *tmp_cpumask;
        bool isolated;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, s32);
	__type(value, struct task_ctx);
} task_ctx SEC(".maps");

static bool task_is_isolated(struct task_struct *p)
{
        bool housekeeped, isolated;
        struct task_ctx *taskc;
	struct bpf_cpumask *cpumask;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] task_is_isolated: Failed to get task local storage");
		return false;
	}

        bpf_rcu_read_lock();

        cpumask = taskc->tmp_cpumask;
        if (!cpumask) {
		scx_bpf_error("[!] task_is_isolated (%s[%d]): taskc->tmp_cpumask is NULL", p->comm, p->pid);
		bpf_rcu_read_unlock();
		return false;
	}
	housekeeped = bpf_cpumask_and(cpumask, p->cpus_ptr, &housekeeping_cpumask.cpumask);
        isolated = bpf_cpumask_and(cpumask, p->cpus_ptr, &isolated_cpumask.cpumask);

        bpf_rcu_read_unlock();

        if (housekeeped && isolated) {
                bpf_printk("[?] %s[%d] is housekeeped and isolated", p->comm, p->pid);
                return false;
        }

        if (isolated) {
                // bpf_printk("[*] %s[%d] is isolated", p->comm, p->pid);
                return true;
        }

        if (housekeeped) {
                // bpf_printk("[*] %s[%d] is housekeeped", p->comm, p->pid);
                return false;
        }

        scx_bpf_error("[!] %s[%d] is neither housekeeped nor isolated", p->comm, p->pid);
        return false;
}

// MARK: init/exit
/*******************************************************************************
 * Callbacks for initialization and deinitialization
 */

s32 ops_init()
{
        s32 ret, cpu;

        bpf_printk("[*] isolcpus scheduler starts");

        /*
         * Init CPUs information.
         */
        nr_cpus = 12; /* Hard coding */
        bpf_cpumask_clear(&isolated_cpumask);
        bpf_cpumask_set_cpu(5, &isolated_cpumask);
        bpf_cpumask_set_cpu(11, &isolated_cpumask);

        bpf_for(cpu, 0, MAX_NR_CPUS) {
                if (cpu >= nr_cpus)
                        break;
                
                if (!bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask)) {
                        bpf_cpumask_set_cpu(cpu, &housekeeping_cpumask);
                }
        }

        bpf_printk("[*] isolated_cpumask: %lx", isolated_cpumask.cpumask.bits[0]);
        bpf_printk("[*] housekeeping_cpumask: %lx", housekeeping_cpumask.cpumask.bits[0]);

        /*
         * Creates a shared DSQ.
         */
        ret = scx_bpf_create_dsq(SHARED_DSQ, -1);

        return ret;
}

void ops_exit(struct scx_exit_info *ei)
{
        UEI_RECORD(uei, ei);
        bpf_printk("[*] isolcpus scheduler exits");
}

__attribute__((unused))
static s32 ops_init_task(struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_ctx *taskc;
	struct bpf_cpumask *cpumask;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc) {
		scx_bpf_error("[!] init_task: Failed to create task local storage");
		return -ENOMEM;
	}

        cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("[!] init_task: Failed to create bpf_cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&taskc->tmp_cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("[!] init_task: taskc->tmp_cpumask is not NULL");
		bpf_cpumask_release(cpumask);
	}

        taskc->isolated = task_is_isolated(p);

        return 0;
}

void ops_exit_task(struct task_struct *p, struct scx_exit_task_args *args)
{
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
        struct task_ctx *taskc;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] runnable: Failed to get task local storage");
		return;
	}

        if (taskc->isolated && p->pid != 0) {
                bpf_printk("%s[%d] (isolated) runnable");
        }
}

void ops_running(struct task_struct *p)
{
        struct task_ctx *taskc;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] running: Failed to get task local storage");
		return;
	}

        if (taskc->isolated && p->pid != 0) {
                bpf_printk("%s[%d] (isolated) running");
        }
}

void ops_stopping(struct task_struct *p, bool runnable)
{
        struct task_ctx *taskc;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] stopping: Failed to get task local storage");
		return;
	}

        if (taskc->isolated && p->pid != 0) {
                bpf_printk("%s[%d] (isolated) stopping");
        }
}

void ops_quiescent(struct task_struct *p, u64 deq_flags)
{
        struct task_ctx *taskc;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] quiescent: Failed to get task local storage");
		return;
	}

        if (taskc->isolated && p->pid != 0) {
                bpf_printk("%s[%d] (isolated) quiescent");
        }
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

void ops_set_cpumask(struct task_struct *p, const struct cpumask *cpumask)
{
        struct task_ctx *taskc;

        /* check the equation between p->cpus_ptr and cpumask */
        if (p->cpus_mask.bits[0] != cpumask->bits[0]) {
                scx_bpf_error("[!] set_cpumask: p->cpus_mask is not equal to cpumask");
                return;
        }

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] set_cpumask: Failed to get task local storage");
		return;
	}
        taskc->isolated = task_is_isolated(p);
}

void ops_set_weight(struct task_struct *p, u32 weight)
{
        struct task_ctx *taskc;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] set_weight: Failed to get task local storage");
		return;
	}
        taskc->isolated = task_is_isolated(p);
}
