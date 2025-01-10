// SPDX-License-Identifier: GPL-2.0
/*
 * Main implementation of the scheduler.
 */

#include "intf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <scx/common.bpf.h>

#define U64_MAX 0xFFFFFFFFFFFFFFFF

#define SHARED_DSQ 0
#define EDF_DSQ 1

UEI_DEFINE(uei);

#define MAX_NR_CPUS 512
s32 nr_cpus;
struct bpf_cpumask isolated_cpumask;
struct bpf_cpumask housekeeping_cpumask;

struct task_stats {
	u64 count;
	u64 sum_exectime;
	u64 avg_exectime;
};

struct edf_entity {
	u64 wake_up_time;
	u64 relative_deadline;
	u64 deadline;

	u64 exectime;
	u64 estimated_exectime;

	/*
	 * Internal use
	 */
	u64 prev_sum_exec_runtime;
};

struct task_ctx {
	struct bpf_cpumask __kptr *tmp_cpumask;
        bool isolated;
	bool stats_on;
        struct edf_entity edf;
        struct task_stats stats;
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
                // bpf_printk("[?] %s[%d] is housekeeped and isolated", p->comm, p->pid);
                return false;
        }

        if (isolated) {
                bpf_printk("[*] %s[%d] is isolated", p->comm, p->pid);
                return true;
        }

        if (housekeeped) {
                // bpf_printk("[*] %s[%d] is housekeeped", p->comm, p->pid);
                return false;
        }

        scx_bpf_error("[!] %s[%d] is neither housekeeped nor isolated", p->comm, p->pid);
        return false;
}

static void record_task_deadline(struct task_struct *p, u64 wake_up_time, u64 relative_deadline, u64 deadline);

/*
 * Sets deadline and wake_up_time when @p wakes up.
 */
static void set_edf_entity(struct task_struct *p, struct task_ctx* taskc)
{
	taskc->edf.wake_up_time = bpf_ktime_get_boot_ns();
	taskc->edf.prev_sum_exec_runtime = p->se.sum_exec_runtime;
	if (taskc->edf.relative_deadline < U64_MAX) {
		taskc->edf.deadline = taskc->edf.wake_up_time + taskc->edf.relative_deadline;
		record_task_deadline(p, taskc->edf.wake_up_time,
				     taskc->edf.relative_deadline, taskc->edf.deadline);
	} else {
		taskc->edf.deadline = U64_MAX;
	}
}

static void init_edf_entity(struct task_struct *p, struct task_ctx* taskc)
{
        /*
         * Init edf task info.
         */
        taskc->edf.wake_up_time = 0;
	taskc->edf.prev_sum_exec_runtime = p->se.sum_exec_runtime;
	taskc->edf.relative_deadline = U64_MAX;
	taskc->edf.deadline = U64_MAX;
	taskc->edf.exectime = U64_MAX;
	taskc->edf.estimated_exectime = U64_MAX;
}

static void init_task_stats(struct task_struct *p, struct task_ctx* taskc)
{
        /*
         * Init task stats
         */
	taskc->stats.count = 0;
	taskc->stats.sum_exectime = 0;
	taskc->stats.avg_exectime = 0;       
}

static void fini_task_stats(struct task_struct *p, struct task_ctx* taskc)
{
        /*
         * Called when taskc->stats_on is disabled.
         */  
}

// MARK: cpu_ctx
/*
 * Structure of per-cpu context
 */
struct cpu_ctx {
	s32 curr;
	u64 curr_deadline;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx SEC(".maps");

static struct cpu_ctx *get_cpu_ctx_id(s32 cpu)
{
	const s32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx, &idx, cpu);
}

static struct cpu_ctx *get_cpu_ctx()
{
	s32 cpu = bpf_get_smp_processor_id();
	return get_cpu_ctx_id(cpu);
}

/*
 * Updates the current CPU context
 */
void update_cpu_ctx(struct task_struct *p)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;

	cpuc = get_cpu_ctx();
	if (!cpuc) {
		scx_bpf_error("update_cpu_ctx: Failed to get per-cpu context.");
		return;
	}

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("update_cpu_ctx: Failed to create task local storage.");
		return;
	}

	cpuc->curr = p->pid;
	cpuc->curr_deadline = taskc->edf.deadline;
}

/*
 * すべてのCPUを走査していき、その中で最もデッドラインが先のCPUを探し出す
 * If preemptible, return the cpu id, else return -1.
 */
static s32 find_preemptible_cpu(struct task_struct *p, struct task_ctx *taskc)
{
	struct cpu_ctx *cpuc;
	s32 cpu, ret;
	u64 max_deadline = 0;

	bpf_for(cpu, 0, nr_cpus) {
		if (!bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask))
			continue;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("find_preemptible_cpu: Failed to find cpu context");
			return -1;
		}
		if (max_deadline < cpuc->curr_deadline) {
			max_deadline = cpuc->curr_deadline;
			ret = cpu;
		}
	}

	if (taskc->edf.deadline < max_deadline)
		return ret;
	else
	 	return -1;
}

static bool should_preempt(s32 cpu, struct task_struct *prev) {
	struct cpu_ctx *cpuc;
	struct bpf_iter_scx_dsq *it;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc) {
		scx_bpf_error("should_preempt: Failed to find cpu context");
		return -1;
	}

	/*
	 * TODO：EDF_DSQの先頭のタスクのdeadlineとcpuc->curr_deadlineを比べて判断する
	 */
	bpf_iter_scx_dsq_new(it, EDF_DSQ, 0);
}

// MARK: urb
/*******************************************************************************
 * Implementation for the user ring buffer
 */

struct msg_struct {
	s32 pid; /* tid */
	u64 relative_deadline;
	u64 exectime;
};

/*
 * Message queue from userspace to bpf side
 */
#define USER_RINGBUF_SIZE (4096 * 4096)
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, USER_RINGBUF_SIZE);
} urb SEC(".maps");

/*
 * Callback that is called from consume_user_ringbuf
 */
static long user_ringbuf_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	long err;
	struct msg_struct msg;
	struct task_struct *p;
	struct task_ctx *taskc;

	/*
	 * Copy a messege from dynptr to buf.
	 */
	err = bpf_dynptr_read(&msg, sizeof(msg), dynptr, 0, 0);
	if (err) {
		bpf_printk("Failed to read from dynptr...");
		return 1;
	}
	bpf_printk("Msg from URB: pid=%d, exectime=%ld, relative_deadline=%ld",
		msg.pid, msg.exectime, msg.relative_deadline);
	
	p = bpf_task_from_pid(msg.pid);
	if (!p) {
		bpf_printk("[W] user_ringbuf_callback: Failed to get task_struct from pid");
		return 0;
	}	

	taskc = bpf_task_storage_get(&task_ctx, p, NULL, 0);
	if (!taskc) {
		bpf_printk("[W] user_ringbuf_callback: Failed to get task storage");
		bpf_task_release(p);
		return 0;
	}

	// bpf_printk("[*] %s[%d] (before): exectime=%ld, relative_deadline=%ld, deadline=%ld",
        //         p->comm, p->pid, taskc->edf.exectime, taskc->edf.relative_deadline, taskc->edf.deadline);

	taskc->edf.exectime = msg.exectime;
	taskc->edf.relative_deadline = msg.relative_deadline;
	/*
	 * taskc->edf.deadline deadline is set when task wakes up.
	 */

        // bpf_printk("[*] %s[%d] (after): exectime=%ld, relative_deadline=%ld, deadline=%ld",
        //         p->comm, p->pid, taskc->edf.exectime, taskc->edf.relative_deadline, taskc->edf.deadline);

	bpf_task_release(p);
	return 0;
}

/*
 * Consume a message from urb_queue
 */
void consume_user_ringbuf()
{
	bpf_user_ringbuf_drain(&urb, user_ringbuf_callback, NULL, 0);
}

// MARK: init/exit
/*******************************************************************************
 * Callbacks for initialization and deinitialization
 */

__attribute__((unused))
static s32 ops_init()
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
        if (ret < 0) {
                scx_bpf_error("[!] Failed to creat SHARED_DSQ");
                return ret;
        }

        ret = scx_bpf_create_dsq(EDF_DSQ, -1);

        return ret;
}

__attribute__((unused))
static void ops_exit(struct scx_exit_info *ei)
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

	init_edf_entity(p, taskc);

	init_task_stats(p, taskc);

        return 0;
}

__attribute__((unused))
static void ops_exit_task(struct task_struct *p, struct scx_exit_task_args *args)
{
	struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] exit_task: Failed to create task local storage");
		return;
	}

        if (taskc->isolated) {
                bpf_printk("[*] exit_task: %s[%d] (isolated) stats.avg_exectime=%ld",
                        p->comm, p->pid, taskc->stats.avg_exectime);
        }

	fini_task_stats(p, taskc);
}

// MARK: enable/disable
__attribute__((unused))
static void ops_enable(struct task_struct *p)
{
}

__attribute__((unused))
static void ops_disable(struct task_struct *p)
{
}

// MARK: state transition
/*******************************************************************************
 * Callbacks for inspecting task state transitions
 */

__attribute__((unused))
static void ops_runnable(struct task_struct *p, u64 enq_flags)
{
        struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] ops_runnable: Failed to get task local storage");
		return;
	}

        consume_user_ringbuf();

	/*
	 * Records information at wakeup.
	 */
	set_edf_entity(p, taskc);
}

__attribute__((unused))
static void ops_running(struct task_struct *p)
{
        s32 cpu = bpf_get_smp_processor_id();

        if (bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask))
                update_cpu_ctx(p);
}

__attribute__((unused))
void ops_stopping(struct task_struct *p, bool runnable)
{
}

__attribute__((unused))
static void ops_quiescent(struct task_struct *p, u64 deq_flags)
{
        u64 sum_exec_runtime_delta;
	struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("ops_quiescent: Failed to get task local storage.");
		return;
	}

        /*
	 * Records task statistics
	 * sched_switch で測ったほうがいいのでは？
	 */
	sum_exec_runtime_delta = p->se.sum_exec_runtime - taskc->edf.prev_sum_exec_runtime;
	taskc->stats.count++;
	taskc->stats.sum_exectime += sum_exec_runtime_delta;
	taskc->stats.avg_exectime = taskc->stats.sum_exectime / taskc->stats.count;

	if (taskc->isolated) {
		u64 now = bpf_ktime_get_boot_ns();
		if (taskc->edf.deadline < now) {
			bpf_printk("[!] DEADLINE VIOLATION! deadline=%lld, now=%lld",
				taskc->edf.deadline, now);
		}
	}
}

// MARK: select_cpu
/*******************************************************************************
 * Callbacks for scheduling decisions
 */

__attribute__((unused))
static s32 ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
        s32 cpu;
        struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("ops_select_cpu: Failed to get task local storage.");
		return -1;
	}

        consume_user_ringbuf();

        if (taskc->isolated) {
                cpu = scx_bpf_pick_idle_cpu(&isolated_cpumask.cpumask, 0);
                if (cpu >= 0) {
			/*
			 * If there exists an idle CPU, then dispatch task to local DSQ of it.
			 */
                        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
                        scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
                } else {
			/*
			 * If there doesn't exist an idle CPU, delay the migration task.
			 */
                        cpu = prev_cpu;
                }
        } else {
                cpu = scx_bpf_pick_idle_cpu(&housekeeping_cpumask.cpumask, 0);
                if (cpu >= 0) {
                        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
                        scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
                } else {
                        cpu = prev_cpu;
                }
        }

        return cpu;
}

__attribute__((unused))
static void ops_enqueue(struct task_struct *p, u64 enq_flags)
{
        s32 cpu;
	struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] ops_enqueue: Failed to get task local storage");
		return;
	}

        if (taskc->isolated) {
                /*
                 * If @p is a kernel thread that is associated with only a single CPU,
                 * dispatchs to global DSQ.
                 */
                if (p->nr_cpus_allowed == 1 && (p->flags & PF_KTHREAD)) {
                        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
                        return;
                }

                scx_bpf_dispatch_vtime(p, EDF_DSQ, SCX_SLICE_INF, taskc->edf.deadline, enq_flags);
                /*
                 * If there is an CPU where a lower priority task is running, then kick it.
                 */
                cpu = find_preemptible_cpu(p, taskc);
                if (cpu >= 0) {
                        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
                }
        } else {
                scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
        }
}

__attribute__((unused))
static void ops_dispatch(s32 cpu, struct task_struct *prev)
{
        consume_user_ringbuf();
        
        if (bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask)) {
		if (should_preempt(cpu, prev))
	                scx_bpf_consume(EDF_DSQ);
        } else {
                scx_bpf_consume(SHARED_DSQ);
        }
}

__attribute__((unused))
static void ops_set_cpumask(struct task_struct *p, const struct cpumask *cpumask)
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

__attribute__((unused))
static void ops_set_weight(struct task_struct *p, u32 weight)
{
        struct task_ctx *taskc;

        taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] set_weight: Failed to get task local storage");
		return;
	}
        taskc->isolated = task_is_isolated(p);
}
