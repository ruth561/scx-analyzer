// SPDX-License-Identifier: GPL-2.0
/*
 * Main implementation of the scheduler.
 */

#include "intf.h"
#include "vmlinux.h"
#include "sched.bpf.h"

#include <bpf/bpf_helpers.h>

#include "stat.bpf.h"


#define U64_MAX 0xFFFFFFFFFFFFFFFF

#define SHARED_DSQ 0
#define EDF_DSQ 1

/*
 * @nr_task_edf_dsq - The number of tasks in EDF_DSQ.
 *
 * This counter accounts for the following cases:
 *
 *	- Tasks queued in EDF_DSQ.
 *
 *	- Tasks that have been dispatched (by scx_bpf_dsq_insert) but are not yet
 *	  queued in EDF_DSQ due to delayed dispatch processing.
 *
 *	- Tasks that have been moved to the local DSQ (by scx_bpf_dsq_move_to_local), but
 *	  this counter has not been decremented yet.
 *
 * Therefore, this counter may be an overestimated value compared to the
 * actual number of tasks in EDF_DSQ.
 *
 * This variable prevents CPUs from going idle while there are runnable tasks,
 * so such overestimation is not a problem.
 */
u32 nr_task_edf_dsq = 0;
/*
 * @nr_isolated_cpus - The number of isolated CPUs.
 *
 * This variable is initialized in ops_init and remains immutable afterward.
 */
u32 nr_isolated_cpus;
/*
 * @nr_isolated_idle_cpus - The number of idle CPUs among the isolated CPUs..
 *
 * This variable is incremented and decremented in ops.update_idle.
 * It is used alongside the variable nr_task_edf_dsq. 
 * Dispatch processing and transitioning to idle can occur concurrently.
 *
 * If the task dispatching to the EDF_DSQ on one CPU and the transition to
 * the idle state on another CPU occur concurrently, there is a possibility
 * that a task remains in the EDF_DSQ while the CPU becomes idle.
 * Therefore, this variable is used to notify the dispatch side when a CPU
 * transitions to the idle state.
 */
u32 nr_isolated_idle_cpus;

UEI_DEFINE(uei);

#define MAX_NR_CPUS 512
s32 nr_cpus;
struct bpf_cpumask isolated_cpumask;
struct bpf_cpumask isolated_idle_cpumask;
struct bpf_cpumask housekeeping_cpumask;

// MARK: task_ctx
enum task_state {
	TASK_STATE_RUNNABLE,
	TASK_STATE_QUIESCENT,
	TASK_STATE_RUNNING,
	TASK_STATE_STOPPING,

	TASK_STATE_MIGRATING,
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
	int state;
        bool isolated;
        struct edf_entity edf;
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

static void init_task_state(struct task_ctx* taskc)
{
	taskc->state = TASK_STATE_QUIESCENT;
}

static void change_task_state(struct task_ctx* taskc, int new_state)
{
	taskc->state = new_state;
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

		/*
		 * If the CPU is about to become idle, then return it.
		 */
		if (bpf_cpumask_test_cpu(cpu, &isolated_idle_cpumask.cpumask))
			return cpu;
		
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

static inline bool should_preempt(struct task_struct *current) {
	s32 err;
	bool ret = false;
	struct task_struct *p;
        struct task_ctx *pc, *currentc;
	struct bpf_iter_scx_dsq it;

	if (!current)
		return false;

	/*
	 * Retrieve the task context of current.
	 */
	currentc = bpf_task_storage_get(&task_ctx, current, 0, 0);
	if (!currentc) {
		scx_bpf_error("should_preempt: Failed to get current task local storage. current=%s[%d]",
			current->comm, current->pid);
		return false;
	}

	/*
	 * If the current task is to go to sleep, then return true.
	 */
	if (currentc->state == TASK_STATE_QUIESCENT) {
		return true;
	}

	/*
	* Retrieve the task context of the task at the front of the EDF_DSQ.
	*/
	bpf_rcu_read_lock();
	err = bpf_iter_scx_dsq_new(&it, EDF_DSQ, 0);
	if (err) {
		scx_bpf_error("should_preempt: Failed to init a DSQ iterator.");
		goto out;
	}

	p = bpf_iter_scx_dsq_next(&it);
	if (!p) {
		/*
		 * Preemption should not be performed if there is no task in SHARED_DSQ.
		 */
		goto out;
	}

        pc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!pc) {
		scx_bpf_error("should_preempt: Failed to get task local storage");
		goto out;
	}
	
	/*
	 * Preemption should be performed if the deadline of a runnable task is closer
	 * than that of the current task. 
	 */
	if (pc->edf.deadline < currentc->edf.deadline) {
		ret = true;
	} else {
		ret = false;
	}

out:
	bpf_iter_scx_dsq_destroy(&it);
	bpf_rcu_read_unlock();
	return ret;
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

__hidden
s32 ops_init(void)
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

		stat_per_cpu_init(cpu);
        }

        bpf_printk("[*] isolated_cpumask: %lx", isolated_cpumask.cpumask.bits[0]);
        bpf_printk("[*] housekeeping_cpumask: %lx", housekeeping_cpumask.cpumask.bits[0]);

	/*
	 * Sets all isolated CPUs to the idle state.
	 */
	nr_isolated_cpus = bpf_cpumask_weight(&isolated_cpumask.cpumask);
	nr_isolated_idle_cpus = nr_isolated_cpus;
	bpf_cpumask_clear(&isolated_idle_cpumask);
	bpf_cpumask_copy(&isolated_idle_cpumask, &isolated_cpumask.cpumask);

	bpf_printk("[*] nr_isolated_cpus = %d", nr_isolated_cpus);
	bpf_printk("[*] isolated_cpumask = %016llx", isolated_cpumask.cpumask.bits[0]);
	bpf_printk("[*] nr_isolated_idle_cpus = %d", nr_isolated_idle_cpus);
	bpf_printk("[*] isolated_idle_cpumask = %016llx", isolated_idle_cpumask.cpumask.bits[0]);

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

__hidden
void ops_exit(struct scx_exit_info *ei)
{
        UEI_RECORD(uei, ei);
        bpf_printk("[*] isolcpus scheduler exits");
}

__hidden
s32 ops_init_task(struct task_struct *p, struct scx_init_task_args *args)
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

	init_task_state(taskc);

	init_edf_entity(p, taskc);

	stat_per_task_init(p);

        return 0;
}

__hidden
void ops_exit_task(struct task_struct *p, struct scx_exit_task_args *args)
{
	struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] exit_task: Failed to create task local storage");
		return;
	}
}

// MARK: enable/disable
__hidden
void ops_enable(struct task_struct *p)
{
}

__hidden
void ops_disable(struct task_struct *p)
{
}

// MARK: state transition
/*******************************************************************************
 * Callbacks for inspecting task state transitions
 */

__hidden
void ops_runnable(struct task_struct *p, u64 enq_flags)
{
        struct task_ctx *taskc;

	stat_at_runnable(p, enq_flags);

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

	change_task_state(taskc, TASK_STATE_RUNNABLE);
}

__hidden
void ops_running(struct task_struct *p)
{
	struct task_ctx *taskc;
        s32 cpu = bpf_get_smp_processor_id();

	stat_at_running(p);

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] ops_running: Failed to get task local storage");
		return;
	}

        if (bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask))
                update_cpu_ctx(p);

	change_task_state(taskc, TASK_STATE_RUNNING);
}

__hidden
void ops_stopping(struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;

	stat_at_stopping(p, runnable);
	
	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("[!] ops_stopping: Failed to get task local storage");
		return;
	}

	change_task_state(taskc, TASK_STATE_STOPPING);
}

__hidden
void ops_quiescent(struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *taskc;

	stat_at_quiescent(p, deq_flags);

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("ops_quiescent: Failed to get task local storage.");
		return;
	}

	if (taskc->isolated) {
		u64 now = bpf_ktime_get_boot_ns();
		if (taskc->edf.deadline < now) {
			bpf_printk("[!] DEADLINE VIOLATION! deadline=%lld, now=%lld",
				taskc->edf.deadline, now);
		}
	}

	if (deq_flags & SCX_DEQ_SLEEP) {
		change_task_state(taskc, TASK_STATE_QUIESCENT);
	} else {
		change_task_state(taskc, TASK_STATE_MIGRATING);
	}
}

// MARK: select_cpu
/*******************************************************************************
 * Callbacks for scheduling decisions
 */

__hidden
s32 ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
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
                        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
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
                        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
                        scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
                } else {
                        cpu = prev_cpu;
                }
        }

        return cpu;
}

__hidden
void ops_enqueue(struct task_struct *p, u64 enq_flags)
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
                        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
                        return;
                }

		/*
		 * The execution order is important. During the dispatching phase,
		 * nr_task_edf_dsq is incremented first, and then nr_isolated_idle_cpus is checked
		 * (in find_preemptible_cpu).
		 *
		 * See also ops_update_idle.
		 */
		__sync_fetch_and_add(&nr_task_edf_dsq, 1);

		barrier();

                scx_bpf_dsq_insert_vtime(p, EDF_DSQ, SCX_SLICE_INF, taskc->edf.deadline, enq_flags);
                /*
                 * If there is an CPU where a lower priority task is running, then kick it.
                 */
                cpu = find_preemptible_cpu(p, taskc);
                if (cpu >= 0) {
                        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
                }
        } else {
                scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
        }
}

__hidden
void ops_dispatch(s32 cpu, struct task_struct *prev)
{
	bool consumed;

        consume_user_ringbuf();
        
        if (bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask)) {
		/*
		 * If prev is swapper thread, then do consume.
		 */
		if (!prev || prev->pid == 0 || should_preempt(prev)) {
			consumed = scx_bpf_dsq_move_to_local(EDF_DSQ);
			if (consumed) {
				__sync_fetch_and_sub(&nr_task_edf_dsq, 1); 
			}
		}
        } else {
                scx_bpf_dsq_move_to_local(SHARED_DSQ);
        }
}

__hidden
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

__hidden
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

// MARK: tick/update_idle/..
__hidden
void ops_tick(struct task_struct *p)
{
	if (!p)
		return;

        if (should_preempt(p))
		p->scx.slice = 0;
}

__hidden
void ops_update_idle(s32 cpu, bool idle)
{
	stat_at_update_idle(cpu, idle);

	if (!bpf_cpumask_test_cpu(cpu, &isolated_cpumask.cpumask)) {
		return;
	}

	/*
	 * The execution order is important.
	 *
	 *	ops.update_idle		|	ops.enqueue
	 * -----------------------------+-----------------------------
	 *				|
	 *   Updates the CPU state	|  Increments nr_task_edf_dsq (A)
	 *				|
	 *	  barrier()		|	barrier()
	 *				|
	 *   Checks nr_task_edf_dsq	|  Checks the CPU state and kicks
	 *				|    an idle CPU if one exists.
	 *				|
	 *
	 * If nr_tasks_edf_dsq == 0, there are no runnable tasks in EDF_DSQ.
	 * For a task that is about to be dispatched to EDF_DSQ, nr_task_edf_dsq
	 * is still zero because (A) has not been executed yet. In this dispatch path,
	 * the CPU state is checked, and an idle CPU can be identified.
	 *
	 * See also ops_enqueue.
	 */
	if (idle) {
		__sync_fetch_and_add(&nr_isolated_idle_cpus, 1);
		bpf_cpumask_set_cpu(cpu, &isolated_idle_cpumask);
	} else {
		__sync_fetch_and_sub(&nr_isolated_idle_cpus, 1);
		bpf_cpumask_clear_cpu(cpu, &isolated_idle_cpumask);
	}

	if (nr_isolated_idle_cpus > nr_isolated_cpus) {
		scx_bpf_error("nr_isolated_idle_cpus (=%d) > nr_isolated_cpus (=%d)",
			nr_isolated_idle_cpus, nr_isolated_cpus);
		return;
	}

	barrier();

	if (idle) {
		/*
		 * If there might be a task in EDF_DSQ, immediately kick itself and invoke
		 * the scheduler.
		 */
		if (nr_task_edf_dsq > 0) {
			scx_bpf_kick_cpu(cpu, 0);
		}
	}
}
