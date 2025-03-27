// SPDX-License-Identifier: GPL-2.0
/*
 * Main implementation of the scheduler.
 */

#include "intf.h"
#include "utils.bpf.h"
#include "vmlinux.h"
#include "dag_bpf_kfuncs.bpf.h"
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
enum task_state_ {
	TASK_STATE_RUNNABLE,
	TASK_STATE_QUIESCENT,
	TASK_STATE_RUNNING,
	TASK_STATE_STOPPING,

	TASK_STATE_MIGRATING,
};

struct dag_info {
	/*
	 * If this thread doesn't belong to any DAG tasks, this field is set to -1.
	 * Otherwise, set to the DAG task ID, which is the tid of src node in the DAG task.
	 */
	s32 dag_task_id;
	/*
	 * The number of node corresponding to this thread within the DAG task (dag_task_id).
	 * If @dag_task_id equals to -1, node_id also equals to -1.
	 */
	s32 node_id;
};

struct task_ctx {
	struct bpf_cpumask __kptr *tmp_cpumask;
	int state;
        bool isolated;
	bool is_dag_task;
        struct dag_info dag_info;
	/*
	 * This field stores the node priority calculated by bpf_dag_task_calc_XXXX_prio kfuncs.
	 * If not set, it contains -1.
	 */
	s32 prio;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, s32);
	__type(value, struct task_ctx);
} task_ctx SEC(".maps");

/* (isolated) */
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

/* (dag_info) */
static inline void set_dag_info(struct task_ctx *taskc, s32 dag_task_id, s32 node_id)
{
	taskc->dag_info.dag_task_id = dag_task_id;
	taskc->dag_info.node_id = node_id;
	taskc->is_dag_task = true;
}

static inline void init_dag_info(struct task_ctx *taskc)
{
	taskc->is_dag_task = false;
	taskc->dag_info.dag_task_id = -1;
	taskc->dag_info.node_id = -1;
}

/* (task_state) */
static void init_task_state(struct task_ctx* taskc)
{
	taskc->state = TASK_STATE_QUIESCENT;
}

static void change_task_state(struct task_ctx* taskc, int new_state)
{
	taskc->state = new_state;
}

// MARK: cpu_ctx
/*
 * Structure of per-cpu context
 */
struct cpu_ctx {
	s32 curr;
	u64 curr_prio;
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
	cpuc->curr_prio = taskc->prio;
}

/*
 * すべてのCPUを走査していき、その中で最もデッドラインが先のCPUを探し出す
 * If preemptible, return the cpu id, else return -1.
 */
static s32 find_preemptible_cpu(struct task_struct *p, struct task_ctx *taskc)
{
	struct cpu_ctx *cpuc;
	s32 ret, cpu;
	u64 max_prio = 0;

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
		if (max_prio < cpuc->curr_prio) {
			max_prio = cpuc->curr_prio;
			ret = cpu;
		}
	}

	if (taskc->prio < max_prio)
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
	if (pc->prio < currentc->prio) {
		ret = true;
	} else {
		ret = false;
	}

out:
	bpf_iter_scx_dsq_destroy(&it);
	bpf_rcu_read_unlock();
	return ret;
}

// MARK: dag_tasks
#define BPF_DAG_TASK_LIMIT 10

struct dag_tasks_map_value {
	struct bpf_dag_task __kptr *dag_task;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, BPF_DAG_TASK_LIMIT);
	__type(key, s32);
	__type(value, struct dag_tasks_map_value);
} dag_tasks SEC(".maps");

static void __dag_tasks_free(s32 dag_task_id)
{
	struct bpf_dag_task *dag_task;
	struct dag_tasks_map_value *v;

	v = bpf_map_lookup_elem(&dag_tasks, &dag_task_id);
	if (!v) {
		bpf_printk("[W:dag_tasks_free] There is no entry in dag_tasks with key=%d", dag_task_id);
		return;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL);

	if (dag_task) {
		bpf_printk("[I] Free a DAG task (dag_task_id=%d, dag_task_slot_id=%d)", dag_task_id, dag_task->id);
		bpf_dag_task_free(dag_task);
	}
}

static s32 __dag_tasks_get_weight(s32 dag_task_id, s32 node_id)
{
	s32 weight;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	v = bpf_map_lookup_elem(&dag_tasks, &dag_task_id);
	if (!v) {
		bpf_printk("[W:dag_tasks_get_weight] There is no entry in dag_tasks with key=%d", dag_task_id);
		return -1;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("[W:dag_tasks_get_weight] dag_tasks[%d]->dag_task is NULL", dag_task_id);
		return -1;
	}

	weight = bpf_dag_task_get_weight(dag_task, node_id);

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return weight;
}

static s32 __dag_tasks_set_weight(s32 dag_task_id, s32 node_id, s32 weight)
{
	s32 ret;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	v = bpf_map_lookup_elem(&dag_tasks, &dag_task_id);
	if (!v) {
		bpf_printk("[W:dag_tasks_set_weight] There is no entry in dag_tasks with key=%d", dag_task_id);
		return -1;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("[W:dag_tasks_set_weight] dag_tasks[%d]->dag_task is NULL", dag_task_id);
		return -1;
	}

	ret = bpf_dag_task_set_weight(dag_task, node_id, weight);

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return ret;
}

static s32 __dag_tasks_get_prio(s32 dag_task_id, s32 node_id)
{
	s32 prio;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	v = bpf_map_lookup_elem(&dag_tasks, &dag_task_id);
	if (!v) {
		bpf_printk("[W:dag_tasks_get_prio] There is no entry in dag_tasks with key=%d", dag_task_id);
		return -1;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("[W:dag_tasks_get_prio] dag_tasks[%d]->dag_task is NULL", dag_task_id);
		return -1;
	}

	prio = bpf_dag_task_get_prio(dag_task, node_id);

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return prio;
}

static void __dag_tasks_culc_HELT_prio(s32 dag_task_id)
{
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	v = bpf_map_lookup_elem(&dag_tasks, &dag_task_id);
	if (!v) {
		bpf_printk("[W:dag_tasks_culc_HELT_prio] There is no entry in dag_tasks with key=%d", dag_task_id);
		return;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("[W:dag_tasks_culc_HELT_prio] dag_tasks[%d]->dag_task is NULL", dag_task_id);
		return;
	}

	/* === body === */
	bpf_dag_task_culc_HELT_prio(dag_task);
	/* ============ */

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);
}

__attribute__((unused))
static s32 task_ctx_get_weight(struct task_ctx *taskc)
{
	s32 weight;

	if (taskc->is_dag_task) {
		s32 dag_task_id = taskc->dag_info.dag_task_id;
		s32 node_id = taskc->dag_info.node_id;

		weight = __dag_tasks_get_weight(dag_task_id, node_id);
		if (weight < 0) {
			__dag_tasks_free(dag_task_id);
			taskc->is_dag_task = false;
		}
		return weight;
	} else {
		return -1;
	}
}

__attribute__((unused))
static void task_ctx_set_weight(struct task_ctx *taskc, s32 weight)
{
	s32 err, dag_task_id, node_id;

	if (!taskc->is_dag_task)
		return;

	dag_task_id = taskc->dag_info.dag_task_id;
	node_id = taskc->dag_info.node_id;

	err = __dag_tasks_set_weight(dag_task_id, node_id, weight);
	if (err) {
		__dag_tasks_free(dag_task_id);
		taskc->is_dag_task = false;
	}
}

static void task_ctx_free_dag_task(struct task_ctx *taskc)
{
	if (taskc->is_dag_task) {
		__dag_tasks_free(taskc->dag_info.dag_task_id);
	}
}

// MARK: urb
/*******************************************************************************
 * Implementation for the user ring buffer
 */

/*
 * Message queue from userspace to bpf side
 */
#define USER_RINGBUF_SIZE (4096 * 4096)
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, USER_RINGBUF_SIZE);
} urb SEC(".maps");

static long handle_new_dag_task(struct bpf_dag_msg_new_task_payload *payload)
{
	s32 key;
	struct bpf_dag_task *dag_task, *old;
	long status;
	struct dag_tasks_map_value local, *v;
	struct task_struct *p;
	struct task_ctx *taskc;

	/*
	 * Checks if the thread exists. 
	 */
	p = bpf_task_from_pid(payload->src_node_tid);
	assert_ret_err(p, 1);

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		bpf_printk("Failed to get task local storage at handle_new_dag_task.");
		goto err_task_struct_release;
	}

	/*
	 * Allocates a DAG task.
	 */
	dag_task = bpf_dag_task_alloc(payload->src_node_tid, payload->src_node_weight);
	if (!dag_task) {
		bpf_printk("Failed to newly allocate a DAG task (src_node_tid=%d).", payload->src_node_tid);
		goto err_task_struct_release;
	}

	set_dag_info(taskc, payload->src_node_tid, 0);
	bpf_printk("[DAG] ALLOC a DAG-task! tid=%d, dag_task_id=%d, dag_task_slot_id=%d node_id=0",
		payload->src_node_tid, payload->src_node_tid, dag_task->id);

	/*
	 * Saves the bpf_dag_task ptr to the BPF map.
	 */
	key = payload->src_node_tid;
	local.dag_task = NULL;
	status = bpf_map_update_elem(&dag_tasks, &key, &local, 0);
	if (status) {
		bpf_printk("Failed to update dag_tasks's elem with NULL value");
		goto err_dag_task_release;
	}

	v = bpf_map_lookup_elem(&dag_tasks, &key);
	if (!v) {
		bpf_printk("Failed to lookup dag_tasks's elem");
		goto err_dag_task_release;
	}

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	bpf_task_release(p);
	return 0;

err_dag_task_release:
	bpf_dag_task_free(dag_task);
err_task_struct_release:
	bpf_task_release(p);
	return -1;
}

static inline long handle_add_node(struct bpf_dag_msg_add_node_payload *payload)
{
	s32 key, node_id, ret = 0;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;
	struct task_struct *p;
	struct task_ctx *taskc;

	/*
	 * Checks if the thread exists. 
	 */
	p = bpf_task_from_pid(payload->tid);
	assert_ret_err(p, 1);

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		bpf_printk("Failed to get task local storage at handle_new_dag_task.");
		ret = -1;
		goto task_struct_release;
	}

	/*
	 * Looks up the DAG task specified by payload->dag_task_id.
	 */
	key = payload->dag_task_id;
	v = bpf_map_lookup_elem(&dag_tasks, &key);
	if (!v) {
		bpf_printk("There is no entry in dag_tasks with key=%d", key);
		ret = -1;
		goto task_struct_release;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("dag_tasks[%d]->dag_task is NULL", key);
		ret = -1;
		goto task_struct_release;
	}

	node_id = bpf_dag_task_add_node(dag_task, payload->tid, payload->weight);

	bpf_dag_task_dump(dag_task);

	if (node_id >= 0) {
		set_dag_info(taskc, payload->dag_task_id, node_id);
		bpf_printk("[DAG] ADD a node (tid=%d, node_id=%d) to a DAG-task (id=%d)",
			payload->tid, node_id, dag_task->id);
	} else {
		bpf_printk("Failed to add a node (tid=%d) to a DAG-task (id=%d)",
			payload->tid, dag_task->id);
	}

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

task_struct_release:
	bpf_task_release(p);
	return ret;
}

static inline long handle_add_edge(struct bpf_dag_msg_add_edge_payload *payload)
{
	s32 key, edge_id;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	key = payload->dag_task_id;
	v = bpf_map_lookup_elem(&dag_tasks, &key);
	if (!v) {
		bpf_printk("There is no entry in dag_tasks with key=%d", key);
		return -1;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("dag_tasks[%d]->dag_task is NULL", key);
		return -1;
	}

	edge_id = bpf_dag_task_add_edge(dag_task, payload->from_tid, payload->to_tid);

	bpf_dag_task_dump(dag_task);

	if (edge_id >= 0) {
		bpf_printk("[DAG] ADD a edge (%d -> %d, edge_id=%d) to a DAG-task (id=%d)",
			payload->from_tid, payload->to_tid, edge_id, dag_task->id);
	} else {
		bpf_printk("Failed to add a edge (%d -> %d) to a DAG-task (id=%d)",
			payload->from_tid, payload->to_tid, dag_task->id);
	}

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return 0;
}

static long user_ringbuf_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	long err;
	enum bpf_dag_msg_type type;

	err = bpf_dynptr_read(&type, sizeof(type), dynptr, 0, 0);
	if (err) {
		bpf_printk("Failed to drain message type.");
		return 1; // stop continuing
	}

	if (type == BPF_DAG_MSG_NEW_TASK) {
		struct bpf_dag_msg_new_task_payload payload;

		err = bpf_dynptr_read(&payload, sizeof(payload), dynptr, sizeof(type), 0);
		if (err) {
			bpf_printk("Failed to drain message new task type.");
			return 1; // stop continuing
		}
		
		err = handle_new_dag_task(&payload);
		if (err) {
			bpf_printk("Failed to handle a new dag task message");
			return 1;
		}

	} else if (type == BPF_DAG_MSG_ADD_NODE) {
		struct bpf_dag_msg_add_node_payload payload;

		err = bpf_dynptr_read(&payload, sizeof(payload), dynptr, sizeof(type), 0);
		if (err) {
			bpf_printk("Failed to drain message add node.");
			return 1; // stop continuing
		}
		
		err = handle_add_node(&payload);
		if (err) {
			bpf_printk("Failed to handle add_node message");
			return 1;
		}

	} else if (type == BPF_DAG_MSG_ADD_EDGE) {
		struct bpf_dag_msg_add_edge_payload payload;

		err = bpf_dynptr_read(&payload, sizeof(payload), dynptr, sizeof(type), 0);
		if (err) {
			bpf_printk("Failed to drain message add edge.");
			return 1; // stop continuing
		}
		
		err = handle_add_edge(&payload);
		if (err) {
			bpf_printk("Failed to handle add_edge message");
			return 1;
		}

	} else {
		bpf_printk("[ WARN ] Unknown message type: BPF_DAG_MSG_?=%d", type);
	}

	return 0;
}

/*
 * Consume a message from urb_queue
 */
void consume_user_ringbuf()
{
	// User ringbuf messages are only consumed by CPU0.
	s32 cpu = bpf_get_smp_processor_id();
	if (cpu == 0) {
		bpf_user_ringbuf_drain(&urb, user_ringbuf_callback, NULL, 0);
	}
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

	init_dag_info(taskc);

	taskc->prio = -1;

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

	if (taskc->is_dag_task)
		task_ctx_free_dag_task(taskc);
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
	struct task_stat *stat;

	taskc = bpf_task_storage_get(&task_ctx, p, 0, 0);
	if (!taskc) {
		scx_bpf_error("ops_quiescent: Failed to get task local storage.");
		return;
	}

	stat_at_quiescent(p, deq_flags);

	stat = get_task_stat_or_ret(p);

	// TODO:
	// if (taskc->isolated) {
	// 	u64 now = bpf_ktime_get_boot_ns();
	// 	if (taskc->edf.deadline < now) {
	// 		bpf_printk("[!] DEADLINE VIOLATION! deadline=%lld, now=%lld",
	// 			taskc->edf.deadline, now);
	// 	}
	// }

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

	if (taskc->is_dag_task) {
		s32 dag_task_id = taskc->dag_info.dag_task_id;
		s32 node_id = taskc->dag_info.node_id;

		if (node_id == 0) { // src node
			__dag_tasks_culc_HELT_prio(dag_task_id);
		}

		/*
		 * In HELT, the rank is calculated and stored in `prio`.
		 * A higher rank in HELT indicates a higher priority.
		 * On the other hand, in sched_ext's DSQ, tasks with smaller `vtime`
		 * are given higher priority.
		 * Therefore, by using `S32_MAX - prio` as the `vtime` value,
		 * the priority is properly mapped and handled.
		 */
		taskc->prio = 0x7fffffff - __dag_tasks_get_prio(dag_task_id, node_id);
	}

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

                scx_bpf_dsq_insert_vtime(p, EDF_DSQ, SCX_SLICE_INF, taskc->prio, enq_flags);

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
