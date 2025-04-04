// SPDX-License-Identifier: GPL-2.0
/*
 * Thread execution time estimator
 */

#include "exec_time_estimator.bpf.h"
#include "utils.bpf.h"

#include <bpf/bpf_helpers.h>


/*
 * The BPF map "est_ctx" is for a simple estimator.
 * It is not needed, when you implement your own estimator.
 */
struct est_ctx {
	u64 estimated_exec_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, s32);
	__type(value, struct est_ctx);
} est_ctx SEC(".maps");

/*
 * Called by sched.bpf.c.
 * This API returns the current estimated execution time.
 */
__hidden
s64 get_estimated_exec_time(struct task_struct *p)
{
	struct est_ctx *ctx;
	
	ctx = bpf_task_storage_get(&est_ctx, p, 0, 0);
	assert_ret_err(ctx, -1);

	return ctx->estimated_exec_time;
}

/*
 * Called by stat.bpf.c.
 * @exec_time is the duration from when the task became runnable
 * to when it became quiescent.
 * This does not include any time when the task was not running.
 */
__hidden
void record_exec_time_per_work(struct task_struct *p, s64 exec_time)
{
	struct est_ctx *ctx;
	
	ctx = bpf_task_storage_get(&est_ctx, p, 0, 0);
	assert_ret(ctx);

	if (ctx->estimated_exec_time < exec_time) {
		ctx->estimated_exec_time = exec_time;
	}
}

__hidden
void init_exec_time_estimator(struct task_struct *p)
{
	struct est_ctx *ctx;
	
	ctx = bpf_task_storage_get(&est_ctx, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	assert_ret(ctx);

	ctx->estimated_exec_time = 0; /* initialized by zero */
}
