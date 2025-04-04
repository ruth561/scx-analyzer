// SPDX-License-Identifier: GPL-2.0
#ifndef __EXEC_TIME_ESTIMATOR_BPF_H
#define __EXEC_TIME_ESTIMATOR_BPF_H

#include "vmlinux.h"


/*
 * APIs
 * You can implement your own execution time estimation algorithm
 * by modifying the bodies of these API functions.
 * These functions are called from stat.bpf.c or sched.bpf.c.
 * See their call sites for more details.
 */
void record_exec_time_per_work(struct task_struct *p, s64 exec_time);
void init_exec_time_estimator(struct task_struct *p);
s64 get_estimated_exec_time(struct task_struct *p);

#endif
