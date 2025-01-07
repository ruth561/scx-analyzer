// SPDX-License-Identifier: GPL-2.0
/*
 * Main implementation of the scheduler.
 */

#include "intf.h"
#include "vmlinux.h"
#include <scx/common.bpf.h>

s32 ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
        bool is_idle;
        
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}
