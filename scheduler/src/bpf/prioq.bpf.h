#ifndef __PRIOQ_BPF_H
#define __PRIOQ_BPF_H


#include <scx/common.bpf.h>


s32 prioq_push_elem(s32 pid, s64 prio);
s32 prioq_pop_elem(s32 *pid, s64 *prio);
s32 prioq_get_first(s32 *pid, s64 *prio);

#endif
