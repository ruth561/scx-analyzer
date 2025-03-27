// SPDX-License-Identifier: GPL-2.0
#ifndef __UTILS_BPF_H
#define __UTILS_BPF_H

#include <scx/common.bpf.h>


#define assert(cond)						\
	do {							\
		if (!(cond)) {					\
			scx_bpf_error("%s:%d assertion failed",	\
				__FILE__, __LINE__);		\
		}						\
	} while (0)

#define assert_ret(cond)					\
	do {							\
		if (!(cond)) {					\
			scx_bpf_error("%s:%d assertion failed",	\
				__FILE__, __LINE__);		\
			return;					\
		}						\
	} while (0)

#define assert_ret_err(cond, err)				\
	do {							\
		if (!(cond)) {					\
			scx_bpf_error("%s:%d assertion failed",	\
				__FILE__, __LINE__);		\
			return err;				\
		}						\
	} while (0)

#endif
