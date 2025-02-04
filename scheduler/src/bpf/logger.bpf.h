// SPDX-License-Identifier: GPL-2.0
#ifndef __LOGGER_BPF_H
#define __LOGGER_BPF_H

#include <scx/common.bpf.h>


#define LOGGER_BUF_SIZE 0x1000000

void logger(void *data, u32 size);

#define LOGGER(data) logger(data, sizeof(*data))

#endif
