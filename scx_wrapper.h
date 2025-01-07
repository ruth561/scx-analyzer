/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2024 Takumi Jin */
#pragma once

#include "scheduler/src/bpf/intf.h"

void init_perfetto(void);
void start_perfetto_trace(const char *output_file);
void stop_perfetto_trace(void);

void trace_select_cpu(struct entry_header *hdr, struct select_cpu_aux *aux);
void trace_enqueue(struct entry_header *hdr, struct enqueue_aux *aux);
void trace_runnable(struct entry_header *hdr, struct runnable_aux *aux);
void trace_running(struct entry_header *hdr, struct running_aux *aux);
void trace_stopping(struct entry_header *hdr, struct stopping_aux *aux);
void trace_quiescent(struct entry_header *hdr, struct quiescent_aux *aux);
void trace_init_task(struct entry_header *hdr, struct init_task_aux *aux);
void trace_exit_task(struct entry_header *hdr, struct exit_task_aux *aux);
void trace_enable(struct entry_header *hdr, struct enable_aux *aux);
void trace_disable(struct entry_header *hdr, struct disable_aux *aux);
void trace_normal(struct entry_header *hdr, void *_aux);
