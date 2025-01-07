/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2024 Takumi Jin */
#pragma once


enum scx_enq_flags {
	SCX_ENQ_WAKEUP		= 1ULL,
	SCX_ENQ_HEAD		= 1LLU << 4,
	SCX_ENQ_CPU_SELECTED	= 1LLU << 10,
	
	SCX_ENQ_PREEMPT		= 1LLU << 32,
	SCX_ENQ_REENQ		= 1LLU << 40,
	SCX_ENQ_LAST		= 1LLU << 41,
	__SCX_ENQ_INTERNAL_MASK	= 0xffLLU << 56,
	SCX_ENQ_CLEAR_OPSS	= 1LLU << 56,
	SCX_ENQ_DSQ_PRIQ	= 1LLU << 57,
};

enum scx_wake_flags {
	// WF_EXEC			= 0x02, /* not used in scx */
	WF_FORK			= 0x04,
	WF_TTWU			= 0x08,

	WF_SYNC			= 0x10,
	WF_MIGRATED		= 0x20,
	WF_CURRENT_CPU		= 0x40,
	WF_RQ_SELECTED		= 0x80,
};
