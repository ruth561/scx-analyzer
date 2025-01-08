#include "intf.h"
#include "vmlinux.h"
#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>

static bool should_record(s32 cbid);

//MARK: tp/sched_switch
struct tp_sched_switch_format {
        u64 dummy;
        char prev_comm[16];
        s32 prev_pid;
        s32 prev_prio;
        s64 prev_state;
        char next_comm[16];
        s32 next_pid;
        s32 next_prio;
};

SEC("tp/sched/sched_switch")
void tp_sched_switch(struct tp_sched_switch_format *ctx)
{
        s32 cpu = bpf_get_smp_processor_id();
	u64 now = bpf_ktime_get_boot_ns();

	const static u64 hdr_size = sizeof(struct entry_header);
	const static u64 buf_size = hdr_size + sizeof(struct tp_sched_switch_aux);

	__attribute__((aligned(8))) u8 buf[buf_size];
	struct entry_header *hdr = (struct entry_header *) buf;
	struct set_weight_aux *aux = (struct set_weight_aux *) &buf[hdr_size];

	if (!should_record(TP_SCHED_SWITCH))
		return;

	set_header(hdr, CBID_SET_WEIGHT, start, end);
	set_thread_info(&aux->th_info, p);
	aux->weight = weight;

	bpf_ringbuf_output(&cb_history_rb, &buf, buf_size, 0);
}
