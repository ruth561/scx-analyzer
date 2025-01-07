#include <cstdint>
#include <cstdio>
#include <ios>
#include <perfetto.h>
#include <fcntl.h>

#include "utils.h"
#include "scx_wrapper.h"
#include "scx_defs.h"
#include "scheduler/src/bpf/intf.h"

PERFETTO_DEFINE_CATEGORIES(
	perfetto::Category("scx").SetDescription("Sched_ext callback events"),
);

PERFETTO_TRACK_EVENT_STATIC_STORAGE();

static std::unique_ptr<perfetto::TracingSession> tracing_session;
static int fd;

/*
 * UUID of the track that contains scx events.
 * If you want to know about "Track" more, see the comment on perfetto::Track.
 */
#define SCX_TRACK_UUID	0xdeadbeefcafebabe
#define SCX_TRACK_UUID_CPU(cpu) (SCX_TRACK_UUID + cpu)

perfetto::Track get_track(s32 cpu)
{
	return perfetto::Track::Global(SCX_TRACK_UUID_CPU(cpu));
}

void set_all_track_names()
{
	char track_name[0x20];
	int nr_cpus = get_nr_cpus_system(false);

	if (nr_cpus < 0) {
		fprintf(stderr, "Failed to get the number of CPUs in the system.\n");
		return;
	}

	printf("nr_cpus: %d\n", nr_cpus);

	for (int cpu = 0; cpu < nr_cpus; cpu++) {
		auto track = get_track(cpu);
		auto desc = track.Serialize();

		snprintf(track_name, 0x20, "SCX Track for CPU %2d", cpu);
		desc.set_name(track_name);
		perfetto::TrackEvent::SetTrackDescriptor(track, desc);
	}
}

void init_perfetto(void)
{
	perfetto::TracingInitArgs args;

	args.backends |= perfetto::kInProcessBackend;
	args.backends |= perfetto::kSystemBackend;
	args.shmem_size_hint_kb = 1024*100; // 100 MiB
	perfetto::Tracing::Initialize(args);
	perfetto::TrackEvent::Register();
}

void start_perfetto_trace(const char *output_file)
{
	char buffer[256];

	perfetto::TraceConfig cfg;
	perfetto::TraceConfig::BufferConfig* buf;
	buf = cfg.add_buffers();
	buf->set_size_kb(1024*100);  // Record up to 100 MiB.
	buf->set_fill_policy(perfetto::TraceConfig::BufferConfig::RING_BUFFER);
	buf = cfg.add_buffers();
	buf->set_size_kb(1024*100);  // Record up to 100 MiB.
	buf->set_fill_policy(perfetto::TraceConfig::BufferConfig::RING_BUFFER);
	cfg.set_duration_ms(3600000);
	cfg.set_max_file_size_bytes(250 * 1024 * 1024);
	cfg.set_unique_session_name("example");
	cfg.set_write_into_file(true);
	cfg.set_file_write_period_ms(1000);
	cfg.set_flush_period_ms(30000);
	cfg.set_enable_extra_guardrails(false);
	cfg.set_notify_traceur(true);
	cfg.mutable_incremental_state_config()->set_clear_period_ms(15000);

	/* Track Events Data Source */
	perfetto::protos::gen::TrackEventConfig track_event_cfg;
	track_event_cfg.add_enabled_categories("example");

	auto *te_ds_cfg = cfg.add_data_sources()->mutable_config();
	te_ds_cfg->set_name("track_event");
	te_ds_cfg->set_track_event_config_raw(track_event_cfg.SerializeAsString());

	/* Android frametimeline */
	auto *frametl_ds_cfg = cfg.add_data_sources()->mutable_config();
	frametl_ds_cfg->set_name("android.surfaceflinger.frametimeline");

	/* Ftrace Data Source */
	perfetto::protos::gen::FtraceConfig ftrace_cfg;
	ftrace_cfg.add_ftrace_events("sched/sched_switch");
	ftrace_cfg.add_ftrace_events("sched/sched_wakeup_new");
	ftrace_cfg.add_ftrace_events("sched/sched_waking");
	ftrace_cfg.add_ftrace_events("sched/sched_process_exit");
	ftrace_cfg.add_ftrace_events("sched/sched_process_free");
	ftrace_cfg.add_ftrace_events("power/suspend_resume");
	ftrace_cfg.add_ftrace_events("power/cpu_frequency");
	ftrace_cfg.add_ftrace_events("power/cpu_idle");
	ftrace_cfg.add_ftrace_events("task/task_newtask");
	ftrace_cfg.add_ftrace_events("task/task_rename");
	ftrace_cfg.add_ftrace_events("ftrace/print");
	
	ftrace_cfg.set_drain_period_ms(1000);

	auto *ft_ds_cfg = cfg.add_data_sources()->mutable_config();
	ft_ds_cfg->set_name("linux.ftrace");
	ft_ds_cfg->set_ftrace_config_raw(ftrace_cfg.SerializeAsString());

	/* Process Stats Data Source */
	perfetto::protos::gen::ProcessStatsConfig ps_cfg;
	ps_cfg.set_proc_stats_poll_ms(10000);
	ps_cfg.set_record_thread_names(true);

	auto *ps_ds_cfg = cfg.add_data_sources()->mutable_config();
	ps_ds_cfg->set_name("linux.process_stats");
	ps_ds_cfg->set_process_stats_config_raw(ps_cfg.SerializeAsString());

	fd = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		snprintf(buffer, 256, "Failed to create %s", output_file);
		perror(buffer);
		return;
	}

	set_all_track_names();

	tracing_session = perfetto::Tracing::NewTrace();
	tracing_session->Setup(cfg, fd);
	tracing_session->StartBlocking();
}

void stop_perfetto_trace(void)
{
	if (fd < 0)
		return;

	tracing_session->StopBlocking();
	close(fd);
}

std::string get_thread_name(struct th_info *th_info)
{
	std::string ret = th_info->comm;
	ret += "[";
	ret += std::to_string(th_info->pid);
	ret += "]";
	return ret;
}

void push_flag_str(std::string &s, const char *flag_str, bool is_last)
{
	s += flag_str;
	if (!is_last) {
		s += " | ";
	}
}

/*
 * Converts enq_flags to std::string.
 *
 * ex) 0x409 ==> 1033 (WAKEUP | CPU_SELECTED | UNKNOWN=8)
 */
static std::string get_scx_enq_flags_str(u64 enq_flags)
{
	std::string ret = std::to_string(enq_flags);
	ret += " ";

	if (enq_flags == 0) {
		ret += "(NONE)";
		return ret;
	}

	ret += "(";

	if (enq_flags & SCX_ENQ_WAKEUP) {
		enq_flags &= ~SCX_ENQ_WAKEUP;
		push_flag_str(ret, "SCX_ENQ_WAKEUP", enq_flags == 0);
	}

	if (enq_flags & SCX_ENQ_HEAD) {
		enq_flags &= ~SCX_ENQ_HEAD;
		push_flag_str(ret, "SCX_ENQ_HEAD", enq_flags == 0);
	}

	if (enq_flags & SCX_ENQ_CPU_SELECTED) {
		enq_flags &= ~SCX_ENQ_CPU_SELECTED;
		push_flag_str(ret, "SCX_ENQ_CPU_SELECTED", enq_flags == 0);
	}

	if (enq_flags & SCX_ENQ_PREEMPT) {
		enq_flags &= ~SCX_ENQ_PREEMPT;
		push_flag_str(ret, "SCX_ENQ_PREEMPT", enq_flags == 0);
	}

	if (enq_flags & SCX_ENQ_REENQ) {
		enq_flags &= ~SCX_ENQ_REENQ;
		push_flag_str(ret, "SCX_ENQ_REENQ", enq_flags == 0);
	}

	if (enq_flags & SCX_ENQ_LAST) {
		enq_flags &= ~SCX_ENQ_LAST;
		push_flag_str(ret, "SCX_ENQ_LAST", enq_flags == 0);
	}

	if (enq_flags) {
		char flag_str[0x20];
		snprintf(flag_str, 0x20, "UNKNOWN=%llx", enq_flags);
		push_flag_str(ret, flag_str, true);
	}

	ret += ")";
	return ret;
}

void trace_select_cpu(struct entry_header *hdr, struct select_cpu_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "select_cpu",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "prev_cpu", aux->prev_cpu,
		    "wake_flags", aux->wake_flags,
		    "selected_cpu", aux->selected_cpu);
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_enqueue(struct entry_header *hdr, struct enqueue_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "enqueue",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "enq_flags", get_scx_enq_flags_str(aux->enq_flags));
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_runnable(struct entry_header *hdr, struct runnable_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "runnable",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "enq_flags", get_scx_enq_flags_str(aux->enq_flags));
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_running(struct entry_header *hdr, struct running_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "running",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		"thread", get_thread_name(&aux->th_info));
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_stopping(struct entry_header *hdr, struct stopping_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "stopping",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "runnable", aux->runnable ? "true" : "false");
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_quiescent(struct entry_header *hdr, struct quiescent_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "quiescent",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "deq_flags", aux->deq_flags);
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_init_task(struct entry_header *hdr, struct init_task_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "init_task",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "fork", aux->fork);
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_exit_task(struct entry_header *hdr, struct exit_task_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "exit_task",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info),
		    "cancelled", aux->cancelled);
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_enable(struct entry_header *hdr, struct enable_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "enable",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info));
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_disable(struct entry_header *hdr, struct disable_aux *aux)
{
	auto track = get_track(hdr->cpu);

	TRACE_EVENT("scx", "disable",
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu,
		    "thread", get_thread_name(&aux->th_info));
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}

void trace_normal(struct entry_header *hdr, void *_aux)
{
	auto track = get_track(hdr->cpu);
	const char *cbstr = get_string_from_cbid(hdr->cbid);

	TRACE_EVENT("scx", perfetto::DynamicString{cbstr},
		    track,
		    (uint64_t) hdr->start,
		    "CPU", hdr->cpu);
	TRACE_EVENT_END("scx", track, (uint64_t) hdr->end);
}
