#include <algorithm>
#include <cstdint>
#include <perfetto.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>

#include <bpf/libbpf.h>

#include "ring_buffer.h"


PERFETTO_DEFINE_CATEGORIES(
	perfetto::Category("scx").SetDescription("Sched_ext callback events"),
);

PERFETTO_TRACK_EVENT_STATIC_STORAGE();

void init_perfetto(void);
void start_perfetto_trace(void);
void stop_perfetto_trace(void);

static std::unique_ptr<perfetto::TracingSession> tracing_session;
static int fd;
static const char *output_file = "output.perfetto-trace";

static volatile bool tracing_on = false;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int ring_buffer_handler(void *ctx, void *data, size_t size)
{
	if (!tracing_on)
		return 0;

	struct cb_history_entry *entry = (struct cb_history_entry *) data;
	const char *cbstr = get_string_from_cbid(entry->cbid);
	uint64_t start_ts = entry->start;
	uint64_t end_ts = entry->end;
	end_ts = std::min(end_ts, start_ts + 100);

	TRACE_EVENT("scx", perfetto::DynamicString{cbstr},
		start_ts,
		"CPU", entry->cpu);
	TRACE_EVENT_END("scx", end_ts);

	return 0;
}

int main(int argc, char** argv) {
	int err;
	struct ring_buffer *rb;

	rb = create_rb_subscriber("cb_history_rb", ring_buffer_handler);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer subscriber\n");
		return -1;
	}

	printf("Starting scx-analyzer\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	init_perfetto();

	printf("Collecting data, CTRL+c to stop\n");

	/*
	 * Consumes all data in rb before starting tracing.
	 */
	while (ring_buffer__consume(rb) > 0);

	start_perfetto_trace();

	tracing_on = true;

	while (!exiting) {
		err = ring_buffer__poll(rb, 100); /* 100ms */
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "Failed to poll ring buffer\n");
			break;
		}
	}

	stop_perfetto_trace();

	printf("\rCollected %s\n", output_file);

	return err;
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

void start_perfetto_trace(void)
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
	} else {
		printf("Successfully open output file! fd=%d\n", fd);
	}

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
