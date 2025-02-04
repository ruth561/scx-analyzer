use utils::bpf::task_storage::TaskStorage;
use inquire::Text;


#[repr(C)]
#[derive(Debug, Default)]
struct TaskStat {
	state: u32,
	timestamp: u64,
	runnable_time: u64,
	running_time: u64,
	stopping_time: u64,
	quiescent_time: u64,
	work_cnt: u64,
	exectime_acm: u64,
	exectime_sum: u64,
}

fn calc_percent(x: u64, total: u64) -> f32
{
	100.0 * x as f32 / total as f32
}

impl TaskStat {
	fn show(&self) {
		let total_elapsed_time = self.runnable_time + self.running_time + self.stopping_time + self.quiescent_time;
		
		println!("[*] TaskStat reports");
		println!("            state: {}", self.get_state_str());
		println!("    runnable time: {:>5.1}%", calc_percent(self.runnable_time, total_elapsed_time));
		println!("     running time: {:>5.1}%", calc_percent(self.running_time, total_elapsed_time));
		println!("    stopping time: {:>5.1}%", calc_percent(self.stopping_time, total_elapsed_time));
		println!("   quiescent time: {:>5.1}%", calc_percent(self.quiescent_time, total_elapsed_time));
		println!("     work counter: {}", self.work_cnt);
		println!("     exectime sum: {}us", self.exectime_sum / 1000);
		println!("     exectime avg: {}us", (self.exectime_sum / self.work_cnt) / 1000);
	}

	fn get_state_str(&self) -> &'static str {
		match self.state {
			0 => "runnable",
			1 => "running",
			2 => "stopping",
			3 => "quiescent",
			_ => "(none)"
		}
	}
}

#[repr(C)]
#[derive(Debug, Default)]
struct EdfEntity {
	wake_up_time: u64,
	relative_deadline: u64,
	deadline: u64,
	sched_hint: u64,
	prev_sum_exec_runtime: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct TaskCtx {
	tmp_cpumask: u64,
	state: i32,
	isolated: bool,
	edf: EdfEntity,
}

impl TaskCtx {
	fn show(&self) {
		println!("relative deadline: {}us", self.edf.relative_deadline / 1000);
		println!("         deadline: {}us", self.edf.deadline / 1000);
		println!("  scheduling hint: {}us", self.edf.sched_hint / 1000);
	}
}

fn main() {
	let task_stat = TaskStorage::new("task_stat").unwrap();
	let task_ctx = TaskStorage::new("task_ctx").unwrap();
	let mut stat = TaskStat::default();
	let mut ctx = TaskCtx::default();

	loop {
		let tid_s = Text::new("tid>").prompt().unwrap();

		let tid = match i32::from_str_radix(&tid_s, 10) {
			Ok(-1) => break,
			Ok(tid) => tid,
			Err(_) => {
				println!("Please enter an integer");
				continue;
			}
		};
		
		if task_stat.lookup_elem(tid, &mut stat).is_err() {
			println!("Failed to read from a BPF map 'task_stat'");
			continue;
		}

		if task_ctx.lookup_elem(tid, &mut ctx).is_err() {
			println!("Failed to read from a BPF map 'task_ctx'");
			continue;
		}

		println!("task_stat: {:?}", stat);
		println!("task_ctx: {:?}", ctx);
		stat.show();
		ctx.show();
	}
}
