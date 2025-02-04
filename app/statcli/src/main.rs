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

#[repr(C)]
#[derive(Debug, Default)]
struct EdfEntity {
	wake_up_time: u64,
	relative_deadline: u64,
	deadline: u64,
	exectime: u64,
	estimated_exectime: u64,
	prev_sum_exec_runtime: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct TaskCtx {
	tmp_cpumask: u64,
	state: i32,
	isolated: bool,
	stats_on: bool,
	edf: EdfEntity,
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
	}
}
