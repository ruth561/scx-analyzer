use utils::bpf::task_storage::TaskStorage;


#[repr(C)]
#[derive(Debug)]
struct TaskStat {
	state: u32,
	timestamp: u64,
	runnable_time: u64,
	running_time: u64,
	stopping_time: u64,
	quiescent_time: u64,
}

impl TaskStat {
	fn new() -> TaskStat {
		TaskStat {
			state: 0,
			timestamp: 0,
			runnable_time: 0,
			running_time: 0,
			stopping_time: 0,
			quiescent_time: 0,
		}
	}
}

fn main() {
	let task_storage = TaskStorage::new("task_stat").unwrap();
	let mut stat = TaskStat::new();
	let tid = 774752;

	task_storage.lookup_elem(tid, &mut stat).unwrap();
	println!("{:?}", stat);
}
