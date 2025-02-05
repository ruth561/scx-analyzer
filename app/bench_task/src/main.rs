pub mod bench;

use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::time::Duration;

use std::str::FromStr;

use std::sync::mpsc;

use rand::seq::IndexedRandom;
use utils::bpf::urb::UserRingBuffer;

use clap::Parser;
use clap::Subcommand;

#[derive(Debug, Clone, Copy)]
enum BenchType {
	IntBusy,
	FloatBusy,
	CacheBusy,
}

impl FromStr for BenchType {
	type Err = String;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"int" => Ok(Self::IntBusy),
			"float" => Ok(Self::FloatBusy),
			"cache" => Ok(Self::CacheBusy),
			_ => Err(format!("Invalid policy string '{}'", s)),
		}
	}
}

#[derive(Debug, Clone, Subcommand)]
enum Bench {
	/// Run a benchmark task. Specify one of the following benchmark types:
	///   - int:    Integer intensive task
	///   - float:  Floating-point intensive task
	///   - cache:  Cache intensive task
	/// Example usage:
	///   $ bench_task single int
	#[clap(verbatim_doc_comment)]
	Single {
		bench: BenchType,
	},

	/// Run two benchmark tasks in parallel on a single physical core.
	/// Example usage:
	///   $ bench_task dual int float
	#[clap(verbatim_doc_comment)]
	Dual {
		bench1: BenchType,
		bench2: BenchType,
	},
}

#[derive(Debug, Parser)]
struct Cli {
	#[clap(verbatim_doc_comment)]
	#[command(subcommand)]
	bench: Bench,
}

const USER_RING_BUFFER_NAME: &'static str = "urb";

#[repr(C)]
struct UrbMsgStruct {
	tid: i32,
	relative_deadline: u64,
	exectime: u64,
}

fn get_tid() -> i32
{
	unsafe { libc::gettid() }
}

struct ChanMsg {
	bench_type: BenchType,
	weight: u64,
}

/*
 * @rtid: Receiver thread id 
 */
fn waker_thread_main(txes: Vec<Sender<ChanMsg>>, tids: Vec<i32>, cli: &Cli)
{
	let mut urb = UserRingBuffer::new(USER_RING_BUFFER_NAME).unwrap();

	/*
	* Set this thread's priority high.
	*/
	urb.send(UrbMsgStruct {
		tid: get_tid(),
		relative_deadline: Duration::from_millis(3).as_nanos() as u64,
		exectime: Duration::from_millis(3).as_nanos() as u64,
	}).unwrap();

	let (bench1, bench2_opt) = match cli.bench {
		Bench::Single { bench } => (bench, None),
		Bench::Dual { bench1, bench2 } => (bench1, Some(bench2)),
	};

	println!("bench1: {:?}", bench1);
	println!("bench2: {:?}", bench2_opt);

	let mut rng = rand::rng();
	let nums: Vec<u64> = (1..200).collect();
	loop {
		std::thread::sleep(Duration::from_millis(200));

		let weight = *nums.choose(&mut rng).unwrap();

		urb.send(UrbMsgStruct {
			tid: tids[0],
			relative_deadline: Duration::from_secs(1).as_nanos() as u64,
			exectime: Duration::from_millis(weight).as_nanos() as u64,
		}).unwrap();
		txes[0].send(ChanMsg { bench_type: bench1, weight }).unwrap();

		if let Some(bench2) = bench2_opt {
			urb.send(UrbMsgStruct {
				tid: tids[1],
				relative_deadline: Duration::from_secs(1).as_nanos() as u64,
				exectime: Duration::from_millis(weight).as_nanos() as u64,
			}).unwrap();
			txes[1].send(ChanMsg { bench_type: bench2, weight }).unwrap();
		}
	}
}

fn worker_thread_main(rx: Receiver<ChanMsg>)
{
	loop {
		let msg = rx.recv().unwrap();

		match msg.bench_type {
			BenchType::IntBusy => bench::int::busy(msg.weight),
			BenchType::FloatBusy => {
				bench::float::busy(msg.weight);
			},
			BenchType::CacheBusy => {
				bench::cache::busy(msg.weight);
			},
			_ => println!("ERROR: Invalid bench type"),
		}
	}
}

fn main() {
	let cli = Cli::parse();

	// worker thread 1
	let (tx1, rx1) = mpsc::channel::<ChanMsg>();
	let (tx_for_tid, rx_for_tid) = mpsc::channel();
	let w1 = std::thread::spawn(move || {
		tx_for_tid.send(get_tid()).unwrap();
		worker_thread_main(rx1);
	});
	let w1_tid = rx_for_tid.recv().unwrap();

	// worker thread 2
	let (tx2, rx2) = mpsc::channel();
	let (tx_for_tid, rx_for_tid) = mpsc::channel();
	let w2 = std::thread::spawn(move || {
		tx_for_tid.send(get_tid()).unwrap();
		worker_thread_main(rx2);
	});
	let w2_tid = rx_for_tid.recv().unwrap();

	let txes = vec![tx1, tx2];
	let tids = vec![w1_tid, w2_tid];
	let (tx_for_tid, rx_for_tid) = mpsc::channel();
	let st = std::thread::spawn(move || {
		tx_for_tid.send(get_tid()).unwrap();
		waker_thread_main(txes, tids, &cli);
	});
	let stid = rx_for_tid.recv().unwrap();

	println!("current thread's tid: {}", get_tid());
	println!("worker thread 1's tid: {}", w1_tid);
	println!("worker thread 2's tid: {}", w2_tid);
	println!("waker thread's tid: {}", stid);

	st.join().unwrap();
	w1.join().unwrap();
	w2.join().unwrap();
}
