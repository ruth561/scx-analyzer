use std::collections::VecDeque;

use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

use std::time::Duration;

mod dag;

/*
 * Performs a busy-wait loop for the given weight.
 */
fn busy(weight: usize)
{
	for i in 0..weight {
		std::hint::black_box(i);
	}
}

/*
 * Wrapper function for the gettid system call.
 */
fn get_tid() -> i32
{
	unsafe { libc::gettid() }
}

/*
 * Work unit size.
 */
const BUSY_UNIT: usize = 50000;

/*
 * Function executed by each worker thread.
 * 
 * @i: The thread index.
 * @w: The workload weight.
 * @rxes: A vector of receiving channels.
 * @txes: A vector of sending channels.
 * @c2t_rx: Receiver channel from the controller thread.
 * @t2c_tx: Sender channel to the controller thread.
 */
fn thread_fn(i: usize, w: usize, rxes: Vec<Receiver<u32>>, txes: Vec<Sender<u32>>, c2t_rx: Receiver<i32>, t2c_tx: Sender<i32>)
{
	let tid = get_tid();
	t2c_tx.send(tid).unwrap();
	println!("[ worker ] Task {i} spawned. (tid={tid}, w={w}, rxes.len()={}, txes.len()={}).", rxes.len(), txes.len());

	/*
	 * Wait until the initialization of controller thread is complete.
	 */
	while c2t_rx.recv().unwrap() != 1 {}

	println!("[ worker ] Task {i} starts!");

	loop {
		/*
		 * If the thread does not have a receiver channel, it is an initial task.
		 * Otherwise, the thread depends on senders of rxes.
		 */
		if rxes.is_empty() {
			/*
			 * Initial task: produces new task periodically.
			 */
			std::thread::sleep(Duration::from_secs(1));
		} else {
			/*
			 * Dependent task: waits for all inputs.
			 */
			for rx in &rxes {
				rx.recv().unwrap();
			}
		}

		println!("[ worker ] Task {i}[{tid}] starts work.");
		
		/*
		 * Perform the work.
		 */
		busy(w * BUSY_UNIT);

		/*
		 * Notify dependent tasks.
		 */
		for tx in &txes {
			tx.send(0).unwrap();
		}
	}
}

fn main() {

	let n = 9;
	let weights = vec![10, 100, 20, 30, 30, 60, 200, 100, 50];
	let edges = vec![
		(0, 1, 10), (0, 2, 10),
		(1, 3, 10), (1, 4, 10), (1, 5, 10),
		(2, 6, 10),
		(3, 7, 10),
		(4, 7, 10),
		(5, 6, 10),
		(6, 7, 10),
		(7, 8, 10),
	];

	let mut g = vec![vec![]; n];
	for (u, v, w) in &edges {
		g[*u].push((*v, *w));
	}
	
	let mut task_txes = VecDeque::new();
	let mut task_rxes = VecDeque::new();
	for _ in 0..n {
		task_txes.push_back(vec![]);
		task_rxes.push_back(vec![]);
	}
	for &(u, v, _) in &edges {
		let (tx, rx) = mpsc::channel::<u32>();
		task_txes[u].push(tx);
		task_rxes[v].push(rx);
	}

	/*
	 * Spawn worker threads and set up communication channels.
	 *
	 * @c2t_txes[i]: A channel for sending data from the controller (= main thread)
	 *		 to the i-th thread.
	 * @t2c_rxes[i]: A channel for receiving data from the i-th thread to the controller.
	 */
	let mut tasks = vec![];
	let mut c2t_txes = vec![];
	let mut t2c_rxes = vec![];
	for i in 0..n {
		let txes = task_txes.pop_front().unwrap();
		let rxes = task_rxes.pop_front().unwrap();
		let w = weights[i];
		let (c2t_tx, c2t_rx) = mpsc::channel();
		let (t2c_tx, t2c_rx) = mpsc::channel();
		tasks.push(std::thread::spawn(move || {
			thread_fn(i, w, rxes, txes, c2t_rx, t2c_tx);
		}));
		c2t_txes.push(c2t_tx);
		t2c_rxes.push(t2c_rx);
	}

	/*
	 * Collect thread IDs.
	 */
	let mut tids = vec![];
	for i in 0..n {
		let tid = t2c_rxes[i].recv().unwrap();
		println!("{}-th thread's tid is {}", i, tid);
		tids.push(tid);
	}

	send_workload_info_to_scheduler(n, &edges, &weights);

	/*
	 * Notify all threads that initialization is completion. 
	 */
	for i in 0..n {
		c2t_txes[i].send(1).unwrap();
	}

	/*
	 * Join all threads.
	 */
	for _ in 0..n {
		tasks
			.pop()
			.unwrap()
			.join()
			.unwrap();
	}
}

/*
 * Send the information of workload to SCX scheduler before the workload starts.
 */
fn send_workload_info_to_scheduler(_n: usize, _edges: &Vec<(usize, usize, usize)>,
				   _weights: &Vec<usize>)
{
	// TODO:
}
