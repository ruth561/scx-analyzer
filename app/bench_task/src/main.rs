use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::time::Duration;

use std::sync::mpsc;

use rand::seq::IndexedRandom;
use utils::bpf::urb::UserRingBuffer;

const USER_RING_BUFFER_NAME: &'static str = "urb";

fn busy(weight: usize)
{
    for i in 0..weight {
        std::hint::black_box(i);
    }
}

#[repr(C)]
struct MsgStruct {
    tid: i32,
    relative_deadline: u64,
    exectime: u64,
}

fn get_tid() -> i32
{
    unsafe { libc::gettid() }
}

/*
 * @rtid: Receiver thread id 
 */
fn sensor_thread_main(txes: Vec<Sender<usize>>, tids: Vec<i32>)
{
    let mut urb = UserRingBuffer::new(USER_RING_BUFFER_NAME).unwrap();

    /*
     * Set this thread's priority high.
     */
    urb.send(MsgStruct {
        tid: get_tid(),
        relative_deadline: Duration::from_millis(3).as_nanos() as u64,
        exectime: Duration::from_millis(3).as_nanos() as u64,
    }).unwrap();

    let mut rng = rand::rng();
    let nums: Vec<u64> = (1..200).collect();
    loop {

	let hint = nums.choose(&mut rng).unwrap();
	
        std::thread::sleep(Duration::from_millis(200));

        /*
         * Send the information of receiver thread.
         */
        urb.send(MsgStruct {
		tid: tids[0],
		relative_deadline: Duration::from_secs(1).as_nanos() as u64,
		exectime: Duration::from_millis(*hint).as_nanos() as u64,
        }).unwrap();

        txes[0].send(*hint as usize).unwrap();

        /*
         * Send the information of receiver thread.
         */
        urb.send(MsgStruct {
		tid: tids[0],
		relative_deadline: Duration::from_secs(1).as_nanos() as u64,
		exectime: Duration::from_millis(*hint).as_nanos() as u64,
        }).unwrap();

        txes[1].send(*hint as usize).unwrap();
    }
}

/*
 * per 1ms
 */
const BUSY_UNIT: usize = 50000;

fn worker_thread_main(rx: Receiver<usize>)
{
    loop {
        let val = rx.recv().unwrap();

        busy(val * BUSY_UNIT);
    }
}

fn main() {

    // worker thread 1
    let (tx1, rx1) = mpsc::channel();
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

    // worker thread 3
    let (tx3, rx3) = mpsc::channel();
    let (tx_for_tid, rx_for_tid) = mpsc::channel();
    let w3 = std::thread::spawn(move || {
        tx_for_tid.send(get_tid()).unwrap();
        worker_thread_main(rx3);
    });
    let w3_tid = rx_for_tid.recv().unwrap();

    let txes = vec![tx1, tx2, tx3];
    let tids = vec![w1_tid, w2_tid, w3_tid];
    let (tx_for_tid, rx_for_tid) = mpsc::channel();
    let st = std::thread::spawn(move || {
        tx_for_tid.send(get_tid()).unwrap();
        sensor_thread_main(txes, tids);
    });
    let stid = rx_for_tid.recv().unwrap();

    println!("current thread's tid: {}", get_tid());
    println!("worker thread 1's tid: {}", w1_tid);
    println!("worker thread 2's tid: {}", w2_tid);
    println!("worker thread 3's tid: {}", w3_tid);
    println!("sensor thread's tid: {}", stid);

    st.join().unwrap();
    w1.join().unwrap();
    w2.join().unwrap();
    w3.join().unwrap();
}
