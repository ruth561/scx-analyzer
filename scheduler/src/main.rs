// SPDX-License-Identifier: GPL-2.0

mod bpf_skel;
mod bpf_intf;

use bpf_intf::*;
use bpf_skel::*;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::RingBufferBuilder;

use anyhow::Context;
use anyhow::Result;

use scx_utils::import_enums;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use plain::Plain;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

unsafe impl Plain for entry_header {}
unsafe impl Plain for task_work_info {}

use clap::Parser;

#[derive(Debug, Parser)]
struct Cli {
    /// Specify the CPUs where ops events should be recorded.
    /// Accepted formats:
    ///   - Single CPUs:  0,1
    ///   - Ranges:       4-7
    ///   - Mixed:        3,6-8
    #[clap(short, long, verbatim_doc_comment)]
    record_cpus: String,
}

/*
 * Parses a CPU list string specified via command-line arguments
 * and converts it into a cpumask representing the CPUs.
 */
fn parse_cpus_str(cpu_str_arg: &str) -> u64
{
    let mut cpumask = 0u64;
    for cpu_str in cpu_str_arg.split(",") {
        if let Some(i) = cpu_str.find("-") {
            let low = i32::from_str_radix(&cpu_str[0..i], 10).unwrap();
            let high = i32::from_str_radix(&cpu_str[(i+1)..], 10).unwrap();
            for cpu in low..=high {
                cpumask |= 1u64 << cpu;
            }
        } else {
            let cpu = i32::from_str_radix(cpu_str, 10).unwrap();
            cpumask |= 1u64 << cpu;
        }
    }
    cpumask
}

fn logger_rb_recorder(data: &[u8]) -> i32
{
    let entry: &task_work_info = plain::from_bytes(data).unwrap();
    println!("exectime={}, hint={}", entry.exectime, entry.sched_hint);
    return 0;
}

fn main() {
    let cli = Cli::parse();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    }).unwrap();

    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, scheduler_ops).unwrap();

    /*
     * Setting cpumask
     */
    let record_cpumask = parse_cpus_str(&cli.record_cpus);
    println!("[*] record_cpumask: 0x{:016x}", record_cpumask);
    skel.maps.bss_data.record_cpumask.cpumask.bits[0] = record_cpumask;

    let mut skel: BpfSkel = scx_ops_load!(skel, scheduler_ops, uei).unwrap();
    let link: Link = scx_ops_attach!(skel, scheduler_ops).unwrap();
    
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.logger_rb, move |data| {
        logger_rb_recorder(data)
    }).unwrap();
    let ringbuf = builder.build().unwrap();

    println!("[*] BPF scheduler starting!");

    while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&skel, uei) {
        if ringbuf.poll(std::time::Duration::from_millis(10)).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    println!("[*] UEI report");
    uei_report!(&skel, uei).unwrap();

    println!("[*] BPF scheduler exiting..\n");

    /*
     * Detach the BPF scheduler and finally report the BPF maps.
     */
    link.detach().unwrap();
}
