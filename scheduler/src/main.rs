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

use std::io::Read;
use std::io::Write;
use std::fs::File;
use std::io::BufWriter;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

unsafe impl Plain for entry_header {}
unsafe impl Plain for task_info {}
unsafe impl Plain for work_info {}

use clap::Parser;

#[derive(Debug, Clone, Copy)]
enum DagSchedAlgo {
    HELT,
    HLBS,
}

use std::str::FromStr;

impl FromStr for DagSchedAlgo {
	type Err = String; // エラーとして `String` を使用
    
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"HELT" => Ok(DagSchedAlgo::HELT),
			"HLBS" => Ok(DagSchedAlgo::HLBS),
			_ => Err(format!("Invalid policy string '{}'", s)),
		}
	}
}

#[derive(Debug, Parser)]
struct Cli {
    /// Specify the CPUs where ops events should be recorded.
    /// Accepted formats:
    ///   - Single CPUs:  0,1
    ///   - Ranges:       4-7
    ///   - Mixed:        3,6-8
    #[clap(short, long, verbatim_doc_comment)]
    record_cpus: String,

    /// Specify the DAG scheduling algorithm.
    #[clap(short, long, verbatim_doc_comment)]
    dag_sched: DagSchedAlgo,

    /// If you want to enable execution time estimator, then set true to this parametor.
    #[clap(short, long, verbatim_doc_comment, default_value="false")]
    exec_est_enable: bool,
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

fn get_cpu_list_from_sysfs(path: &str) -> String
{
    let mut cpu_list_file = std::fs::File::open(path).unwrap();
    let mut buf = String::new();
    cpu_list_file.read_to_string(&mut buf).unwrap();

    buf.trim().to_string()
}

fn get_isolated_cpu_mask() -> u64
{
    let cpulist = get_cpu_list_from_sysfs("/sys/devices/system/cpu/isolated");
    let cpumask = parse_cpus_str(&cpulist);
    cpumask
}

fn get_possible_cpu_mask() -> u64
{
    let cpulist = get_cpu_list_from_sysfs("/sys/devices/system/cpu/possible");
    let cpumask = parse_cpus_str(&cpulist);
    cpumask
}

fn get_online_cpu_mask() -> u64
{
    let cpulist = get_cpu_list_from_sysfs("/sys/devices/system/cpu/online");
    let cpumask = parse_cpus_str(&cpulist);
    cpumask
}

fn char_ptr_to_str(data: &[i8]) -> String
{
    let bytes: Vec<u8> = data.iter().map(|&b| b as u8).collect();
    
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let ascii_bytes = &bytes[..end];

    std::str::from_utf8(ascii_bytes).unwrap().to_string()
}

fn logger_rb_recorder(data: &[u8], writer: &mut BufWriter<File>) -> i32
{
    let log_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
    match log_type {
        LOG_TYPE_TASK_INFO => {
            let entry: &task_info = plain::from_bytes(data).unwrap();
            writeln!(
                writer,
                "task_info,tid={},comm={},weight={}",
                entry.tid,
                char_ptr_to_str(&entry.comm),
                entry.weight
            ).unwrap();
        },
        LOG_TYPE_WORK_INFO => {
            let entry: &work_info = plain::from_bytes(data).unwrap();
            writeln!(
                writer,
                "work_info,tid={},exectime={},weight={}",
                entry.tid,
                entry.exectime,
                entry.weight
            ).unwrap();
        },
        _ => {
            assert!(false);
        }
    }
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
    let possible_cpumask = get_possible_cpu_mask();
    let online_cpumask = get_online_cpu_mask();
    let isolated_cpumask = get_isolated_cpu_mask();
    skel.maps.bss_data.possible_cpumask.cpumask.bits[0] = possible_cpumask;
    skel.maps.bss_data.online_cpumask.cpumask.bits[0] = online_cpumask;
    skel.maps.bss_data.isolated_cpumask.cpumask.bits[0] = isolated_cpumask;
    skel.maps.bss_data.nr_possible_cpus = possible_cpumask.count_ones();
    skel.maps.bss_data.nr_online_cpus = online_cpumask.count_ones();
    skel.maps.bss_data.nr_isolated_cpus = isolated_cpumask.count_ones();

    let record_cpumask = parse_cpus_str(&cli.record_cpus);
    println!("[*] record_cpumask: 0x{:016x}", record_cpumask);
    skel.maps.bss_data.record_cpumask.cpumask.bits[0] = record_cpumask;

    /*
     * Setting DAG scheduling algorithm
     */
    skel.maps.data_data.dag_sched_algo = 0;
    match cli.dag_sched {
        DagSchedAlgo::HELT => {
            skel.maps.data_data.dag_sched_algo = DAG_SCHED_ALGO_DAG_SCHED_HELT as i32;
            println!("[*] The HELT algorithm is used!");
        },
        DagSchedAlgo::HLBS => {
            skel.maps.data_data.dag_sched_algo = DAG_SCHED_ALGO_DAG_SCHED_HLBS as i32;
            println!("[*] The HLBS algorithm is used!");
        },
    };

    if cli.exec_est_enable {
        skel.maps.bss_data.exec_est_enabled = true;
        println!("[*] Exec time estimator is enabled!");
    } else {
        println!("[*] Exec time estimator is disabled.");
    }

    let mut skel: BpfSkel = scx_ops_load!(skel, scheduler_ops, uei).unwrap();
    let link: Link = scx_ops_attach!(skel, scheduler_ops).unwrap();
    
    let file = File::create("log.txt").unwrap();
    let mut writer = BufWriter::new(file);
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.logger_rb, move |data| {
        logger_rb_recorder(data, &mut writer)
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
