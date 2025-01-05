// SPDX-License-Identifier: GPL-2.0

mod bpf_skel;
mod bpf_intf;

use bpf_intf::*;
use bpf_skel::*;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;

use anyhow::Context;
use anyhow::Result;

use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;

use plain::Plain;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

unsafe impl Plain for cb_history_entry {}

fn main() {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    }).unwrap();

    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, scheduler_ops).unwrap();
    let mut skel: BpfSkel = scx_ops_load!(skel, scheduler_ops, uei).unwrap();
    let link: Link = scx_ops_attach!(skel, scheduler_ops).unwrap();
    
    println!("[*] BPF scheduler starting!");

    while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&skel, uei) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    println!("[*] BPF scheduler exiting..\n");

    /*
     * Detach the BPF scheduler and finally report the BPF maps.
     */
    link.detach().unwrap();
}
