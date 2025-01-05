// SPDX-License-Identifier: GPL-2.0

/*
 * The build sctipt build.rs compiles the BPF program src/bpf/main.bpf.c
 * and generates a skeleton file at OUT_DIR/bpf_skel.rs.
 * The following statement includes the generated file here. 
 */
include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
