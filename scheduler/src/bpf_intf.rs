// SPDX-License-Identifier: GPL-2.0

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

/*
 * The build script build.rs converts the header src/bpf/intf.h,
 * written in C, into OUT_DIR/bpf_intf.rs, which is written in Rust.
 * This allow us to use the header indirectly through the generated file.
 */
include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
