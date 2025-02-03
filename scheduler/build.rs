// SPDX-License-Identifier: GPL-2.0

fn main() {
	// src/bpf/main.bpf.cをコンパイルし、スケルトンファイルに変換する。
	// スケルトンファイルは$(OUT_DIR)/bpf_skel.rsに生成される。
	// OUT_DIRとはビルド時に設定される環境変数であり、中間ファイルなどを
	// 配置しておくディレクトリへのPATHが設定されている。
	// 例えば、target/debug/build/scx-rs-tutorial-XXX/outといった
	// 場所にbpf_skel.rsが生成される。
	//
	// ここの処理はパッケージのビルドの前に先に行われる。生成された
	// $(OUT_DIR)/bpf_skel.rsは、src/bpf_skel.rsでincludeされて
	// 使われることになっている（src/bpf_skel.rsを参照）。
	scx_utils::BpfBuilder::new()
		.unwrap()
		.enable_intf("src/bpf/intf.h", "bpf_intf.rs")
		.enable_skel("src/bpf/main.bpf.c", "bpf")
		.add_source("src/bpf/sched.bpf.c")
		.add_source("src/bpf/stats.bpf.c")
		.compile_link_gen()
		.unwrap();
}
    