#ifndef __MY_OPS_KFUNCS_H
#define __MY_OPS_KFUNCS_H


#include "vmlinux.h"

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#define DAG_TASK_MAX_NODES	20
#define DAG_TASK_MAX_DEG	20
#define DAG_TASK_MAX_EDGES	1000

struct node_info {
	u32 tid;
	u32 weight;

	s32 prio;

	u32 nr_ins;
	u32 ins[DAG_TASK_MAX_DEG];
	u32 nr_outs;
	u32 outs[DAG_TASK_MAX_DEG];
};

struct edge_info {
	u32 from;
	u32 to;
};

struct bpf_dag_task {
	u32 id;
	u32 nr_nodes;
	struct node_info nodes[DAG_TASK_MAX_NODES];
	u32 nr_edges;
	struct edge_info edges[DAG_TASK_MAX_EDGES];
};

extern struct bpf_dag_task *bpf_dag_task_alloc(u32 src_node_tid, u32 src_node_weight) __weak __ksym;
extern void bpf_dag_task_dump(struct bpf_dag_task *dag_task) __weak __ksym;
extern void bpf_dag_task_free(struct bpf_dag_task *dag_task) __weak __ksym;
extern s32 bpf_dag_task_add_node(struct bpf_dag_task *dag_task, u32 tid, u32 weight) __weak __ksym;
extern s32 bpf_dag_task_add_edge(struct bpf_dag_task *dag_task, u32 from, u32 to) __weak __ksym;
extern void bpf_dag_task_culc_HELT_prio(struct bpf_dag_task *dag_task) __weak __ksym;
extern s32 bpf_dag_task_get_weight(struct bpf_dag_task *dag_task, u32 node_id) __weak __ksym;
extern s32 bpf_dag_task_set_weight(struct bpf_dag_task *dag_task, u32 node_id, s32 weight) __weak __ksym;
extern s32 bpf_dag_task_get_prio(struct bpf_dag_task *dag_task, u32 node_id) __weak __ksym;

enum bpf_dag_msg_type {
	BPF_DAG_MSG_NEW_TASK,	// 新しいDAGタスクが作成されたことを伝えるメッセージ（DAGタスクの識別番号はsrc nodeのtid）
	BPF_DAG_MSG_ADD_NODE,
	BPF_DAG_MSG_ADD_EDGE,
	BPF_DAG_MSG_COMMIT,	// TODO: このメッセージでやりたいこと
				//	1. DAGタスクがwell-formedか？
				//		- 連結か？
				//		- トポロジカルソートされているか？
				//		- 変な遷移辺がないか？
				//		- etc..
				//	2. 以降のDAGタスクの形状の変更を禁止する
};

struct bpf_dag_msg_new_task_payload {
	u32 src_node_tid;
	u32 src_node_weight;
};

struct bpf_dag_msg_add_node_payload {
	u32 dag_task_id;
	u32 tid;
	u32 weight;
};

struct bpf_dag_msg_add_edge_payload {
	u32 dag_task_id;
	u32 from_tid;
	u32 to_tid;
};

struct bpf_dag_msg_commit_payload {
	u32 dag_task_id;
};

#endif /* __MY_OPS_KFUNCS_H */
