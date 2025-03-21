// HEFT: Heterogeneous Earliest Finish Time

use std::collections::HashMap;
use maplit::hashmap;
use crate::dag::*;

type TaskWeight = usize;
type TaskPrio = usize;

fn culc_HELT_prio_rec(dag_task: &DagTask, u: usize, w: &HashMap<Reactor, TaskWeight>, prio: &mut Vec<Option<TaskPrio>>)
{
	println!("u: {u}");
	if dag_task.edges[u].is_empty() {
		// sink node
		prio[u] = w.get(&u).copied();
	} else {
		let mut tail_weight_max = 0;
		for v in &dag_task.edges[u] {
			culc_HELT_prio_rec(dag_task, *v, w, prio);
			assert!(prio[*v].is_some());
			tail_weight_max = std::cmp::max(tail_weight_max, prio[*v].unwrap());
		}
		prio[u] = Some(*w.get(&u).unwrap() + tail_weight_max);
	}
}

pub fn culc_HELT_prio(dag_task: &DagTask, w: &HashMap<Reactor, TaskWeight>) -> Vec<TaskPrio>
{
	let mut prio = vec![None; dag_task.nr_nodes];
	culc_HELT_prio_rec(dag_task, 0, w, &mut prio);
	prio.into_iter().map(|v| v.unwrap()).collect()
}

/// An example task graph presented in the paper:
/// "Intra-Task Priority Assignment in Real-Time
///  Scheduling of DAG Tasks on Multi-Cores"
#[test]
fn test_culc_HELT_prio()
{
	let nr_nodes = 7;
	let node_to_reactor = (0..7).collect();
	let mut reactor_to_node = HashMap::new();
	for i in 0..7 {
		reactor_to_node.insert(i, i);
	}
	let edges = vec![
		vec![1, 2, 3],	// 0 -> 1, 0 -> 2, 0 -> 3, 0 is src
		vec![4],	// 1 -> 4
		vec![4],	// 2 -> 4
		vec![6],	// 3 -> 6
		vec![5],	// 4 -> 5
		vec![6],	// 5 -> 6
		vec![],		// 6 is sink
	];

	let dag_task = DagTask {
		id: 0,
		nr_nodes,
		node_to_reactor,
		reactor_to_node,
		edges,
	};
	let w = hashmap! {
		0 => 1,
		1 => 3,
		2 => 1,
		3 => 2,
		4 => 1,
		5 => 1,
		6 => 1,
	};

	let prio = culc_HELT_prio(&dag_task, &w);
	println!("prio: {:?}", prio);
}
