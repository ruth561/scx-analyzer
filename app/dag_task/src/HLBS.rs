// HLBS: Heterogeneous Laxity-Based Scheduling Algorithm for DAG-based Real-Time Computing

use std::{collections::HashMap, usize};
use maplit::hashmap;
use crate::dag::*;

type TaskWeight = usize;
type TaskLaxity = usize;

// TODO: This implementation requires a "DEADLINE" for each invocation,
// but Actually, calculating DEADLINE - laxity allows us to avoid calling
// this function on every invocation.
// We're going to call it `laxity_sub`.
// I'll revise the following implementations to reflect that.

// D: The deadline
// w: The weight of tasks (meaning WCET)
fn culc_HLBS_laxity_rec(dag_task: &DagTask, D: usize, u: usize, w: &HashMap<Reactor, TaskWeight>, laxity: &mut Vec<Option<TaskLaxity>>)
{
	println!("u: {u}");
	if dag_task.edges[u].is_empty() {
		// sink node
		laxity[u] = Some(D - w.get(&u).unwrap());
	} else {
		let mut tail_laxity_min = TaskLaxity::MAX;
		for v in &dag_task.edges[u] {
			culc_HLBS_laxity_rec(dag_task, D, *v, w, laxity);
			assert!(laxity[*v].is_some());
			tail_laxity_min = std::cmp::min(tail_laxity_min, laxity[*v].unwrap());
		}
		println!("tail_laxity_min: {tail_laxity_min}, w[{u}]={}", *w.get(&u).unwrap());
		laxity[u] = Some(tail_laxity_min - *w.get(&u).unwrap());
	}

	println!("u: {u}, laxity[{u}]={:?}", laxity[u]);
}

pub fn culc_HLBS_laxity(dag_task: &DagTask, D: usize, w: &HashMap<Reactor, TaskWeight>) -> Vec<TaskLaxity>
{
	let mut laxity = vec![None; dag_task.nr_nodes];
	culc_HLBS_laxity_rec(dag_task, D, 0, w, &mut laxity);
	laxity.into_iter().map(|v| v.unwrap()).collect()
}

/// [1(1)] 
#[test]
fn test_culc_HLBS_laxity()
{
	let nr_nodes = 8;
	let node_to_reactor = (0..nr_nodes).collect();
	let mut reactor_to_node = HashMap::new();
	for i in 0..nr_nodes {
		reactor_to_node.insert(i, i);
	}
	let edges = vec![
		vec![1, 2, 3, 4, 5],
		vec![7],
		vec![7],
		vec![7],
		vec![6],
		vec![6],
		vec![7],
		vec![],
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
		1 => 7,
		2 => 3,
		3 => 3,
		4 => 6,
		5 => 1,
		6 => 2,
		7 => 1,
	};

	let laxity = culc_HLBS_laxity(&dag_task, 10, &w);
	println!("laxity: {:?}", laxity);
}
