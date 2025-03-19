use std::collections::HashSet;
use std::collections::HashMap;



// similar to a thread id
type Reactor = u32;

#[derive(Debug)]
struct TaskGraph {
	nr_tasks: usize,
	task_to_reactor: Vec<Reactor>, // task_to_reactor[i]: the i-th reactor id
	reactor_to_task: HashMap<u32, usize>,
	edges: Vec<Vec<usize>>,
}

impl TaskGraph {
	fn new() -> Self {
		Self {
			nr_tasks: 0,
			task_to_reactor: vec![],
			reactor_to_task: HashMap::new(),
			edges: vec![],
		}
	}
}

#[derive(Debug)]
struct TaskGraphBuilder {
	reactors: HashSet<Reactor>,
	subs: HashMap<String, HashSet<Reactor>>, // topic name -> [reactor id]
	pubs: HashMap<String, HashSet<Reactor>>, // topic name -> [reactor id]
	topics: HashSet<String>,
}


impl TaskGraphBuilder {
	fn new() -> Self {
		Self {
			reactors: HashSet::new(),
			subs: HashMap::new(),
			pubs: HashMap::new(),
			topics: HashSet::new(),
		}
	}

	/// @reactor: Reactor id
	fn reg_reactor(&mut self, reactor: Reactor, subs: Vec<String>, pubs: Vec<String>) {
		assert!(!self.reactors.contains(&reactor));

		for s in &subs {
			if let Some(reactors) = self.subs.get_mut(s) {
				reactors.insert(reactor);
			} else {
				let mut reactors = HashSet::new();
				reactors.insert(reactor);
				self.subs.insert(s.clone(), reactors);
			}

			self.topics.insert(s.clone());
		}

		for p in &pubs {
			if let Some(reactors) = self.pubs.get_mut(p) {
				reactors.insert(reactor);
			} else {
				let mut reactors = HashSet::new();
				reactors.insert(reactor);
				self.pubs.insert(p.clone(), reactors);
			}

			self.topics.insert(p.clone());
		}

		self.reactors.insert(reactor);
	}

	fn build(&self) -> TaskGraph {
		let nr_tasks = self.reactors.len();
		let mut task_to_reactor = vec![];
		let mut reactor_to_task = HashMap::new();
		let mut edges = vec![vec![]; nr_tasks];

		let mut reactors: Vec<&u32> = self.reactors.iter().collect();
		reactors.sort();
		for (i, reactor) in reactors.iter().enumerate() {
			println!("reactor: {}", reactor);
			task_to_reactor.push(**reactor);
			reactor_to_task.insert(**reactor, i);
		}

		for topic in &self.topics {
			let subs = match self.subs.get(topic) {
				Some(subs) => subs,
				_ => continue,
			};
			let pubs = match self.pubs.get(topic) {
				Some(pubs) => pubs,
				_ => continue,
			};

			for src in pubs {
				for dst in subs {
					let src = reactor_to_task[src];
					let dst = reactor_to_task[dst];
					edges[src].push(dst);
				}
			}
		}

		TaskGraph {
			nr_tasks,
			task_to_reactor,
			reactor_to_task,
			edges,
		}

	}
}


#[test]
fn test_dag_task_builder()
{
	let mut builder = TaskGraphBuilder::new();

	builder.reg_reactor(0, vec![], vec!["topic0".to_string()]);
	builder.reg_reactor(1, vec!["topic0".to_string()], vec!["topic1".to_string(), "topic2".to_string()]);
	builder.reg_reactor(2, vec!["topic1".to_string()], vec!["topic3".to_string()]);
	builder.reg_reactor(3, vec!["topic2".to_string()], vec!["topic4".to_string()]);
	builder.reg_reactor(4, vec!["topic3".to_string(), "topic4".to_string()], vec![]);

	println!("builder: {:?}", builder);
	let dag = builder.build();
	println!("dag: {:?}", dag);
}
