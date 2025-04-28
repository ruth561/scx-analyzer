import matplotlib.pyplot as plt


class NodeInfo:
	def __init__(self, tid, src_node_tid, comm, weight):
		self.tid = tid
		self.src_nod_tid = src_node_tid
		self.comm = comm
		self.weight = weight
		self.exectimes = []
	
	def add_exectime(self, exectime):
		self.exectimes.append(exectime)


node_info_list = dict()
# dag_tasks[tid]: Thread idがtidのsrc nodeのDAGに含まれるスレッドの集合
dag_tasks = dict()


hints = []
exectimes = []
with open("log.txt") as logf:
	for line in logf.readlines():
		line.strip()
		line = list(line.split(","))
		if line[0] == "task_info":
			assert line[1][:4] == "tid="
			tid = int(line[1][4:])
			assert line[2][:13] == "src_node_tid="
			src_node_tid = int(line[2][13:])
			assert line[3][:5] == "comm="
			comm = line[3][5:]
			assert line[4][:7] == "weight="
			weight = int(line[4][7:])
			
			if src_node_tid in dag_tasks.keys():
				dag_tasks[src_node_tid].add(tid)
			else:
				dag_tasks[src_node_tid] = { tid }
			node_info_list[tid] = NodeInfo(tid, src_node_tid, comm, weight)
		elif line[0] == "work_info":
			# ほげ
			assert line[1][:4] == "tid="
			tid = int(line[1][4:])
			assert line[2][:9] == "exectime="
			exectime = int(line[2][9:])
			assert line[3][:7] == "weight="
			weight = int(line[3][7:])
			
                        # exectimeに下限を設ける
			# 下限を下回るときは無視
			if exectime <= 5_000_000: # 5ms
				continue
			
			node_info_list[tid].add_exectime(exectime)
		else:
			print("Unknown message:", line[0])


print(node_info_list)
print(dag_tasks)

plt.figure()

labels = []

for i, node_tid in enumerate(node_info_list):
	node_info = node_info_list[node_tid]
	print(i, node_info)
	exectimes = node_info.exectimes
	x = [i for _ in exectimes]
	plt.scatter(x, exectimes)
	labels.append(node_info.comm)

plt.xticks(range(len(labels)), labels, rotation=45, ha='right', fontsize=20)

plt.ylabel('Execution Time (ns)', fontsize=20)
plt.title('Execution Time per Task', fontsize=40)

# y軸の下限を設定する
# y軸の上限値の0.05倍だけ下に余白を設定する
current_ylim = plt.gca().get_ylim()
ymax = current_ylim[1]
plt.ylim(bottom=-0.05 * ymax)

plt.axhline(y=0, color='black', linestyle='--', linewidth=1)

plt.show()
