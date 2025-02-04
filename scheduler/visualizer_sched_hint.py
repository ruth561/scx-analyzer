import matplotlib.pyplot as plt

# How to use
#
# 1. Run scheduler and redirect the stdout:
#
#	$ sudo target/debug/scheduler --record-cpus 5,11 > log.txt
#
# 2. Run this script:
#
#	$ python3 visualizer_sched_hint.py

hints = []
exectimes = []
with open("log.txt") as logf:
	for line in logf.readlines():
		if len(line) < 8 or line[:8] != "exectime":
			continue
		exectime, hint = line.split(", ")
		exectime = int(exectime[9:])
		hint = int(hint[5:])

		hints.append(hint)
		exectimes.append(exectime)


plt.figure()

plt.scatter(hints, exectimes)

plt.show()
