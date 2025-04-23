#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "Please run this script with sudo."
	exit 1
fi

if [ $# -ne 1 ]; then
	echo "Usage: $0 <cpu_list>"
	echo "Example: $0 0-4,6-10"
	exit 1
fi

CPU_LIST=$1

# Migrate irqs to the specified CPU list
for I in $(ls /proc/irq); do
	AFFINITY_FILE="/proc/irq/$I/smp_affinity_list"

	if [[ -d "/proc/irq/$I" && -f "$AFFINITY_FILE" ]]; then
		# If the affinity file is not writable by root.
		# This scripts is supposed to be executed by root user.
		MODE=$(stat -c "%A" "$AFFINITY_FILE")
		if [[ "$MODE" == "-r--r--r--" ]]; then
			echo "Skipping IRQ $I (mode $MODE: definitely not writable)"
			continue
		fi

		echo "Affining vector $I to CPUs $CPU_LIST"
		echo "$CPU_LIST" > "$AFFINITY_FILE"
	fi	
done
