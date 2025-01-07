#!/bin/bash

# Migrate irqs to CPU 0-4,6-10 (exclude CPU 5,11)
for I in $(ls /proc/irq)
do
    if [[ -d "/proc/irq/$I" ]]
    then
        echo "Affining vector $I to CPUs 0-4,6-10"
        echo "0-4,6-10" > /proc/irq/$I/smp_affinity_list
    fi
done
