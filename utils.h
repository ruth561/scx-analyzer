#pragma once

#include <cstdio>
#include <unistd.h>

/*
 * Returns the number of CPUs in the system.
 * If @only_online is true, only online CPUs are counted.
 * If the return value is < 0, an error has occurred. 
 */
static int get_nr_cpus_system(bool only_online)
{
	int nr_cpus;

	if (only_online) {
		nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	} else {
		nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	}

	return nr_cpus;
}
