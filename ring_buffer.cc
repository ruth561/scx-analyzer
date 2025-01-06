#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "ring_buffer.h"
#include "scheduler/src/bpf/intf.h"

/*
 * Find the BPF map with the name specified by @map_name in the system.
 * Returns the map ID if found, or -1 if not found.
 */
static u32 find_bpf_map_by_name(const char *map_name)
{
	u32 map_id = 0;

	while (true) {
		int err, map_fd;
		u32 info_size;
		struct bpf_map_info map_info;

		/*
		 * Retrieve the next BPF map ID after `map_id`.
		 */
		err = bpf_map_get_next_id(map_id, &map_id);
		if (err < 0) {
			printf("Failed to find BPF map named %s.\n", map_name);
			break;
		}

		/*
		 * Get a file descriptor for the BPF map using its ID.
		 */
		map_fd = bpf_map_get_fd_by_id(map_id);
		if (map_fd < 0) {
			printf("Failed to get the file descriptor of the BPF map. (%s)\n", strerror(errno));
			continue;
		}

		/*
		 * Retrieve information about the BPF map.
		 */
		info_size = sizeof(struct bpf_map_info);
		err = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size);
		close(map_fd);
		if (err < 0) {
			printf("Failed to get the BPF map info. (%s)\n", strerror(errno));
			continue;
		}

		/*
		 * Check if the map name matches `map_name`. If so, return the map ID.
		 */
		if (!strcmp(map_info.name, map_name)) {
			return map_id;
		}
	}

	return -1;
}

static int open_bpf_map_by_name(const char *map_name)
{
	u32 mapid = find_bpf_map_by_name(map_name);
	return bpf_map_get_fd_by_id(mapid);
}

struct ring_buffer *create_rb_subscriber(const char *map_name, ring_buffer_sample_fn cb)
{
	int fd;

	fd = open_bpf_map_by_name(map_name);
	return ring_buffer__new(fd, cb, NULL, NULL);
}
