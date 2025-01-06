#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct ring_buffer *create_rb_subscriber(const char *map_name, ring_buffer_sample_fn cb);
