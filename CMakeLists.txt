cmake_minimum_required(VERSION 3.13)
project(ScxAnalyzer)
find_package(Threads)

# Define a static library for Perfetto.
include_directories(perfetto/sdk)
add_library(perfetto STATIC perfetto/sdk/perfetto.cc)

# libbpf
set(LIBBPF_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/_INSTALL/usr/include)
set(LIBBPF_LIB ${CMAKE_SOURCE_DIR}/_INSTALL/usr/lib64/libbpf.a)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)

include_directories(
	${LIBBPF_INCLUDE_DIR}
	${LIBELF_INCLUDE_DIRS})

# Link the library to your main executable.
add_executable(scx_analyzer scx_analyzer.cc ring_buffer.cc scx_wrapper.cc)
target_link_libraries(scx_analyzer
	perfetto
	${LIBBPF_LIB}
	${LIBELF_LIBRARIES}
	z
	${CMAKE_THREAD_LIBS_INIT})
