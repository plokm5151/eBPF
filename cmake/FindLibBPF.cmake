find_path(LIBBPF_INCLUDE_DIRS
    NAMES bpf/libbpf.h
    PATHS /usr/include /usr/local/include /usr/include/x86_64-linux-gnu
)

find_library(LIBBPF_LIBRARIES
    NAMES bpf
    PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
)

if (LIBBPF_INCLUDE_DIRS AND LIBBPF_LIBRARIES)
    set(LIBBPF_FOUND TRUE)
else()
    set(LIBBPF_FOUND FALSE)
endif()

if (LIBBPF_FOUND)
    message(STATUS "Found libbpf: ${LIBBPF_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find libbpf")
endif()

mark_as_advanced(LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES)
