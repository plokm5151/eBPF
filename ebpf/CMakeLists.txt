# ebpf/CMakeLists.txt

cmake_minimum_required(VERSION 3.10)

set(BPF_PROG exec_monitor)

add_custom_command(
    OUTPUT ${BPF_PROG}.skel.h
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Werror -c ${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c -o ${BPF_PROG}.bpf.o
    COMMAND bpftool gen skeleton ${BPF_PROG}.bpf.o > ${BPF_PROG}.skel.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c
    COMMENT "Compiling eBPF program and generating skeleton"
)

add_custom_target(bpf_target DEPENDS ${BPF_PROG}.skel.h)

add_custom_command(
    TARGET bpf_target POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${BPF_PROG}.skel.h ${CMAKE_SOURCE_DIR}/src/
    COMMENT "Copying skeleton header to src/"
)
