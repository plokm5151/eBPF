set(BPF_PROG exec_monitor)

find_program(BPF_CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)

set(VMLINUX_BTF "/sys/kernel/btf/vmlinux" CACHE FILEPATH "Path to vmlinux BTF file")
if(NOT EXISTS "${VMLINUX_BTF}")
    message(FATAL_ERROR "Kernel BTF not found at: ${VMLINUX_BTF}")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH arm64)
else()
    message(FATAL_ERROR "Unsupported arch for eBPF build: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(VMLINUX_H "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h")
set(BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/${BPF_PROG}.bpf.o")
set(BPF_SKELETON_H "${CMAKE_CURRENT_BINARY_DIR}/${BPF_PROG}.skel.h")

add_custom_command(
    OUTPUT "${VMLINUX_H}"
    COMMAND bash -c "\"${BPFTOOL}\" btf dump file \"${VMLINUX_BTF}\" format c > \"${VMLINUX_H}\""
    COMMENT "Generating vmlinux.h from kernel BTF"
    VERBATIM
)

add_custom_command(
    OUTPUT "${BPF_OBJ}"
    COMMAND
        "${BPF_CLANG}" -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
        -I"${CMAKE_CURRENT_BINARY_DIR}"
        -I"${CMAKE_CURRENT_SOURCE_DIR}"
        -I"${LIBBPF_INCLUDE_DIRS}"
        -Wall
        -c "${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c"
        -o "${BPF_OBJ}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c" "${VMLINUX_H}"
    COMMENT "Compiling eBPF program"
    VERBATIM
)

add_custom_command(
    OUTPUT "${BPF_SKELETON_H}"
    COMMAND bash -c "\"${BPFTOOL}\" gen skeleton \"${BPF_OBJ}\" > \"${BPF_SKELETON_H}\""
    DEPENDS "${BPF_OBJ}"
    COMMENT "Generating libbpf skeleton header"
    VERBATIM
)

add_custom_target(bpf_target DEPENDS "${BPF_SKELETON_H}")

set(EBPF_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}" PARENT_SCOPE)
set(EBPF_SKELETON_HEADER "${BPF_SKELETON_H}" PARENT_SCOPE)
