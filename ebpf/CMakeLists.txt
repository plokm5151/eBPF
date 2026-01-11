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

set(GENERATE_VMLINUX_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/GenerateVmlinuxHeader.cmake")
set(GENERATE_SKELETON_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/GenerateBpfSkeleton.cmake")

add_custom_command(
    OUTPUT "${VMLINUX_H}"
    COMMAND "${CMAKE_COMMAND}"
        -DBPFTOOL:FILEPATH=${BPFTOOL}
        -DVMLINUX_BTF:FILEPATH=${VMLINUX_BTF}
        -DOUT:FILEPATH=${VMLINUX_H}
        -P "${GENERATE_VMLINUX_SCRIPT}"
    DEPENDS "${GENERATE_VMLINUX_SCRIPT}"
    COMMENT "Generating vmlinux.h from kernel BTF"
    VERBATIM
)

add_custom_command(
    OUTPUT "${BPF_OBJ}"
    COMMAND
        "${BPF_CLANG}" -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
        -I "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${CMAKE_CURRENT_SOURCE_DIR}"
        -I "${CMAKE_SOURCE_DIR}/include"
        -I "${LIBBPF_INCLUDE_DIRS}"
        -Wall
        -c "${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c"
        -o "${BPF_OBJ}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c" "${VMLINUX_H}"
    COMMENT "Compiling eBPF program"
    VERBATIM
)

add_custom_command(
    OUTPUT "${BPF_SKELETON_H}"
    COMMAND "${CMAKE_COMMAND}"
        -DBPFTOOL:FILEPATH=${BPFTOOL}
        -DBPF_OBJ:FILEPATH=${BPF_OBJ}
        -DOUT:FILEPATH=${BPF_SKELETON_H}
        -P "${GENERATE_SKELETON_SCRIPT}"
    DEPENDS "${BPF_OBJ}" "${GENERATE_SKELETON_SCRIPT}"
    COMMENT "Generating libbpf skeleton header"
    VERBATIM
)

add_custom_target(bpf_target DEPENDS "${BPF_SKELETON_H}")

set(EBPF_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}" PARENT_SCOPE)
set(EBPF_SKELETON_HEADER "${BPF_SKELETON_H}" PARENT_SCOPE)
