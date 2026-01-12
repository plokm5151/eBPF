set(BPF_PROG exec_monitor)

find_program(BPF_CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH arm64)
else()
    message(FATAL_ERROR "Unsupported arch for eBPF build: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(BPF_EXTRA_INCLUDES)
if(CMAKE_LIBRARY_ARCHITECTURE)
    set(MULTIARCH_INCLUDE_DIR "/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")
else()
    if(BPF_ARCH STREQUAL "x86")
        set(MULTIARCH_INCLUDE_DIR "/usr/include/x86_64-linux-gnu")
    elseif(BPF_ARCH STREQUAL "arm64")
        set(MULTIARCH_INCLUDE_DIR "/usr/include/aarch64-linux-gnu")
    endif()
endif()
if(DEFINED MULTIARCH_INCLUDE_DIR AND EXISTS "${MULTIARCH_INCLUDE_DIR}")
    list(APPEND BPF_EXTRA_INCLUDES -I "${MULTIARCH_INCLUDE_DIR}")
endif()

set(BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/${BPF_PROG}.bpf.o")
set(BPF_SKELETON_H "${CMAKE_CURRENT_BINARY_DIR}/${BPF_PROG}.skel.h")

set(GENERATE_SKELETON_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/GenerateBpfSkeleton.cmake")

add_custom_command(
    OUTPUT "${BPF_OBJ}"
    COMMAND
        "${BPF_CLANG}" -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
        -I "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${CMAKE_CURRENT_SOURCE_DIR}"
        -I "${CMAKE_SOURCE_DIR}/include"
        ${BPF_EXTRA_INCLUDES}
        -I "${LIBBPF_INCLUDE_DIRS}"
        -Wall
        -c "${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c"
        -o "${BPF_OBJ}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${BPF_PROG}.bpf.c"
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
