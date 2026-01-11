cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED BPFTOOL)
    message(FATAL_ERROR "BPFTOOL is not set")
endif()
if(NOT DEFINED VMLINUX_BTF)
    message(FATAL_ERROR "VMLINUX_BTF is not set")
endif()
if(NOT DEFINED OUT)
    message(FATAL_ERROR "OUT is not set")
endif()

get_filename_component(out_dir "${OUT}" DIRECTORY)
file(MAKE_DIRECTORY "${out_dir}")

execute_process(
    COMMAND "${BPFTOOL}" btf dump file "${VMLINUX_BTF}" format c
    RESULT_VARIABLE rc
    OUTPUT_FILE "${OUT}"
    ERROR_VARIABLE err
)

if(NOT rc EQUAL 0)
    file(REMOVE "${OUT}")
    string(STRIP "${err}" err)
    message(FATAL_ERROR "bpftool btf dump failed (rc=${rc}): ${err}")
endif()

