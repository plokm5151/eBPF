#pragma once

#include <stdint.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Event payload emitted by ebpf/exec_monitor.bpf.c via perf events.
struct process_info_t {
    uint32_t pid; // tgid
    uint32_t uid;
    uint32_t gid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

