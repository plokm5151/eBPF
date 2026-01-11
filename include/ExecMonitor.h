#pragma once

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Event payload emitted by ebpf/exec_monitor.bpf.c via perf events.
struct process_info_t {
    unsigned int pid; // tgid
    unsigned int uid;
    unsigned int gid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
