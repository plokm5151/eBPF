// ebpf/exec_monitor.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct process_info_t {
    u32 pid;
    u32 gid;
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(handle_execve)
{
    struct process_info_t info = {};
    u64 id = bpf_get_current_pid_tgid();
    info.pid = id >> 32;
    info.gid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&info.filename, sizeof(info.filename));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
