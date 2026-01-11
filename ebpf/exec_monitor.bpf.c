#include "ExecMonitor.h"

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/*
 * Tracepoint context structs for sys_enter/sys_exit.
 *
 * We intentionally define these locally (instead of including vmlinux.h) to
 * avoid CO-RE relocations and the runtime dependency on kernel BTF, which is
 * not guaranteed to be available/usable in all CI environments.
 *
 * Layout reference (kernel): struct trace_event_raw_sys_enter/exit.
 */
struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __s64 args[6];
};

struct trace_event_raw_sys_exit {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __s64 ret;
};

struct execve_args_t {
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct execve_args_t);
} execve_args SEC(".maps");

// Scratch space to avoid large stack frames (BPF stack is limited to 512 bytes).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct execve_args_t);
} scratch_args SEC(".maps");

// Scratch space to avoid large stack frames (BPF stack is limited to 512 bytes).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_info_t);
} scratch_info SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 scratch_key = 0;
    struct execve_args_t* args = bpf_map_lookup_elem(&scratch_args, &scratch_key);
    if (!args) {
        return 0;
    }
    __builtin_memset(args, 0, sizeof(*args));

    const char *filename = (const char *)(unsigned long)ctx->args[0];
    bpf_probe_read_user_str(args->filename, sizeof(args->filename), filename);

    bpf_map_update_elem(&execve_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct execve_args_t* args = bpf_map_lookup_elem(&execve_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&execve_args, &pid_tgid);
        return 0;
    }

    __u32 scratch_key = 0;
    struct process_info_t* info = bpf_map_lookup_elem(&scratch_info, &scratch_key);
    if (!info) {
        bpf_map_delete_elem(&execve_args, &pid_tgid);
        return 0;
    }
    __builtin_memset(info, 0, sizeof(*info));

    __u64 uid_gid = bpf_get_current_uid_gid();

    info->pid = pid_tgid >> 32;
    info->uid = uid_gid & 0xffffffff;
    info->gid = uid_gid >> 32;
    bpf_get_current_comm(&info->comm, sizeof(info->comm));

    __builtin_memcpy(info->filename, args->filename, sizeof(info->filename));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, info, sizeof(*info));

    bpf_map_delete_elem(&execve_args, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
