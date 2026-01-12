#include "ExecMonitor.h"

#include <linux/bpf.h>
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

#if defined(__TARGET_ARCH_x86)
#define RPD_SYSCALL_EXECVE 59
#define RPD_SYSCALL_EXECVEAT 322
#elif defined(__TARGET_ARCH_arm64)
#define RPD_SYSCALL_EXECVE 221
#define RPD_SYSCALL_EXECVEAT 281
#else
#error "Unsupported BPF target arch for syscall numbers"
#endif

struct execve_args_t {
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
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

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter* ctx)
{
    __s64 id = ctx->id;
    const char* filename = 0;
    if (id == RPD_SYSCALL_EXECVE) {
        filename = (const char*)(unsigned long)ctx->args[0];
    } else if (id == RPD_SYSCALL_EXECVEAT) {
        filename = (const char*)(unsigned long)ctx->args[1];
    } else {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 scratch_key = 0;
    struct execve_args_t* args = bpf_map_lookup_elem(&scratch_args, &scratch_key);
    if (!args) {
        return 0;
    }
    __builtin_memset(args, 0, sizeof(*args));

    bpf_probe_read_user_str(args->filename, sizeof(args->filename), filename);

    bpf_map_update_elem(&execve_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

static __always_inline int handle_exit_exec_common(struct trace_event_raw_sys_exit* ctx)
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

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit* ctx)
{
    __s64 id = ctx->id;
    if (id != RPD_SYSCALL_EXECVE && id != RPD_SYSCALL_EXECVEAT) {
        return 0;
    }
    return handle_exit_exec_common(ctx);
}

char LICENSE[] SEC("license") = "GPL";
