#include "eBPFProgram.h"
#include "exec_monitor.skel.h"
#include "Logger.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <queue>
#include <mutex>


std::queue<ProcessInfo> processQueue;
std::mutex queueMutex;

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct process_info_t *e = (struct process_info_t *)data;

    ProcessInfo info;
    info.pid = e->pid;
    info.gid = e->gid;
    info.filePath = e->filename;

    // 加鎖保護佇列
    std::lock_guard<std::mutex> lock(queueMutex);
    processQueue.push(info);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    auto& logger = Logger::getInstance();
    logger.logError("Lost " + std::to_string(lost_cnt) + " events on CPU " + std::to_string(cpu));
}

eBPFProgram::eBPFProgram() : running_(false), skel_(nullptr), pb_(nullptr) {
    // 設置 rlimit，以允許加載更大的 BPF 程式
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);
}

eBPFProgram::~eBPFProgram() {
    stop();
}

void eBPFProgram::start() {
    running_ = true;

    // 加載並驗證 BPF 程式
    skel_ = exec_monitor_bpf__open_and_load();
    if (!skel_) {
        throw std::runtime_error("Failed to open and load BPF skeleton");
    }

    // 附加 kprobe
    int err = exec_monitor_bpf__attach(skel_);
    if (err) {
        throw std::runtime_error("Failed to attach BPF skeleton");
    }

    // 打開 perf buffer
    pb_ = perf_buffer__new(bpf_map__fd(skel_->maps.events), 8, handle_event, handle_lost_events, nullptr, nullptr);
    if (!pb_) {
        throw std::runtime_error("Failed to open perf buffer");
    }

    // 啟動事件監聽線程
    listenerThread_ = std::thread(&eBPFProgram::eventListener, this);
}

void eBPFProgram::stop() {
    if (running_) {
        running_ = false;
        if (listenerThread_.joinable()) {
            listenerThread_.join();
        }
        if (pb_) {
            perf_buffer__free(pb_);
            pb_ = nullptr;
        }
        if (skel_) {
            exec_monitor_bpf__destroy(skel_);
            skel_ = nullptr;
        }
    }
}

void eBPFProgram::eventListener() {
    auto& logger = Logger::getInstance();

    while (running_) {
        int err = perf_buffer__poll(pb_, 100);
        if (err < 0) {
            logger.logError("Error polling perf buffer: " + std::to_string(err));
            break;
        }
    }
}

std::optional<ProcessInfo> eBPFProgram::getNextProcessEvent() {
    std::lock_guard<std::mutex> lock(queueMutex);
    if (!processQueue.empty()) {
        ProcessInfo info = processQueue.front();
        processQueue.pop();
        return info;
    } else {
        return std::nullopt;
    }
}
