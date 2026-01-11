#pragma once

#include <string>
#include <chrono>
#include <condition_variable>
#include <linux/types.h>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <atomic>
#include <memory>
#include "Common.h"

struct exec_monitor_bpf;
struct perf_buffer;

class eBPFProgram {
public:
    eBPFProgram();
    ~eBPFProgram();

    void start();
    void stop();
    bool isRunning() const;

    // Get the next process event (non-blocking).
    std::optional<ProcessInfo> getNextProcessEvent();
    std::optional<ProcessInfo> waitNextProcessEvent(std::chrono::milliseconds timeout);

private:
    void eventListener();

    static void handleEvent(void *ctx, int cpu, void *data, __u32 data_sz);
    static void handleLostEvents(void *ctx, int cpu, __u64 lost_cnt);

    std::thread listenerThread_;
    std::atomic<bool> running_;

    exec_monitor_bpf* skel_;
    perf_buffer* pb_;

    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::queue<ProcessInfo> processQueue_;
};
