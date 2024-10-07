#pragma once

#include <string>
#include <optional>
#include <thread>
#include <atomic>
#include <memory>
#include "Common.h"


class eBPFProgram {
public:
    eBPFProgram();
    ~eBPFProgram();

    void start();
    void stop();

    // 獲取下一個行程事件
    std::optional<ProcessInfo> getNextProcessEvent();

private:
    void eventListener();

    std::thread listenerThread_;
    std::atomic<bool> running_;
    // 用於儲存從 eBPF 接收到的事件，可以使用thread安全的隊列
    // 例如：std::queue 或其他queue結構，需thread安全
};
