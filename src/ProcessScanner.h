#pragma once

#include <string>
#include "Common.h"

class ProcessScanner {
public:
    ProcessScanner() = default;
    ~ProcessScanner() = default;

    // 掃描指定 pid 的行程，搜尋指定的字串模式
    bool scanProcess(pid_t pid, const std::string& pattern);

    // 將掃描結果保存為 JSON
    void saveScanResult(const ProcessInfo& processInfo);

private:
    bool searchMemory(pid_t pid, const std::string& pattern);
};
