#pragma once

#include <string>
#include "Common.h"

class ProcessScanner {
public:
    ProcessScanner() = default;
    ~ProcessScanner() = default;

    // Scan process memory for a given pattern.
    bool scanProcess(pid_t pid, const std::string& pattern);

    // Save scan result as JSON.
    void saveScanResult(const ProcessInfo& processInfo);

private:
    bool searchMemory(pid_t pid, const std::string& pattern);
};
