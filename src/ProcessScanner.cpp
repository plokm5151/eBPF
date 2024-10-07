#include "ProcessScanner.h"
#include "Logger.h"
#include "JSONWriter.h"
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>


bool ProcessScanner::scanProcess(pid_t pid, const std::string& pattern) {
    auto& logger = Logger::getInstance();
    try {
        return searchMemory(pid, pattern);
    } catch (const std::exception& e) {
        logger.logError(e.what());
        return false;
    }
}

bool ProcessScanner::searchMemory(pid_t pid, const std::string& pattern) {
    // 打開 /proc/<pid>/mem
    std::string memPath = "/proc/" + std::to_string(pid) + "/mem";
    int memFd = open(memPath.c_str(), O_RDONLY);
    if (memFd == -1) {
        throw std::runtime_error("Failed to open memory file for pid: " + std::to_string(pid));
    }

    // 打開 /proc/<pid>/maps 以獲取記憶體區段
    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        close(memFd);
        throw std::runtime_error("Failed to open maps file for pid: " + std::to_string(pid));
    }

    std::string line;
    bool found = false;
    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string address;
        if (!(iss >> address)) {
            continue;
        }

        // 解析地址範圍
        size_t dashPos = address.find('-');
        if (dashPos == std::string::npos) {
            continue;
        }

        uintptr_t start = std::stoul(address.substr(0, dashPos), nullptr, 16);
        uintptr_t end = std::stoul(address.substr(dashPos + 1), nullptr, 16);
        size_t size = end - start;

        // 讀取記憶體內容
        std::vector<char> buffer(size);
        struct iovec local_iov = { buffer.data(), size };
        struct iovec remote_iov = { reinterpret_cast<void*>(start), size };

        ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (nread <= 0) {
            continue;
        }

        // 搜尋模式
        std::string memContent(buffer.data(), nread);
        if (memContent.find(pattern) != std::string::npos) {
            found = true;
            break;
        }
    }

    close(memFd);
    return found;
}

void ProcessScanner::saveScanResult(const ProcessInfo& processInfo) {
    JSONWriter jsonWriter;
    jsonWriter.writeProcessInfo(processInfo);
}
