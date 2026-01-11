#include "ProcessScanner.h"
#include "Logger.h"
#include "JSONWriter.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>
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
    // Parse /proc/<pid>/maps to enumerate memory regions.
    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        throw std::runtime_error("Failed to open maps file for pid: " + std::to_string(pid));
    }

    std::string line;

    if (pattern.empty()) {
        return false;
    }

    constexpr size_t kChunkSize = 1 * 1024 * 1024; // 1 MiB
    std::vector<char> buffer(kChunkSize);
    std::string carry;
    carry.reserve(pattern.size() > 0 ? pattern.size() - 1 : 0);

    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string address;
        std::string perms;
        if (!(iss >> address >> perms)) {
            continue;
        }

        if (perms.empty() || perms[0] != 'r') {
            continue;
        }

        // Parse address range.
        size_t dashPos = address.find('-');
        if (dashPos == std::string::npos) {
            continue;
        }

        uintptr_t start = std::stoul(address.substr(0, dashPos), nullptr, 16);
        uintptr_t end = std::stoul(address.substr(dashPos + 1), nullptr, 16);
        size_t size = end > start ? static_cast<size_t>(end - start) : 0;
        if (size == 0) {
            continue;
        }

        carry.clear();

        for (size_t offset = 0; offset < size; offset += kChunkSize) {
            size_t toRead = std::min(kChunkSize, size - offset);

            struct iovec local_iov = { buffer.data(), toRead };
            struct iovec remote_iov = { reinterpret_cast<void*>(start + offset), toRead };

            ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
            if (nread <= 0) {
                break;
            }

            std::string combined;
            combined.reserve(carry.size() + static_cast<size_t>(nread));
            combined.append(carry);
            combined.append(buffer.data(), static_cast<size_t>(nread));

            if (combined.find(pattern) != std::string::npos) {
                return true;
            }

            if (pattern.size() > 1) {
                size_t keep = std::min(pattern.size() - 1, combined.size());
                carry.assign(combined.end() - static_cast<std::ptrdiff_t>(keep), combined.end());
            }
        }
    }

    return false;
}

void ProcessScanner::saveScanResult(const ProcessInfo& processInfo) {
    JSONWriter jsonWriter;
    jsonWriter.writeProcessInfo(processInfo);
}
