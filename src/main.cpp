#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>
#include "eBPFProgram.h"
#include "ProcessScanner.h"
#include "Logger.h"


struct Options {
    std::string watchPrefix = "/usr/local/bin";
    std::string pattern = "i am a shellcode";
    size_t workers = 1;
    size_t maxEvents = 0;     // 0 = run forever
    int timeoutMs = 0;        // 0 = no timeout
    int scanDelayMs = 0;      // delay before scanning
};

static std::string tryReadProcExe(pid_t pid) {
    std::string linkPath = "/proc/" + std::to_string(pid) + "/exe";
    std::vector<char> buffer(4096);
    ssize_t n = ::readlink(linkPath.c_str(), buffer.data(), buffer.size() - 1);
    if (n <= 0) {
        return {};
    }
    buffer[static_cast<size_t>(n)] = '\0';
    return std::string(buffer.data());
}

static void printUsage(const char* argv0) {
    std::cout
        << "Usage: " << argv0 << " [options]\n"
        << "\n"
        << "Options:\n"
        << "  --watch-prefix <path>   Only scan exec paths with this prefix (default /usr/local/bin)\n"
        << "  --pattern <str>         Pattern to search in process memory\n"
        << "  --workers <n>            Scanner worker threads (default 1)\n"
        << "  --max-events <n>         Stop after n matched events (default 0 = forever)\n"
        << "  --timeout-ms <ms>        Stop after ms (default 0 = forever)\n"
        << "  --scan-delay-ms <ms>     Sleep before scanning to let the process initialize\n"
        << "  --help                   Show this help\n";
}

static Options parseArgs(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto requireValue = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string("Missing value for ") + flag);
            }
            return argv[++i];
        };

        if (arg == "--watch-prefix") {
            opt.watchPrefix = requireValue("--watch-prefix");
        } else if (arg == "--pattern") {
            opt.pattern = requireValue("--pattern");
        } else if (arg == "--workers") {
            opt.workers = std::stoull(requireValue("--workers"));
        } else if (arg == "--max-events") {
            opt.maxEvents = std::stoull(requireValue("--max-events"));
        } else if (arg == "--timeout-ms") {
            opt.timeoutMs = std::stoi(requireValue("--timeout-ms"));
        } else if (arg == "--scan-delay-ms") {
            opt.scanDelayMs = std::stoi(requireValue("--scan-delay-ms"));
        } else if (arg == "--help") {
            printUsage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("Unknown arg: " + arg);
        }
    }

    if (opt.workers == 0) {
        throw std::runtime_error("--workers must be >= 1");
    }
    if (opt.timeoutMs < 0) {
        throw std::runtime_error("--timeout-ms must be >= 0");
    }
    if (opt.scanDelayMs < 0) {
        throw std::runtime_error("--scan-delay-ms must be >= 0");
    }
    return opt;
}

int main(int argc, char** argv) {
    // Initialize logger singleton.
    auto& logger = Logger::getInstance();

    try {
        Options opt = parseArgs(argc, argv);

        // Initialize eBPF program.
        auto ebpfProgram = std::make_unique<eBPFProgram>();

        // Start eBPF program.
        ebpfProgram->start();

        std::mutex jsonMutex;
        std::atomic<size_t> matchedEvents{0};
        std::atomic<size_t> foundEvents{0};
        std::atomic<bool> stop{false};

        auto workerFn = [&]() {
            ProcessScanner scanner;

            while (!stop.load()) {
                auto processInfo = ebpfProgram->waitNextProcessEvent(std::chrono::milliseconds(200));
                if (!processInfo) {
                    if (!ebpfProgram->isRunning()) {
                        break;
                    }
                    continue;
                }

                bool matchesPrefix = processInfo->filePath.rfind(opt.watchPrefix, 0) == 0;
                std::string procExe;
                if (!matchesPrefix) {
                    procExe = tryReadProcExe(processInfo->pid);
                    if (!procExe.empty()) {
                        matchesPrefix = procExe.rfind(opt.watchPrefix, 0) == 0;
                    }
                }
                if (!matchesPrefix) {
                    continue;
                }

                size_t current = matchedEvents.fetch_add(1) + 1;
                std::string logLine =
                    "Matched exec: pid=" + std::to_string(processInfo->pid) +
                    " uid=" + std::to_string(processInfo->uid) +
                    " gid=" + std::to_string(processInfo->gid) +
                    " comm=" + processInfo->comm +
                    " path=" + processInfo->filePath;
                if (!procExe.empty() && procExe != processInfo->filePath) {
                    logLine += " exe=" + procExe;
                }
                logger.logInfo(logLine);

                if (opt.scanDelayMs > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(opt.scanDelayMs));
                }

                bool found = scanner.scanProcess(processInfo->pid, opt.pattern);
                if (found) {
                    foundEvents.fetch_add(1);
                    std::lock_guard<std::mutex> lock(jsonMutex);
                    scanner.saveScanResult(*processInfo);
                    logger.logInfo("Pattern FOUND for pid=" + std::to_string(processInfo->pid));
                } else {
                    logger.logInfo("Pattern not found for pid=" + std::to_string(processInfo->pid));
                }

                if (opt.maxEvents > 0 && current >= opt.maxEvents) {
                    stop.store(true);
                    ebpfProgram->stop();
                    break;
                }
            }
        };

        std::vector<std::thread> workers;
        workers.reserve(opt.workers);
        for (size_t i = 0; i < opt.workers; ++i) {
            workers.emplace_back(workerFn);
        }

        auto startedAt = std::chrono::steady_clock::now();
        while (!stop.load()) {
            if (opt.timeoutMs > 0) {
                auto elapsed = std::chrono::steady_clock::now() - startedAt;
                if (elapsed >= std::chrono::milliseconds(opt.timeoutMs)) {
                    stop.store(true);
                    ebpfProgram->stop();
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        for (auto& t : workers) {
            t.join();
        }

        logger.logInfo("Matched events: " + std::to_string(matchedEvents.load()) +
                       ", found pattern: " + std::to_string(foundEvents.load()));

    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        logger.logError(e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
