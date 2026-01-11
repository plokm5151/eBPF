#include "JSONWriter.h"
#include "ProcessScanner.h"
#include "eBPFProgram.h"

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <limits.h>
#include <sys/wait.h>
#include <unistd.h>

static uint32_t xorshift32(uint32_t& state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

static char nextPatternChar(uint32_t& state) {
    static constexpr char kAlphabet[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    constexpr size_t kAlphabetLen = sizeof(kAlphabet) - 1;
    return kAlphabet[xorshift32(state) % kAlphabetLen];
}

static std::string generatePattern(size_t len, uint32_t seed) {
    std::string pattern;
    pattern.resize(len);
    uint32_t state = seed;
    for (size_t i = 0; i < len; ++i) {
        pattern[i] = nextPatternChar(state);
    }
    return pattern;
}

static std::string getSelfDir() {
    char path[PATH_MAX] = {};
    ssize_t n = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n <= 0) {
        return ".";
    }
    path[n] = '\0';
    std::string full(path);
    auto pos = full.find_last_of('/');
    if (pos == std::string::npos) {
        return ".";
    }
    return full.substr(0, pos);
}

static std::string realpathOrDie(const std::string& p) {
    char out[PATH_MAX] = {};
    if (!::realpath(p.c_str(), out)) {
        std::cerr << "realpath failed for: " << p << "\n";
        std::exit(2);
    }
    return std::string(out);
}

static void killAndReap(const std::vector<pid_t>& pids) {
    for (pid_t pid : pids) {
        if (pid > 0) {
            ::kill(pid, SIGTERM);
        }
    }
    for (pid_t pid : pids) {
        if (pid <= 0) {
            continue;
        }
        int status = 0;
        (void)::waitpid(pid, &status, 0);
    }
}

int main(int argc, char** argv) {
    size_t workers = 1;
    size_t processes = 8;
    size_t allocMb = 64;
    int sleepMs = 15000;
    int scanDelayMs = 100;
    int timeoutMs = 30000;
    size_t patternLen = 64;
    uint32_t seed = 0x12345678u;
    bool writeJson = true;

    std::string targetPath = getSelfDir() + "/../tools/target_process";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto requireValue = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << flag << "\n";
                std::exit(2);
            }
            return argv[++i];
        };

        if (arg == "--workers") {
            workers = std::stoull(requireValue("--workers"));
        } else if (arg == "--processes") {
            processes = std::stoull(requireValue("--processes"));
        } else if (arg == "--alloc-mb") {
            allocMb = std::stoull(requireValue("--alloc-mb"));
        } else if (arg == "--sleep-ms") {
            sleepMs = std::stoi(requireValue("--sleep-ms"));
        } else if (arg == "--scan-delay-ms") {
            scanDelayMs = std::stoi(requireValue("--scan-delay-ms"));
        } else if (arg == "--timeout-ms") {
            timeoutMs = std::stoi(requireValue("--timeout-ms"));
        } else if (arg == "--pattern-len") {
            patternLen = std::stoull(requireValue("--pattern-len"));
        } else if (arg == "--seed") {
            seed = static_cast<uint32_t>(std::stoul(requireValue("--seed")));
        } else if (arg == "--target") {
            targetPath = requireValue("--target");
        } else if (arg == "--no-json") {
            writeJson = false;
        } else if (arg == "--help") {
            std::cout
                << "ebpf_scan_bench options:\n"
                << "  --workers <n>        Scanner worker threads (default 1)\n"
                << "  --processes <n>      Number of target processes (default 8)\n"
                << "  --alloc-mb <n>       Target process allocation (default 64)\n"
                << "  --sleep-ms <ms>      Target process lifetime (default 15000)\n"
                << "  --scan-delay-ms <ms> Delay before scanning (default 100)\n"
                << "  --timeout-ms <ms>    Overall timeout (default 30000)\n"
                << "  --pattern-len <n>    Pattern length (default 64)\n"
                << "  --seed <u32>         Pattern seed (default 0x12345678)\n"
                << "  --target <path>      Path to target_process (default ../tools/target_process)\n"
                << "  --no-json            Do not write scan_results.json\n";
            return 0;
        } else {
            std::cerr << "Unknown arg: " << arg << "\n";
            return 2;
        }
    }

    if (workers == 0) {
        std::cerr << "--workers must be >= 1\n";
        return 2;
    }
    if (processes == 0) {
        std::cerr << "--processes must be >= 1\n";
        return 2;
    }

    std::string targetAbs = realpathOrDie(targetPath);
    std::string pattern = generatePattern(patternLen, seed);

    std::cerr << "ebpf_scan_bench config"
              << " workers=" << workers
              << " processes=" << processes
              << " alloc_mb=" << allocMb
              << " scan_delay_ms=" << scanDelayMs
              << " timeout_ms=" << timeoutMs
              << " target=" << targetAbs
              << "\n";

    if (writeJson) {
        std::remove("scan_results.json");
    }

    eBPFProgram program;
    try {
        program.start();
    } catch (const std::exception& e) {
        std::cerr << "Failed to start eBPFProgram: " << e.what() << "\n";
        return 2;
    }

    std::vector<pid_t> children;
    children.reserve(processes);
    for (size_t i = 0; i < processes; ++i) {
        pid_t pid = ::fork();
        if (pid == 0) {
            std::string allocArg = std::to_string(allocMb);
            std::string sleepArg = std::to_string(sleepMs);
            std::string patternLenArg = std::to_string(patternLen);
            std::string seedArg = std::to_string(seed);

            ::execl(
                targetAbs.c_str(),
                targetAbs.c_str(),
                "--alloc-mb",
                allocArg.c_str(),
                "--sleep-ms",
                sleepArg.c_str(),
                "--pattern-len",
                patternLenArg.c_str(),
                "--seed",
                seedArg.c_str(),
                static_cast<char*>(nullptr)
            );
            std::perror("execl");
            std::exit(127);
        }
        if (pid < 0) {
            std::perror("fork");
            program.stop();
            killAndReap(children);
            return 2;
        }
        children.push_back(pid);
    }

    std::mutex remainingMutex;
    std::unordered_set<pid_t> remaining(children.begin(), children.end());

    std::mutex jsonMutex;
    std::mutex logMutex;
    JSONWriter writer;

    std::atomic<size_t> scannedOk{0};
    std::atomic<size_t> scannedFail{0};
    std::atomic<size_t> eventsMatched{0};
    std::atomic<bool> done{false};

    auto startedAt = std::chrono::steady_clock::now();
    auto deadline = startedAt + std::chrono::milliseconds(timeoutMs);

    auto workerFn = [&]() {
        ProcessScanner scanner;

        while (!done.load()) {
            if (std::chrono::steady_clock::now() > deadline) {
                break;
            }

            auto event = program.waitNextProcessEvent(std::chrono::milliseconds(200));
            if (!event) {
                continue;
            }

            bool shouldScan = false;
            bool pathMismatch = false;
            {
                std::lock_guard<std::mutex> lock(remainingMutex);
                if (remaining.erase(event->pid) > 0) {
                    shouldScan = true;
                    pathMismatch = (event->filePath != targetAbs);
                }
            }
            if (!shouldScan) {
                continue;
            }

            if (pathMismatch) {
                std::lock_guard<std::mutex> lock(logMutex);
                std::cerr << "warning: exec path mismatch"
                          << " pid=" << event->pid
                          << " expected=" << targetAbs
                          << " got=" << event->filePath
                          << "\n";
            }

            eventsMatched.fetch_add(1);

            {
                std::lock_guard<std::mutex> lock(logMutex);
                std::cerr << "captured"
                          << " pid=" << event->pid
                          << " uid=" << event->uid
                          << " gid=" << event->gid
                          << " comm=" << event->comm
                          << " filePath=" << event->filePath
                          << "\n";
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(scanDelayMs));

            bool found = scanner.scanProcess(event->pid, pattern);
            if (found) {
                scannedOk.fetch_add(1);
                if (writeJson) {
                    std::lock_guard<std::mutex> lock(jsonMutex);
                    writer.writeProcessInfo(*event);
                }
            } else {
                scannedFail.fetch_add(1);
            }

            {
                std::lock_guard<std::mutex> lock(logMutex);
                std::cerr << "scanned"
                          << " pid=" << event->pid
                          << " result=" << (found ? "FOUND" : "NOT_FOUND")
                          << "\n";
            }

            ::kill(event->pid, SIGTERM);

            {
                std::lock_guard<std::mutex> lock(remainingMutex);
                if (remaining.empty()) {
                    done.store(true);
                }
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (size_t i = 0; i < workers; ++i) {
        threads.emplace_back(workerFn);
    }

    for (auto& t : threads) {
        t.join();
    }

    auto finishedAt = std::chrono::steady_clock::now();
    program.stop();

    killAndReap(children);

    auto elapsedMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(finishedAt - startedAt).count();
    double elapsedSec = elapsedMs / 1000.0;
    if (elapsedSec <= 0.0) {
        elapsedSec = 0.001;
    }

    size_t ok = scannedOk.load();
    size_t fail = scannedFail.load();
    size_t matched = eventsMatched.load();

    std::cerr << "ebpf_scan_bench result"
              << " matched=" << matched << "/" << processes
              << " scanned_ok=" << ok
              << " scanned_fail=" << fail
              << " elapsed_ms=" << elapsedMs
              << " throughput_proc_per_sec=" << (ok + fail) / elapsedSec
              << "\n";

    if (ok != processes) {
        std::cerr << "ERROR: not all scans succeeded\n";
        return 1;
    }

    return 0;
}
