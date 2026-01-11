#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

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

int main(int argc, char** argv) {
    size_t allocMb = 64;
    int sleepMs = 5000;
    size_t patternLen = 64;
    uint32_t seed = 0x12345678u;
    std::string overridePattern;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto requireValue = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << flag << "\n";
                std::exit(2);
            }
            return argv[++i];
        };

        if (arg == "--alloc-mb") {
            allocMb = std::stoull(requireValue("--alloc-mb"));
        } else if (arg == "--sleep-ms") {
            sleepMs = std::stoi(requireValue("--sleep-ms"));
        } else if (arg == "--pattern-len") {
            patternLen = std::stoull(requireValue("--pattern-len"));
        } else if (arg == "--seed") {
            seed = static_cast<uint32_t>(std::stoul(requireValue("--seed")));
        } else if (arg == "--pattern") {
            overridePattern = requireValue("--pattern");
        } else if (arg == "--help") {
            std::cout
                << "target_process options:\n"
                << "  --alloc-mb <n>       Allocate n MiB (default 64)\n"
                << "  --sleep-ms <ms>      Sleep time (default 5000)\n"
                << "  --pattern <str>      Override pattern string\n"
                << "  --pattern-len <n>    Deterministic pattern length (default 64)\n"
                << "  --seed <u32>         Deterministic pattern seed (default 0x12345678)\n";
            return 0;
        } else {
            std::cerr << "Unknown arg: " << arg << "\n";
            return 2;
        }
    }

    size_t totalBytes = allocMb * 1024ULL * 1024ULL;
    if (totalBytes == 0) {
        totalBytes = 1;
    }

    std::vector<char> buffer(totalBytes, 'A');

    if (!overridePattern.empty()) {
        if (overridePattern.size() > buffer.size()) {
            std::cerr << "Pattern longer than buffer\n";
            return 2;
        }
        std::memcpy(buffer.data() + (buffer.size() - overridePattern.size()),
                    overridePattern.data(),
                    overridePattern.size());
    } else {
        if (patternLen > buffer.size()) {
            patternLen = buffer.size();
        }

        uint32_t state = seed;
        size_t offset = buffer.size() - patternLen;
        for (size_t i = 0; i < patternLen; ++i) {
            buffer[offset + i] = nextPatternChar(state);
        }
    }

    std::cerr << "target_process ready"
              << " alloc_mb=" << allocMb
              << " sleep_ms=" << sleepMs
              << " pid=" << ::getpid()
              << "\n";

    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    return 0;
}
