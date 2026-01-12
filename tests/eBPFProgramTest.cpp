// tests/eBPFProgramTest.cpp

#include <gtest/gtest.h>
#include "eBPFProgram.h"
#include <optional>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <sys/wait.h>

TEST(eBPFProgramTest, StartAndStop) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root (or CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN depending on kernel)";
    }

    eBPFProgram program;

    // Verify start/stop.
    try {
        program.start();
    } catch (const std::exception& e) {
        if (std::getenv("CI")) {
            FAIL() << "Failed to start eBPF program in CI: " << e.what();
        }
        GTEST_SKIP() << "Failed to start eBPF program: " << e.what();
    }
    EXPECT_TRUE(program.isRunning());

    program.stop();
    EXPECT_FALSE(program.isRunning());
}

TEST(eBPFProgramTest, EventProcessing) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root (or CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN depending on kernel)";
    }

    eBPFProgram program;
    try {
        program.start();
    } catch (const std::exception& e) {
        if (std::getenv("CI")) {
            FAIL() << "Failed to start eBPF program in CI: " << e.what();
        }
        GTEST_SKIP() << "Failed to start eBPF program: " << e.what();
    }

    // Trigger an execve("/bin/true") in a child, so we can match by PID reliably.
    pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ::execl("/bin/true", "/bin/true", static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);

    // Find the matching event.
    std::optional<ProcessInfo> matched;
    std::string observed;
    size_t observedCount = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        auto event = program.waitNextProcessEvent(std::chrono::milliseconds(200));
        if (!event) {
            continue;
        }
        if (observedCount < 25) {
            observed += "pid=" + std::to_string(event->pid) + " comm=" + event->comm +
                        " filePath=" + event->filePath + "\n";
            ++observedCount;
        }
        if (event->pid == child &&
            (event->filePath == "/bin/true" || event->filePath == "/usr/bin/true")) {
            matched = std::move(event);
            break;
        }
    }

    ASSERT_TRUE(matched.has_value()) << "No matching exec event for pid=" << child
                                     << " within timeout; first events:\n"
                                     << observed;
    EXPECT_EQ(matched->pid, child);
    EXPECT_EQ(matched->uid, geteuid());
    EXPECT_EQ(matched->gid, getegid());
    EXPECT_FALSE(matched->comm.empty());
    EXPECT_TRUE(matched->filePath == "/bin/true" || matched->filePath == "/usr/bin/true");

    program.stop();
}
