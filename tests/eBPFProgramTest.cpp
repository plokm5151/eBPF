// tests/eBPFProgramTest.cpp

#include <gtest/gtest.h>
#include "eBPFProgram.h"
#include <optional>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <cstdlib>

TEST(eBPFProgramTest, StartAndStop) {
    if (geteuid() != 0) {
        GTEST_SKIP() << "Requires root (or CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN depending on kernel)";
    }

    eBPFProgram program;

    // Verify start/stop.
    try {
        program.start();
    } catch (const std::exception& e) {
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
        GTEST_SKIP() << "Failed to start eBPF program: " << e.what();
    }

    // Trigger an execve ("/bin/true").
    int rc = std::system("/bin/true");
    (void)rc;

    // Find the matching event.
    std::optional<ProcessInfo> matched;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        auto event = program.waitNextProcessEvent(std::chrono::milliseconds(200));
        if (event && event->filePath == "/bin/true") {
            matched = std::move(event);
            break;
        }
    }

    ASSERT_TRUE(matched.has_value());
    EXPECT_GT(matched->pid, 0);
    EXPECT_EQ(matched->uid, geteuid());
    EXPECT_EQ(matched->gid, getegid());
    EXPECT_FALSE(matched->comm.empty());
    EXPECT_EQ(matched->filePath, "/bin/true");

    program.stop();
}
