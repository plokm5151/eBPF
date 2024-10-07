// tests/eBPFProgramTest.cpp

#include <gtest/gtest.h>
#include "eBPFProgram.h"
#include <optional>

TEST(eBPFProgramTest, StartAndStop) {
    eBPFProgram program;

    // 測試啟動和停止
    program.start();
    EXPECT_TRUE(program.isRunning());

    program.stop();
    EXPECT_FALSE(program.isRunning());
}

TEST(eBPFProgramTest, EventProcessing) {
    eBPFProgram program;
    program.start();

    // 等待事件產生（可能需要手動觸發一些thread）
    // 這裡我們等待一段時間
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // 檢查是否有事件
    auto event = program.getNextProcessEvent();
    EXPECT_TRUE(event.has_value());

    if (event.has_value()) {
        ProcessInfo info = event.value();
        // 檢查 ProcessInfo 是否合理
        EXPECT_GT(info.pid, 0);
        EXPECT_GT(info.gid, 0);
        EXPECT_FALSE(info.filePath.empty());
    }

    program.stop();
}
