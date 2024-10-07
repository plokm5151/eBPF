// tests/LoggerTest.cpp

#include <gtest/gtest.h>
#include "Logger.h"
#include <fstream>
#include <thread>

TEST(LoggerTest, SingletonInstance) {
    Logger& logger1 = Logger::getInstance();
    Logger& logger2 = Logger::getInstance();

    // 檢查兩個引用是否指向同一instance
    EXPECT_EQ(&logger1, &logger2);
}

TEST(LoggerTest, LogInfo) {
    Logger& logger = Logger::getInstance();
    std::string testMessage = "Test Info Message";

    // 刪除日誌文件以確保測試結果
    std::remove("application.log");

    logger.logInfo(testMessage);

    std::ifstream logFile("application.log");
    ASSERT_TRUE(logFile.is_open());

    std::string line;
    std::getline(logFile, line);
    logFile.close();

    // 檢查日誌內容是否包含測試消息
    EXPECT_NE(line.find(testMessage), std::string::npos);
}

TEST(LoggerTest, ThreadSafety) {
    Logger& logger = Logger::getInstance();
    const int threadCount = 10;
    const int messagesPerThread = 100;
    std::vector<std::thread> threads;

    // 刪除logger文件以確保測試結果
    std::remove("application.log");

    // 啟動多個thread同時寫入日誌
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([&logger, i, messagesPerThread]() {
            for (int j = 0; j < messagesPerThread; ++j) {
                logger.logInfo("Thread " + std::to_string(i) + " message " + std::to_string(j));
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // 檢查logger文件的行數是否正確
    std::ifstream logFile("application.log");
    ASSERT_TRUE(logFile.is_open());

    int lineCount = 0;
    std::string line;
    while (std::getline(logFile, line)) {
        ++lineCount;
    }
    logFile.close();

    EXPECT_EQ(lineCount, threadCount * messagesPerThread);
}
