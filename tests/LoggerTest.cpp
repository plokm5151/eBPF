// tests/LoggerTest.cpp

#include <gtest/gtest.h>
#include "Logger.h"
#include <fstream>
#include <thread>
#include <vector>

TEST(LoggerTest, SingletonInstance) {
    Logger& logger1 = Logger::getInstance();
    Logger& logger2 = Logger::getInstance();

    // Ensure both references point to the same instance.
    EXPECT_EQ(&logger1, &logger2);
}

TEST(LoggerTest, LogInfo) {
    Logger& logger = Logger::getInstance();
    std::string testMessage = "Test Info Message";

    // Truncate log file (avoid unlink; the singleton keeps the same fd).
    std::ofstream truncate("application.log", std::ios::trunc);
    truncate.close();

    logger.logInfo(testMessage);

    std::ifstream logFile("application.log");
    ASSERT_TRUE(logFile.is_open());

    std::string line;
    std::getline(logFile, line);
    logFile.close();

    // Ensure the log contains the test message.
    EXPECT_NE(line.find(testMessage), std::string::npos);
}

TEST(LoggerTest, ThreadSafety) {
    Logger& logger = Logger::getInstance();
    const int threadCount = 10;
    const int messagesPerThread = 100;
    std::vector<std::thread> threads;

    std::ofstream truncate("application.log", std::ios::trunc);
    truncate.close();

    // Start multiple threads writing logs concurrently.
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

    // Check that the line count matches expectations.
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
