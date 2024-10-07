// tests/ProcessScannerTest.cpp

#include <gtest/gtest.h>
#include "ProcessScanner.h"

TEST(ProcessScannerTest, ScanExistingProcess) {
    ProcessScanner scanner;
    pid_t pid = getpid(); // 獲取當前進程的 PID
    std::string pattern = "ProcessScannerTest";

    bool result = scanner.scan(pid, pattern);

    // 由於當前進程的可執行文件名稱應該包含 "ProcessScannerTest"
    EXPECT_TRUE(result);
}

TEST(ProcessScannerTest, ScanNonExistingProcess) {
    ProcessScanner scanner;
    pid_t pid = 999999; // 假設這個 PID 不存在
    std::string pattern = "TestPattern";

    bool result = scanner.scan(pid, pattern);

    // 掃描應該失敗或返回 false
    EXPECT_FALSE(result);
}

TEST(ProcessScannerTest, ScanWithMaliciousInput) {
    ProcessScanner scanner;
    pid_t pid = getpid();
    std::string pattern = "../../../../etc/passwd";

    bool result = scanner.scan(pid, pattern);

    // 應該正確處理惡意輸入，不應該崩潰或洩露信息
    EXPECT_FALSE(result);
}
