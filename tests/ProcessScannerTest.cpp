// tests/ProcessScannerTest.cpp

#include <gtest/gtest.h>
#include "ProcessScanner.h"
#include <unistd.h>

TEST(ProcessScannerTest, ScanExistingProcess) {
    ProcessScanner scanner;
    pid_t pid = getpid(); // Get current process PID.
    std::string pattern = "ProcessScannerTest";

    bool result = scanner.scanProcess(pid, pattern);

    // The current process address space should contain the literal "ProcessScannerTest".
    EXPECT_TRUE(result);
}

TEST(ProcessScannerTest, ScanNonExistingProcess) {
    ProcessScanner scanner;
    pid_t pid = 999999; // Assume this PID doesn't exist.
    std::string pattern = "TestPattern";

    bool result = scanner.scanProcess(pid, pattern);

    // Scan should fail or return false.
    EXPECT_FALSE(result);
}

TEST(ProcessScannerTest, ScanWithEmptyPattern) {
    ProcessScanner scanner;
    pid_t pid = getpid();
    EXPECT_FALSE(scanner.scanProcess(pid, ""));
}
