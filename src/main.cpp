#include <iostream>
#include <memory>
#include "eBPFProgram.h"
#include "ProcessScanner.h"
#include "Logger.h"


int main() {
    // 創建 Logger 單例
    auto& logger = Logger::getInstance();

    try {
        // 初始化 eBPF 程式
        auto ebpfProgram = std::make_unique<eBPFProgram>();

        // 啟動 eBPF 程式
        ebpfProgram->start();

        // 創建 ProcessScanner
        auto processScanner = std::make_unique<ProcessScanner>();

        // 主循環，等待 eBPF 程式的事件
        while (true) {
            // 從 eBPF 程式獲取新啟動的行程資訊
            auto processInfo = ebpfProgram->getNextProcessEvent();

            if (processInfo) {
                // 如果路徑符合條件，進行記憶體掃描
                if (processInfo->filePath.find("/usr/local/bin") == 0) {
                    bool found = processScanner->scanProcess(processInfo->pid, "i am a shellcode");

                    if (found) {
                        // 將結果輸出為 JSON
                        processScanner->saveScanResult(*processInfo);
                    }
                }
            }

            // 可以根據需要添加退出條件或休眠時間
        }

    } catch (const std::exception& e) {
        logger.logError(e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
