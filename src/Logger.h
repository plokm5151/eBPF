#pragma once

#include <string>
#include <fstream>
#include <mutex>


class Logger {
public:
    static Logger& getInstance();

    void logInfo(const std::string& message);
    void logError(const std::string& message);

private:
    Logger();
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void logLine(const char* level, const std::string& message);

    std::ofstream logFile_;
    std::mutex mutex_;
};
