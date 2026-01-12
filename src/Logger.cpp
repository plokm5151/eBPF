#include "Logger.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>



Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() {
    logFile_.open("application.log", std::ios::app);
}

Logger::~Logger() {
    if (logFile_.is_open()) {
        logFile_.close();
    }
}

void Logger::logLine(const char* level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm {};
    localtime_r(&now, &tm);
    logFile_ << "[" << level << "] " << std::put_time(&tm, "%F %T") << ": " << message << '\n';
    logFile_.flush();
}

void Logger::logInfo(const std::string& message) {
    logLine("INFO", message);
}

void Logger::logError(const std::string& message) {
    logLine("ERROR", message);
}
