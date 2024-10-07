#include "Logger.h"
#include <iostream>
#include <chrono>
#include <ctime>



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

void Logger::logInfo(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    logFile_ << "[INFO] " << std::ctime(&now) << ": " << message << std::endl;
}

void Logger::logError(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    logFile_ << "[ERROR] " << std::ctime(&now) << ": " << message << std::endl;
}
