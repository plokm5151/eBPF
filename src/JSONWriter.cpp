// src/JSONWriter.cpp
#include "JSONWriter.h"
#include <nlohmann/json.hpp>
#include <fstream>

void JSONWriter::writeProcessInfo(const ProcessInfo& processInfo) {
    nlohmann::json j;
    j["pid"] = processInfo.pid;
    j["uid"] = processInfo.uid;
    j["gid"] = processInfo.gid;
    j["comm"] = processInfo.comm;
    j["filePath"] = processInfo.filePath;

    // Keep this file valid JSON (single object) even if multiple matches are written.
    std::ofstream outFile("scan_results.json", std::ios::trunc);
    outFile << j.dump(4) << std::endl;
}
