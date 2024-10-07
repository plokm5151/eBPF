// tests/JSONWriterTest.cpp

#include <gtest/gtest.h>
#include "JSONWriter.h"
#include <fstream>
#include <nlohmann/json.hpp>

TEST(JSONWriterTest, WriteProcessInfo) {
    JSONWriter writer;
    ProcessInfo info;
    info.pid = 1234;
    info.gid = 1000;
    info.filePath = "/usr/bin/test_process";

    // 刪除結果文件
    std::remove("scan_results.json");

    writer.writeProcessInfo(info);

    // 讀取生成的 JSON 文件
    std::ifstream jsonFile("scan_results.json");
    ASSERT_TRUE(jsonFile.is_open());

    nlohmann::json j;
    jsonFile >> j;
    jsonFile.close();

    // 檢查 JSON 內容
    EXPECT_EQ(j["pid"], info.pid);
    EXPECT_EQ(j["gid"], info.gid);
    EXPECT_EQ(j["filePath"], info.filePath);
}
