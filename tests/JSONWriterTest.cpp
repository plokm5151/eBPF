// tests/JSONWriterTest.cpp

#include <gtest/gtest.h>
#include "JSONWriter.h"
#include <fstream>
#include <nlohmann/json.hpp>

TEST(JSONWriterTest, WriteProcessInfo) {
    JSONWriter writer;
    ProcessInfo info;
    info.pid = 1234;
    info.uid = 1000;
    info.gid = 1000;
    info.comm = "test_process";
    info.filePath = "/usr/bin/test_process";

    // Delete previous output file.
    std::remove("scan_results.json");

    writer.writeProcessInfo(info);

    // Read the generated JSON file.
    std::ifstream jsonFile("scan_results.json");
    ASSERT_TRUE(jsonFile.is_open());

    nlohmann::json j;
    jsonFile >> j;
    jsonFile.close();

    // Validate JSON contents.
    EXPECT_EQ(j["pid"], info.pid);
    EXPECT_EQ(j["uid"], info.uid);
    EXPECT_EQ(j["gid"], info.gid);
    EXPECT_EQ(j["comm"], info.comm);
    EXPECT_EQ(j["filePath"], info.filePath);
}
