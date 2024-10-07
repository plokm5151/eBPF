# tests/CMakeLists.txt

cmake_minimum_required(VERSION 3.10)

# 添加測試可執行文件
add_executable(runTests
    LoggerTest.cpp
    ProcessScannerTest.cpp
    JSONWriterTest.cpp
    eBPFProgramTest.cpp
)

# 包含源代碼目錄和第三方庫
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/ebpf)
include_directories(${LIBBPF_INCLUDE_DIRS})

# 連接需要測試的庫和第三方庫
target_link_libraries(runTests
    core
    gtest
    gtest_main
    pthread
    ${LIBBPF_LIBRARIES}
    nlohmann_json::nlohmann_json
)
