add_executable(runTests
    LoggerTest.cpp
    ProcessScannerTest.cpp
    JSONWriterTest.cpp
    eBPFProgramTest.cpp
)

target_include_directories(runTests
    PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/include"
)

if(TARGET GTest::gtest_main)
    set(GTEST_MAIN_TARGET GTest::gtest_main)
elseif(TARGET gtest_main)
    set(GTEST_MAIN_TARGET gtest_main)
else()
    message(FATAL_ERROR "gtest_main target not found; enable RPD_FETCH_DEPS or install GTest")
endif()

target_link_libraries(runTests
    PRIVATE
        core
        nlohmann_json::nlohmann_json
        "${GTEST_MAIN_TARGET}"
        Threads::Threads
)

add_test(NAME runTests COMMAND runTests)
