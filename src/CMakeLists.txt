add_library(core
    eBPFProgram.cpp
    ProcessScanner.cpp
    Logger.cpp
    JSONWriter.cpp
)

add_dependencies(core bpf_target)

target_include_directories(core
    PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
    PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${LIBBPF_INCLUDE_DIRS}"
        "${EBPF_GENERATED_DIR}"
)

target_link_libraries(core
    PRIVATE
        "${LIBBPF_LIBRARIES}"
        Threads::Threads
        nlohmann_json::nlohmann_json
)

add_executable(realtime_detection main.cpp)

target_link_libraries(realtime_detection PRIVATE core)
