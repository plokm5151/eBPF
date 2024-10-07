# src/CMakeLists.txt

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${LIBBPF_INCLUDE_DIRS})

add_library(core
    eBPFProgram.cpp
    ProcessScanner.cpp
    Logger.cpp
    JSONWriter.cpp
)

add_dependencies(core bpf_target)

target_link_libraries(core
    ${LIBBPF_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    nlohmann_json::nlohmann_json
)

add_executable(realtime_detection main.cpp)

target_link_libraries(realtime_detection
    core
)
