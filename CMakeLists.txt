cmake_minimum_required(VERSION 3.16)

project(RealtimeProcessDetection LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project requires Linux (eBPF + /proc). Current system: ${CMAKE_SYSTEM_NAME}")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(LibBPF REQUIRED)

include(CTest) # provides BUILD_TESTING option

option(RPD_FETCH_DEPS "Fetch third-party deps via FetchContent" ON)
option(RPD_BUILD_TOOLS "Build helper tools" OFF)
option(RPD_BUILD_EXPERIMENTS "Build experiments/benchmarks" OFF)

if(RPD_FETCH_DEPS)
    include(FetchContent)

    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)

    if(BUILD_TESTING)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
        )
        FetchContent_MakeAvailable(googletest)
    endif()
else()
    find_package(nlohmann_json REQUIRED)
    if(BUILD_TESTING)
        find_package(GTest REQUIRED)
    endif()
endif()

add_subdirectory(ebpf)
add_subdirectory(src)
if(RPD_BUILD_TOOLS)
    add_subdirectory(tools)
endif()
if(RPD_BUILD_EXPERIMENTS)
    add_subdirectory(experiments)
endif()
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
