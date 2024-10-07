# 根目錄的 CMakeLists.txt

cmake_minimum_required(VERSION 3.10)

project(RealtimeProcessDetection)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加 cmake/ 目錄到 CMAKE_MODULE_PATH
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(LibBPF REQUIRED)

# 添加子目錄
add_subdirectory(ebpf)
add_subdirectory(src)
add_subdirectory(tests)
