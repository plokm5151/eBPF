add_executable(ebpf_scan_bench ebpf_scan_bench.cpp)

target_compile_features(ebpf_scan_bench PRIVATE cxx_std_17)

target_include_directories(ebpf_scan_bench
    PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries(ebpf_scan_bench PRIVATE core)
