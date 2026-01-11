# RealtimeProcessDetection (eBPF + Memory Scan Demo)

Linux-only demo project that:
- Captures process `execve` events via eBPF + libbpf (user-space skeleton).
- Optionally scans the new process memory for a user-provided string pattern.
- Writes findings to `scan_results.json` and logs to `application.log`.

This is designed to showcase:
1) eBPF reliably capturing process execution metadata, and
2) multi-threaded user-space processing/scanning throughput.

## Repository Layout
- `ebpf/`: eBPF program (`exec_monitor.bpf.c`) + CMake rules to build BPF object, generate skeleton, and generate `vmlinux.h`
- `src/`: user-space core (`realtime_detection`) + supporting classes
- `include/`: shared structs (e.g. `ProcessInfo`)
- `tests/`: unit tests (GTest)
- `tools/`: helper binaries used by experiments (`target_process`)
- `experiments/`: end-to-end experiments / benchmarks (`ebpf_scan_bench`)
- `.github/workflows/`: CI pipelines (GitHub Actions)

## Requirements
### Linux
- Kernel with BTF enabled and available at `/sys/kernel/btf/vmlinux`
- `clang` with BPF target support
- `bpftool`
- `libbpf` headers + library (e.g. `libbpf-dev`)

### Privileges
Loading eBPF programs and attaching tracepoints typically requires root, or the appropriate capabilities
(kernel/config dependent). The CI runs as root for simplicity.

Memory scanning uses `process_vm_readv()`; reading other processes may be restricted by:
- UID mismatch (unless root)
- `kernel.yama.ptrace_scope`
- container/LSM policies

## Build
### Default (FetchContent)
By default, CMake fetches `nlohmann/json` and `googletest` via `FetchContent`:
```sh
cmake -S . -B build_linux -DCMAKE_BUILD_TYPE=Release -DRPD_BUILD_TOOLS=ON -DRPD_BUILD_EXPERIMENTS=ON
cmake --build build_linux -j
```

### Offline (no network)
Install deps via your package manager, then:
```sh
cmake -S . -B build_linux -DCMAKE_BUILD_TYPE=Release -DRPD_FETCH_DEPS=OFF -DRPD_BUILD_TOOLS=ON -DRPD_BUILD_EXPERIMENTS=ON
cmake --build build_linux -j
```

### Useful CMake options
- `-DRPD_FETCH_DEPS=ON|OFF`: fetch third-party deps via `FetchContent`
- `-DRPD_BUILD_TOOLS=ON|OFF`: build `tools/*`
- `-DRPD_BUILD_EXPERIMENTS=ON|OFF`: build `experiments/*`
- `-DBUILD_TESTING=ON|OFF`: build tests

## Run: realtime_detection
Print available flags:
```sh
sudo ./build_linux/src/realtime_detection --help
```

### Output
- `application.log`: runtime logs (matched events, scan results)
- `scan_results.json`: appended JSON objects (one per matched + pattern-found event)

### End-to-end demo (deterministic)
This demo starts the detector, then launches a helper process that contains a known pattern in memory.
```sh
rm -f scan_results.json application.log
WATCH_PREFIX="$(realpath build_linux/tools)"

sudo ./build_linux/src/realtime_detection \
  --watch-prefix "$WATCH_PREFIX" \
  --pattern "i am a shellcode" \
  --workers 2 \
  --scan-delay-ms 200 \
  --max-events 1 \
  --timeout-ms 15000 &

sudo ./build_linux/tools/target_process --alloc-mb 32 --sleep-ms 8000 --pattern "i am a shellcode"
```

## Experiments
### tools/target_process
Helper binary that allocates a buffer and embeds a known pattern (used for memory-scan validation).

### experiments/ebpf_scan_bench
Validates that:
- eBPF captures `execve` events for a known target binary, and
- the scanner threads can find a deterministic pattern in those processes.

It prints a concise summary including throughput.
Example:
```sh
sudo ./build_linux/experiments/ebpf_scan_bench --workers 1 --processes 8 --alloc-mb 64 --scan-delay-ms 200
sudo ./build_linux/experiments/ebpf_scan_bench --workers 4 --processes 8 --alloc-mb 64 --scan-delay-ms 200
```

## CI (GitHub Actions)
Workflow: `.github/workflows/ci-linux.yml`

What CI does on Ubuntu 22.04 and 24.04:
1) Builds the project (including eBPF skeleton generation).
2) Runs unit tests as root (`runTests`).
3) Runs an end-to-end demo that produces and parses `scan_results.json`.
4) Runs a multi-thread benchmark (`--workers 1` vs `--workers 4`) and generates `ci_logs/bench_summary.txt`.
5) Uploads all logs under `ci_logs/` as an artifact for inspection.

To inspect results:
- Go to GitHub Actions → open a run → download the `ci-logs-ubuntu-*` artifact.

## Notes / Troubleshooting
- If eBPF fails to load/attach, check kernel support and privileges. CI logs include kernel/BTF details.
- If memory scanning returns false unexpectedly, try increasing `--scan-delay-ms` to allow the process to initialize.
