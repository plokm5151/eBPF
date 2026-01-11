#include "eBPFProgram.h"

#include "ExecMonitor.h"
#include "exec_monitor.skel.h"
#include "Logger.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {
template <typename T, typename = void>
struct has_member_sz : std::false_type {};
template <typename T>
struct has_member_sz<T, std::void_t<decltype(std::declval<T&>().sz)>> : std::true_type {};
template <typename T>
inline constexpr bool has_member_sz_v = has_member_sz<T>::value;

constexpr size_t kPerfBufferPageCnt = 8;

std::string formatErrno(int err) {
    if (err == 0) {
        return "0";
    }
    int e = (err < 0) ? -err : err;
    return std::to_string(err) + " (" + std::string(std::strerror(e)) + ")";
}

int libbpfPrint(enum libbpf_print_level level, const char* format, va_list args) {
    const char* ci = std::getenv("CI");
    const char* debug = std::getenv("RPD_LIBBPF_DEBUG");
    bool verbose = (debug && *debug) || (ci && *ci);

    if (!verbose && level == LIBBPF_DEBUG) {
        return 0;
    }
    return std::vfprintf(stderr, format, args);
}

perf_buffer* openPerfBuffer(int mapFd, void* ctx, perf_buffer_sample_fn sampleCb, perf_buffer_lost_fn lostCb) {
    struct perf_buffer_opts opts = {};

#if defined(perf_buffer_opts__last_field)
    // Newer libbpf API: callbacks are passed directly, opts is for extra settings.
    if constexpr (has_member_sz_v<struct perf_buffer_opts>) {
        opts.sz = sizeof(opts);
    }
    return perf_buffer__new(mapFd, kPerfBufferPageCnt, sampleCb, lostCb, ctx, &opts);
#else
    // Older libbpf API: callbacks are stored in perf_buffer_opts, and perf_buffer__new() takes 3 args.
    opts.sample_cb = sampleCb;
    opts.lost_cb = lostCb;
    opts.ctx = ctx;
    return perf_buffer__new(mapFd, kPerfBufferPageCnt, &opts);
#endif
}
} // namespace

eBPFProgram::eBPFProgram() : running_(false), skel_(nullptr), pb_(nullptr) {
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        auto& logger = Logger::getInstance();
        logger.logError("setrlimit(RLIMIT_MEMLOCK) failed (need CAP_SYS_RESOURCE/root?)");
    }
}

eBPFProgram::~eBPFProgram() {
    stop();
}

void eBPFProgram::start() {
    if (running_) {
        return;
    }

    running_ = true;

    try {
        libbpf_set_print(libbpfPrint);

        exec_monitor_bpf* skel = exec_monitor_bpf__open();
        if (!skel) {
            throw std::runtime_error("exec_monitor_bpf__open() returned NULL");
        }
        long openErr = libbpf_get_error(skel);
        if (openErr) {
            throw std::runtime_error("Failed to open BPF skeleton: " + formatErrno(static_cast<int>(openErr)));
        }
        int loadErr = exec_monitor_bpf__load(skel);
        if (loadErr) {
            exec_monitor_bpf__destroy(skel);
            throw std::runtime_error("Failed to load BPF skeleton: " + formatErrno(loadErr));
        }
        skel_ = skel;

        int err = exec_monitor_bpf__attach(skel_);
        if (err) {
            throw std::runtime_error("Failed to attach BPF skeleton: " + formatErrno(err));
        }

        int mapFd = bpf_map__fd(skel_->maps.events);

        perf_buffer* pb = openPerfBuffer(mapFd, this, &eBPFProgram::handleEvent, &eBPFProgram::handleLostEvents);
        if (!pb) {
            throw std::runtime_error("Failed to open perf buffer");
        }
        long pbErr = libbpf_get_error(pb);
        if (pbErr) {
            throw std::runtime_error("Failed to open perf buffer: " + std::to_string(pbErr));
        }
        pb_ = pb;

        listenerThread_ = std::thread(&eBPFProgram::eventListener, this);
    } catch (...) {
        stop();
        throw;
    }
}

void eBPFProgram::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    queueCv_.notify_all();

    if (listenerThread_.joinable()) {
        listenerThread_.join();
    }

    if (pb_) {
        perf_buffer__free(pb_);
        pb_ = nullptr;
    }
    if (skel_) {
        exec_monitor_bpf__destroy(skel_);
        skel_ = nullptr;
    }
}

bool eBPFProgram::isRunning() const {
    return running_;
}

void eBPFProgram::eventListener() {
    auto& logger = Logger::getInstance();

    while (running_) {
        int err = perf_buffer__poll(pb_, 100);
        if (err == -EINTR) {
            continue;
        }
        if (err < 0) {
            logger.logError("Error polling perf buffer: " + std::to_string(err));
            break;
        }
    }
}

void eBPFProgram::handleEvent(void *ctx, int /*cpu*/, void *data, __u32 /*data_sz*/) {
    auto* self = static_cast<eBPFProgram*>(ctx);
    if (!self) {
        return;
    }

    const auto* e = static_cast<const struct process_info_t*>(data);

    ProcessInfo info;
    info.pid = static_cast<pid_t>(e->pid);
    info.uid = static_cast<uid_t>(e->uid);
    info.gid = static_cast<gid_t>(e->gid);
    info.comm = e->comm;
    info.filePath = e->filename;

    {
        std::lock_guard<std::mutex> lock(self->queueMutex_);
        self->processQueue_.push(std::move(info));
    }
    self->queueCv_.notify_one();
}

void eBPFProgram::handleLostEvents(void * /*ctx*/, int cpu, __u64 lost_cnt) {
    auto& logger = Logger::getInstance();
    logger.logError("Lost " + std::to_string(lost_cnt) + " events on CPU " + std::to_string(cpu));
}

std::optional<ProcessInfo> eBPFProgram::getNextProcessEvent() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    if (processQueue_.empty()) {
        return std::nullopt;
    }

    ProcessInfo info = std::move(processQueue_.front());
    processQueue_.pop();
    return info;
}

std::optional<ProcessInfo> eBPFProgram::waitNextProcessEvent(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(queueMutex_);
    bool ready = queueCv_.wait_for(lock, timeout, [this]() {
        return !processQueue_.empty() || !running_;
    });
    if (!ready || processQueue_.empty()) {
        return std::nullopt;
    }

    ProcessInfo info = std::move(processQueue_.front());
    processQueue_.pop();
    return info;
}
