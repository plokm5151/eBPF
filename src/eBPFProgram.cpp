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
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {
template <typename T>
inline constexpr bool always_false_v = false;

template <typename T, typename = void>
struct has_member_sz : std::false_type {};
template <typename T>
struct has_member_sz<T, std::void_t<decltype(std::declval<T&>().sz)>> : std::true_type {};
template <typename T>
inline constexpr bool has_member_sz_v = has_member_sz<T>::value;

template <typename T, typename = void>
struct has_member_sample_cb : std::false_type {};
template <typename T>
struct has_member_sample_cb<T, std::void_t<decltype(std::declval<T&>().sample_cb)>> : std::true_type {};
template <typename T>
inline constexpr bool has_member_sample_cb_v = has_member_sample_cb<T>::value;

template <typename T, typename = void>
struct has_member_lost_cb : std::false_type {};
template <typename T>
struct has_member_lost_cb<T, std::void_t<decltype(std::declval<T&>().lost_cb)>> : std::true_type {};
template <typename T>
inline constexpr bool has_member_lost_cb_v = has_member_lost_cb<T>::value;

template <typename T, typename = void>
struct has_member_ctx : std::false_type {};
template <typename T>
struct has_member_ctx<T, std::void_t<decltype(std::declval<T&>().ctx)>> : std::true_type {};
template <typename T>
inline constexpr bool has_member_ctx_v = has_member_ctx<T>::value;

template <typename, typename... Args>
struct is_perf_buffer_new_invocable : std::false_type {};

template <typename... Args>
struct is_perf_buffer_new_invocable<std::void_t<decltype(perf_buffer__new(std::declval<Args>()...))>, Args...>
    : std::true_type {};

template <typename... Args>
inline constexpr bool is_perf_buffer_new_invocable_v = is_perf_buffer_new_invocable<void, Args...>::value;

constexpr size_t kPerfBufferPageCnt = 8;

template <typename Dummy = void>
perf_buffer* openPerfBuffer(int mapFd, void* ctx, perf_buffer_sample_fn sampleCb, perf_buffer_lost_fn lostCb) {
    // Prefer the libbpf API where callbacks are passed directly (less struct-field drift).
    if constexpr (is_perf_buffer_new_invocable_v<int,
                                                 size_t,
                                                 perf_buffer_sample_fn,
                                                 perf_buffer_lost_fn,
                                                 void*,
                                                 struct perf_buffer_opts*>) {
        return perf_buffer__new(mapFd,
                                kPerfBufferPageCnt,
                                sampleCb,
                                lostCb,
                                ctx,
                                static_cast<struct perf_buffer_opts*>(nullptr));
    } else if constexpr (
        is_perf_buffer_new_invocable_v<int, size_t, perf_buffer_sample_fn, perf_buffer_lost_fn, void*>) {
        return perf_buffer__new(mapFd, kPerfBufferPageCnt, sampleCb, lostCb, ctx);
    } else if constexpr (is_perf_buffer_new_invocable_v<int, size_t, struct perf_buffer_opts*>) {
        // Older libbpf API: callbacks are provided via struct perf_buffer_opts (field set varies by version).
        struct perf_buffer_opts opts = {};
        if constexpr (has_member_sz_v<struct perf_buffer_opts>) {
            opts.sz = sizeof(opts);
        }
        if constexpr (has_member_sample_cb_v<struct perf_buffer_opts>) {
            opts.sample_cb = sampleCb;
        }
        if constexpr (has_member_lost_cb_v<struct perf_buffer_opts>) {
            opts.lost_cb = lostCb;
        }
        if constexpr (has_member_ctx_v<struct perf_buffer_opts>) {
            opts.ctx = ctx;
        }

        constexpr bool hasCallbacks = has_member_sample_cb_v<struct perf_buffer_opts> &&
                                      has_member_lost_cb_v<struct perf_buffer_opts> &&
                                      has_member_ctx_v<struct perf_buffer_opts>;
        static_assert(hasCallbacks,
                      "libbpf perf_buffer__new(map_fd, page_cnt, opts) exists, but perf_buffer_opts has no callback fields");

        return perf_buffer__new(mapFd, kPerfBufferPageCnt, &opts);
    } else {
        static_assert(always_false_v<Dummy>,
                      "Unsupported perf_buffer__new() API in libbpf headers; update src/eBPFProgram.cpp");
        return nullptr;
    }
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
        exec_monitor_bpf* skel = exec_monitor_bpf__open_and_load();
        if (!skel) {
            throw std::runtime_error("Failed to open and load BPF skeleton");
        }
        long skelErr = libbpf_get_error(skel);
        if (skelErr) {
            throw std::runtime_error("Failed to open and load BPF skeleton: " + std::to_string(skelErr));
        }
        skel_ = skel;

        int err = exec_monitor_bpf__attach(skel_);
        if (err) {
            throw std::runtime_error("Failed to attach BPF skeleton");
        }

        int mapFd = bpf_map__fd(skel_->maps.events);

        perf_buffer* pb = openPerfBuffer<>(mapFd, this, &eBPFProgram::handleEvent, &eBPFProgram::handleLostEvents);
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
