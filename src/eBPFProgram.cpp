#include "eBPFProgram.h"

#include "ExecMonitor.h"
#include "exec_monitor.skel.h"
#include "Logger.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {
template <typename, typename... Args>
struct has_perf_buffer_new : std::false_type {};

template <typename... Args>
struct has_perf_buffer_new<std::void_t<decltype(perf_buffer__new(std::declval<Args>()...))>, Args...>
    : std::true_type {};

template <typename... Args>
constexpr bool has_perf_buffer_new_v = has_perf_buffer_new<void, Args...>::value;
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

        perf_buffer* pb = nullptr;

        if constexpr (has_perf_buffer_new_v<int, size_t, const struct perf_buffer_opts*>) {
            // Newer libbpf: callbacks are provided via perf_buffer_opts, and perf_buffer__new has 3 args.
            struct perf_buffer_opts pbOpts = {};
            pbOpts.sz = sizeof(pbOpts);
            pbOpts.sample_cb = &eBPFProgram::handleEvent;
            pbOpts.lost_cb = &eBPFProgram::handleLostEvents;
            pbOpts.ctx = this;
            pb = perf_buffer__new(mapFd, 8, &pbOpts);
        } else if constexpr (has_perf_buffer_new_v<int,
                                                    size_t,
                                                    perf_buffer_sample_fn,
                                                    perf_buffer_lost_fn,
                                                    void*,
                                                    const struct perf_buffer_opts*>) {
            // Older libbpf: callbacks are passed as separate args, perf_buffer_opts is optional.
            pb = perf_buffer__new(mapFd,
                                  8,
                                  &eBPFProgram::handleEvent,
                                  &eBPFProgram::handleLostEvents,
                                  this,
                                  nullptr);
        } else if constexpr (has_perf_buffer_new_v<int,
                                                    size_t,
                                                    perf_buffer_sample_fn,
                                                    perf_buffer_lost_fn,
                                                    void*>) {
            // Very old libbpf: no perf_buffer_opts parameter.
            pb = perf_buffer__new(mapFd,
                                  8,
                                  &eBPFProgram::handleEvent,
                                  &eBPFProgram::handleLostEvents,
                                  this);
        } else {
            static_assert(false, "Unsupported perf_buffer__new() signature in libbpf headers");
        }
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
