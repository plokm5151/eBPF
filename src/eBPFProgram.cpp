#include "eBPFProgram.h"

#include "ExecMonitor.h"
#include "exec_monitor.skel.h"
#include "Logger.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif

#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <string>

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

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
        struct perf_buffer_opts pbOpts = {};
        pbOpts.sz = sizeof(pbOpts);
        pbOpts.sample_cb = &eBPFProgram::handleEvent;
        pbOpts.lost_cb = &eBPFProgram::handleLostEvents;
        pbOpts.ctx = this;
        perf_buffer* pb = perf_buffer__new(mapFd, 8, &pbOpts);
#else
        perf_buffer* pb = perf_buffer__new(
            mapFd,
            8,
            &eBPFProgram::handleEvent,
            &eBPFProgram::handleLostEvents,
            this,
            nullptr
        );
#endif
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
