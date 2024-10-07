#pragma once

#include <sys/types.h>
#include <string>

struct ProcessInfo {
    pid_t pid;
    gid_t gid;
    std::string filePath;
};
