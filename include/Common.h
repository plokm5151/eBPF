#pragma once

#include <sys/types.h>
#include <string>

struct ProcessInfo {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    std::string comm;
    std::string filePath;
};
