// src/JSONWriter.h
#pragma once

#include "Common.h"

class JSONWriter {
public:
    JSONWriter() = default;
    ~JSONWriter() = default;

    void writeProcessInfo(const ProcessInfo& processInfo);
};

