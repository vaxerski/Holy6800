#pragma once
#include <string>

enum LogLevel {
    NONE = -1,
    LOG = 0,
    WARN,
    ERR,
    CRIT,
    INFO
};

namespace Debug {
    void log(LogLevel level, std::string mainText, const char* fmt, ...);
    void err(std::string mainText, size_t line, const char* fmt, ...);
};