#include "Log.hpp"

#include <fstream>
#include <iostream>
#include <string.h>
#include <stdarg.h>

void Debug::log(LogLevel level, std::string mainText, const char* fmt, ...) {
    switch (level) {
        case LOG:
            std::cout << "\033[36m[LOG] ";
            break;
        case WARN:
            std::cout << "\033[93m[WARN] ";
            break;
        case ERR:
            std::cout << "\033[91m[ERR] ";
            break;
        case CRIT:
            std::cout << "\033[91m[CRITICAL] ";
            break;
        case INFO:
            std::cout << "\033[32m[INFO] ";
            break;
        default:
            break;
    }

    char buf[1024] = "";
    char* outputStr;
    int logLen;

    va_list args;
    va_start(args, fmt);
    logLen = vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);

    if ((long unsigned int)logLen < sizeof buf) {
        outputStr = strdup(buf);
    } else {
        outputStr = (char*)malloc(logLen + 1);

        if (!outputStr) {
            printf("CRITICAL: Cannot alloc size %d for log! (Out of memory?)", logLen + 1);
            return;
        }

        va_start(args, fmt);
        vsnprintf(outputStr, logLen + 1U, fmt, args);
        va_end(args);
    }

    // hyprpicker only logs to stdout
    std::cout << mainText << "\033[39;49m " << outputStr << "\n";

    // free the log
    free(outputStr);
}
