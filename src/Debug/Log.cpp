#include "Log.hpp"

#include <fstream>
#include <iostream>
#include <string.h>
#include <stdarg.h>
#include "../LiTokenizer/LiTokenizer.hpp"

void Debug::log(LogLevel level, std::string mainText, const char* fmt, ...) {
    switch (level) {
        case LOG:
            std::cout << "\033[36m ";
            break;
        case WARN:
            std::cout << "\033[93m ";
            break;
        case ERR:
            std::cout << "\033[91m ";
            break;
        case CRIT:
            std::cout << "\033[91m ";
            break;
        case INFO:
            std::cout << "\033[32m ";
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

    std::cout << mainText << "\033[39;49m " << outputStr << "\n";

    // free the log
    free(outputStr);
}

void Debug::err(std::string mainText, size_t line, const char* fmt, ...) {
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

    // log a nice error
    /*

╭————————————————————————
✕ Syntax Error

at line 1337:

│ if (mainTest == 0) {

"mainTest" undefined
╰————————————————————————


*/

    std::string errorText =
"\033[90m╭————————————————————————\n\
\033[91m✕ " + mainText + "\n\
\n\
\033[39;49mat line \033[92m";

    errorText += std::to_string(line);

    errorText += 
"\033[39;49m:\n" + g_pLiTokenizer->m_vLines[line - 1] + "\n\n" + outputStr + "\n\033[90m╰————————————————————————";

    std::cout << errorText << "\n";

    // free the log
    free(outputStr);
}
