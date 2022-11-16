#include <iostream>
#include <deque>
#include <string>
#include <filesystem>

#include "helpers/MiscFunctions.hpp"
#include "Debug/Log.hpp"
#include "LiTokenizer/LiTokenizer.hpp"
#include "Compiler/Compiler.hpp"

std::deque<std::string> splitArgs(int argc, char** argv) {
    std::deque<std::string> result;

    for (auto i = 1 /* skip the executable */; i < argc; ++i)
        result.push_back(std::string(argv[i]));

    return result;
}

void printHelp() {
    std::cout << R"#(   Holy6800

        -c [file]                   -> compile a file
        -o [file]                   -> specify output
        -r                          -> raw output (not for hippy)
        --no-optimizations          -> disable binary optimizations (debug builds)
        --optimization-steps [n]    -> how many optimization stages to perform. [default: -1, all]
        -h / --help                 -> print this
)#";
}

int main(int argc, char** argv, char** envp) {
    const auto ARGS = splitArgs(argc, argv);

    std::string fileToCompile = "";
    std::string output = "";
    bool raw = false;
    bool optimize = true;
    int optimizationSteps = -1;

    for (long unsigned int i = 0; i < ARGS.size(); ++i) {
        if ((ARGS[i][0] == '-') && !isNumber(ARGS[i], true) /* For stuff like -2 */) {
            // parse

            if (ARGS[i] == "-c") {
                if (i + 1 >= ARGS.size()) {
                    printHelp();
                    return 1;
                }
                fileToCompile = ARGS[++i];
                continue;
            } else if (ARGS[i] == "-o") {
                if (i + 1 >= ARGS.size()) {
                    printHelp();
                    return 1;
                }
                output = ARGS[++i];
                continue;
            } else if (ARGS[i] == "-h" || ARGS[i] == "--help") {
                printHelp();
                continue;
            } else if (ARGS[i] == "-r") {
                raw = true;
                continue;
            } else if (ARGS[i] == "--no-optimizations") {
                optimize = false;
                continue;
            } else if (ARGS[i] == "--optimization-steps") {
                if (i + 1 >= ARGS.size() || !isNumber(ARGS[i + 1])) {
                    printHelp();
                    return 1;
                }
                optimizationSteps = toInt(ARGS[++i]);
                continue;
            } else {
                std::cout << "Unrecognized parameter: " << ARGS[i] << "\n";
                return 1;
            }

            continue;
        }
    }

    if (fileToCompile.empty()) {
        std::cout << "No file to compile! Use -c to specify one.\n";
        return 1;
    }

    if (!std::filesystem::exists(fileToCompile)) {
        std::cout << "Invalid file specified (doesn't exist)\n";
        return 1;
    }

    if (std::filesystem::status(fileToCompile).type() != std::filesystem::file_type::regular) {
        std::cout << "Invalid file specified (not a file)\n";
        return 1;
    }

    if (fileToCompile.substr(fileToCompile.length() - 2) != "hc") {
        std::cout << "Invalid file specified (not a .hc file)\n";
        return 1;
    }

    Debug::log(LOG, "Found input file:", "%s", fileToCompile.c_str());

    g_pLiTokenizer = std::make_unique<CLiTokenizer>(fileToCompile);

    g_pCompiler = std::make_unique<CCompiler>(output, raw, optimize, optimizationSteps);

    return 0;
}