#include "LiTokenizer.hpp"
#include <fstream>
#include "../Debug/Log.hpp"
#include <algorithm>
#include <chrono>
#include <ranges>

CLiTokenizer::CLiTokenizer(std::string path) {
    // load the file to a string
    std::fstream f(path);
    std::string entireFile((std::istreambuf_iterator<char>(f)), (std::istreambuf_iterator<char>()));
    f.close();

    Debug::log(LOG, "Loaded file into memory.", "Total byte size: %.2fkB", entireFile.length() / 1024.0);

    m_szInputFile = path;

    // start tokenizing
    tokenizeFile(entireFile);
}

void CLiTokenizer::tokenizeFile(std::string& in) {
    std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();

    // first, split it.
    std::deque<std::string> tokens;

    std::string currentArg = "";
    bool lastWasSpace = false;
    bool comment = false;
    for (unsigned long int i = 0; i < in.length(); ++i) {

        if (isspace(in[i])) {
            // space denotes a new token, but multiple ones should be ignored
            if (in[i] == '\n') 
                comment = false;

            if (lastWasSpace)
                continue;

            lastWasSpace = true;
            if (!currentArg.empty())
                tokens.emplace_back(currentArg);
            currentArg = "";
            continue;
        }

        if (comment)
            continue;

        lastWasSpace = false;

        if (i + 1 < in.length() && in[i] == '/' && in[i + 1] == '/') {
            comment = true;
            continue;
        }

        // colon / semicolon does too, but we also want it as a token. Additionally one-char operators.
        if (in[i] == ',' || in[i] == ';' || in[i] == '{' || in[i] == '(' || in[i] == ')' || in[i] == '}' || std::find_if(BUILTIN_OPERATORS.begin(), BUILTIN_OPERATORS.end(), [&](const char* other) { return other[0] == in[i]; }) != BUILTIN_OPERATORS.end()) {
            
            // pointers are treated together
            if (in[i] == '*' && ((i > 0 && !isspace(in[i - 1])) || (i + 1 < in.length() && !isspace(in[i + 1])))) {
                currentArg += in[i];
                continue;
            }

            // check if it's not a long operator
            bool foundLong = false;
            for (auto& op : BUILTIN_OPERATORS) {
                if (op[1] == '\0')
                    continue;

                int it = 1;
                while (op[it] != 0) {
                    if (op[it] != in[i + it]) 
                        break;
                    it++;
                }

                if (op[it] == 0) {
                    // found a long one!
                    tokens.emplace_back(in.substr(i, it));
                    i += it;
                    currentArg = "";
                    foundLong = true;
                    break;
                }
            }

            if (foundLong)
                continue;

            if (!currentArg.empty())
                tokens.emplace_back(currentArg);
            currentArg = "";
            tokens.emplace_back(in.substr(i, 1));
            continue;
        }

        currentArg += in[i];
    }

    tokens.emplace_back(currentArg);

    // tokens stage 1 done. We loaded all tokens into the tokens deque
    Debug::log(LOG, "Tokenization stage 1 done.", "Amount of tokens: %d", tokens.size());

    // now, we identify the tokens
    for (auto& token : tokens) {
        SToken newToken;
        newToken.raw = token;

        if (token == ",") {
            newToken.type = TOKEN_COLON;
        } else if (token == ";") {
            newToken.type = TOKEN_SEMICOLON;
        } else if (token == "(") {
            newToken.type = TOKEN_OPEN_PARENTHESIS;
        } else if (token == ")") {
            newToken.type = TOKEN_CLOSE_PARENTHESIS;
        } else if (token == "{") {
            newToken.type = TOKEN_OPEN_CURLY;
        } else if (token == "}") {
            newToken.type = TOKEN_CLOSE_CURLY;
        } else if (std::find_if(BUILTIN_TYPES.begin(), BUILTIN_TYPES.end(), [&](const char* other) { return other == token; }) != BUILTIN_TYPES.end()) {
            newToken.type = TOKEN_TYPE;
        } else if (std::find_if(KEYWORDS.begin(), KEYWORDS.end(), [&](const char* other) { return other == token; }) != KEYWORDS.end()) {
            newToken.type = TOKEN_KEYWORD;
        } else if (std::find_if(BUILTIN_OPERATORS.begin(), BUILTIN_OPERATORS.end(), [&](const char* other) { return other == token; }) != BUILTIN_OPERATORS.end()) {
            newToken.type = TOKEN_OPERATOR;
        } else if (std::ranges::all_of(token.begin(), token.end(), [] (char other) { return isspace(other); })) {
            continue;
        } else {
            newToken.type = TOKEN_LITERAL;
        }

        m_dTokens.emplace_back(newToken);
        continue;
    }

    // token stage 2 done. We can move on to compiling!
    Debug::log(LOG, "Tokenization stage 2 done.", "Time elapsed for tokenization: %.2fms", std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - begin).count() / 1000.0);

}