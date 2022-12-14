#include "LiTokenizer.hpp"
#include <fstream>
#include "../Debug/Log.hpp"
#include <algorithm>
#include <chrono>
#include <ranges>
#include "../helpers/MiscFunctions.hpp"

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

    // first, split it. token -> line
    std::deque<std::pair<std::string, size_t>> tokens;

    std::string currentArg = "";
    std::string currentLine = "";
    size_t lineNo = 1;
    bool lastWasSpace = false;
    bool comment = false;
    for (unsigned long int i = 0; i < in.length(); ++i) {

        currentLine += in[i];

        if (isspace(in[i])) {
            // space denotes a new token, but multiple ones should be ignored
            bool newline = false;

            if (in[i] == '\n')  {
                comment = false;
                if (currentLine.length() > 0)
                    currentLine.pop_back(); // pop the \n
                m_vLines.emplace_back(currentLine);
                currentLine = "";
                lineNo++;
                newline = true;
            }

            if (lastWasSpace)
                continue;

            lastWasSpace = true;
            if (!currentArg.empty())
                tokens.push_back({currentArg, lineNo - (newline ? 1 : 0)});
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
                    tokens.push_back({in.substr(i, it), lineNo});
                    i += it;
                    currentArg = "";
                    foundLong = true;
                    for (int itt = 0; itt < it; itt++)
                        currentLine += in[i + itt - it + 1];
                    break;
                }
            }

            if (foundLong)
                continue;

            if (!currentArg.empty())
                tokens.push_back({currentArg, lineNo});
            currentArg = "";
            tokens.push_back({in.substr(i, 1), lineNo});
            continue;
        }

        currentArg += in[i];
    }

    tokens.push_back({currentArg, lineNo});

    // tokens stage 1 done. We loaded all tokens into the tokens deque
    Debug::log(LOG, "Tokenization stage 1 done.", "Amount of tokens: %d", tokens.size());

    // now, we identify the tokens
    for (size_t i = 0; i < tokens.size(); ++i) {
        std::string& token = tokens[i].first;
        SToken newToken;
        newToken.raw = token;
        newToken.lineNo = tokens[i].second;

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
        } else if (std::find_if(BUILTIN_TYPES.begin(), BUILTIN_TYPES.end(), [&](const char* other) { return other == (token.back() == '*' ? token.substr(0, token.length() - 1) : token); }) != BUILTIN_TYPES.end()) {
            newToken.type = TOKEN_TYPE;
        } else if (std::find_if(KEYWORDS.begin(), KEYWORDS.end(), [&](const char* other) { return other == token; }) != KEYWORDS.end()) {
            newToken.type = TOKEN_KEYWORD;
        } else if (std::find_if(BUILTIN_OPERATORS.begin(), BUILTIN_OPERATORS.end(), [&](const char* other) { return other == token; }) != BUILTIN_OPERATORS.end()) {
            // check ~ on constant optimizations
            if (token == "~" && i + 1 < tokens.size() && isNumber(tokens[i + 1].first)) {
                // trolololo
                newToken.type = TOKEN_LITERAL;
                newToken.raw = std::to_string(~toInt(tokens[i + 1].first));
                i++;
            } else {
                newToken.type = TOKEN_OPERATOR;
            }
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