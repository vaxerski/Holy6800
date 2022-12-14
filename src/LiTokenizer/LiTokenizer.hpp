#pragma once

#include <memory>
#include <string>
#include <deque>
#include <array>
#include <vector>

inline const std::array<const char*, 3> BUILTIN_TYPES = {
    "U8",
    "U0",
    "I8"
};

inline const std::array<const char*, 12> KEYWORDS = {
    "const",
    "static",
    "for",
    "while",
    "if",
    "else",
    "return",
    "struct",
    "break",
    "continue",
    "case",
    "switch"
};

inline const std::array<const char*, 18> BUILTIN_OPERATORS = {
    "~",
    "!",
    "*",
    "/",
    "+",
    "-",
    "<",
    ">",
    "!=",
    "==",
    "|",
    "&",
    "||",
    "&&",
    "=",
    "+=",
    "-=",
    ":"
};

enum eTokenType {
    TOKEN_INVALID = -1,
    TOKEN_EMPTY = 0, /* Not invalid, but should be ignored */
    TOKEN_LITERAL,
    TOKEN_OPERATOR,
    TOKEN_TYPE,
    TOKEN_OPEN_PARENTHESIS,
    TOKEN_CLOSE_PARENTHESIS,
    TOKEN_OPEN_CURLY,
    TOKEN_CLOSE_CURLY,
    TOKEN_KEYWORD,
    TOKEN_SEMICOLON,
    TOKEN_COLON
};

struct SToken {
    eTokenType type = TOKEN_INVALID;
    std::string raw = "";
    size_t lineNo = 0;
};

class CLiTokenizer {
public:
    CLiTokenizer(std::string path);
    ~CLiTokenizer() = default;

    std::deque<SToken>  m_dTokens;

    std::string         m_szInputFile = "";

    std::vector<std::string> m_vLines;

private:
    void            tokenizeFile(std::string&);
};

inline std::unique_ptr<CLiTokenizer> g_pLiTokenizer;