#pragma once

#include <memory>
#include "../LiTokenizer/LiTokenizer.hpp"

typedef uint8_t BYTE;

struct SFunction {
    std::string signature = "";
    size_t binaryBegin;
    std::string returnType = "";

    // only for parsing
    uint8_t stackOffset = 0;
};

class CCompiler {
public:
    CCompiler(std::string output, bool raw);
    ~CCompiler() = default;

private:
    bool        compile();
    void        write(std::string path);

    void        initializeBinary(uint16_t start);
    bool        compileFunction(SToken* returnType, SToken* name, std::deque<std::pair<SToken*, SToken*>>& args);
    bool        compileScope(std::deque<std::pair<std::string, uint16_t>>& inheritedLocals, bool ISMAIN = false);

    void        writeBytes(void* begin, BYTE* bytes, size_t len);

    std::string createHippyRecord(void* begin, size_t len);

    BYTE*       m_pBytes;
    size_t      m_iBytesSize = 0;
    std::deque<SFunction> m_dFunctions;
    size_t      m_iCurrentToken = 0;

    bool        m_bRawOutput = false;

    SFunction*  m_pCurrentFunction = nullptr;
};

inline std::unique_ptr<CCompiler> g_pCompiler;