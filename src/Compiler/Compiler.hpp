#pragma once

#include <memory>
#include <unordered_map>
#include "../LiTokenizer/LiTokenizer.hpp"

typedef uint8_t BYTE;

struct SFunction {
    std::string signature = "";
    size_t binaryBegin;
    std::string returnType = "";

    // only for parsing
    uint8_t stackOffset = 0;
};

struct SLocal {
    std::string name = "";
    uint8_t offset = 0;
    bool funcParam = false;
};

class CCompiler {
public:
    CCompiler(std::string output, bool raw, bool optimize);
    ~CCompiler() = default;

private:
    bool        compile();
    void        write(std::string path);

    void        initializeBinary(uint16_t start);
    bool        compileFunction(SToken* returnType, SToken* name, std::deque<std::pair<SToken*, SToken*>>& args);
    bool        compileScope(std::deque<SLocal>& inheritedLocals, bool ISMAIN = false, bool ISFUNC = false);

    void        optimizeBinary();

    void        writeBytes(void* begin, BYTE* bytes, size_t len);

    std::string createHippyRecord(void* begin, size_t len);

    BYTE*       m_pBytes;
    size_t      m_iBytesSize = 0;
    std::deque<SFunction> m_dFunctions;
    size_t      m_iCurrentToken = 0;

    bool        m_bRawOutput = false;
    bool        m_bOptimize  = false;

    SFunction*  m_pCurrentFunction = nullptr;

    struct SOptimizer {
        CCompiler* p;
        std::deque<size_t> byteStartPositions;
        void updateByteStartPositions();
        void fixAddressesAfterRemove(size_t where, size_t lenRemoved);
        size_t getNextByteStart(size_t cur);
        size_t getLastByteStart(size_t cur);
        bool isRelative(uint8_t byte);
        bool isRetWai(uint8_t byte);
        bool isPush(uint8_t byte);
        bool isLoad(uint8_t byte);
        void optimizeBinary();
    } optimizer;
};

inline std::unique_ptr<CCompiler> g_pCompiler;

// a map that contains opcode -> length
inline const std::unordered_map<uint8_t, uint8_t> OPERATIONSTOBYTES = {
    {0x1B, 1}, {0x89, 2}, {0x99, 2}, {0xA9, 2}, {0xB9, 3}, {0xC9, 2}, {0xD9, 2},
    {0xE9, 2}, {0xF9, 3}, {0x8B, 2}, {0x9B, 2}, {0xAB, 2}, {0xBB, 3}, {0xCB, 2}, {0xDB, 2},
    {0xEB, 2}, {0xFB, 3}, {0x84, 2}, {0x94, 2}, {0xA4, 2}, {0xB4, 3}, {0xC4, 2}, {0xD4, 2},
    {0xE4, 2}, {0xF4, 3}, {0x48, 1}, {0x58, 1}, {0x68, 2}, {0x78, 3}, {0x47, 1}, {0x57, 1},
    {0x67, 2}, {0x77, 3}, {0x24, 2}, {0x25, 2}, {0x27, 2}, {0x2C, 2}, {0x2E, 2}, {0x22, 2},
    {0x85, 2}, {0x95, 2}, {0xA5, 2}, {0xB5, 3}, {0xC5, 2}, {0xD5, 2}, {0xE5, 2}, {0xF5, 3},
    {0x2F, 2}, {0x23, 2}, {0x2D, 2}, {0x2B, 2}, {0x26, 2}, {0x2A, 2}, {0x20, 2}, {0x8D, 2},
    {0x28, 2}, {0x29, 2}, {0x11, 1}, {0x0C, 1}, {0x0E, 1}, {0x4F, 1}, {0x5F, 1}, {0x6F, 2},
    {0x7F, 3}, {0x0A, 1}, {0x81, 2}, {0x91, 2}, {0xA1, 2}, {0xB1, 3}, {0xC1, 2}, {0xD1, 2},
    {0xE1, 2}, {0xF1, 3}, {0x43, 1}, {0x53, 1}, {0x63, 2}, {0x73, 3}, {0x9C, 2}, {0xAC, 2},
    {0x8C, 3}, {0xBC, 3}, {0x19, 1}, {0x4A, 1}, {0x5A, 1}, {0x6A, 2}, {0x7A, 3}, {0x34, 1},
    {0x09, 1}, {0x88, 2}, {0x98, 2}, {0xA8, 2}, {0xB8, 3}, {0xC8, 2}, {0xD8, 2}, {0xE8, 2},
    {0xF8, 3}, {0x4C, 1}, {0x5C, 1}, {0x6C, 2}, {0x7C, 3}, {0x31, 1}, {0x08, 1}, {0x6E, 2},
    {0x7E, 3}, {0xAD, 2}, {0xBD, 3}, {0x86, 2}, {0x96, 2}, {0xA6, 2}, {0xB6, 3}, {0xC6, 2},
    {0xD6, 2}, {0xE6, 2}, {0xF6, 3}, {0x9E, 2}, {0xAE, 2}, {0x8E, 3}, {0xBE, 3}, {0xDE, 2},
    {0xEE, 2}, {0xCE, 3}, {0xFE, 3}, {0x44, 1}, {0x54, 1}, {0x64, 2}, {0x74, 3}, {0x40, 1},
    {0x50, 1}, {0x60, 2}, {0x70, 3}, {0x01, 1}, {0x8A, 2}, {0x9A, 2}, {0xAA, 2}, {0xBA, 3},
    {0xCA, 2}, {0xDA, 2}, {0xEA, 2}, {0xFA, 3}, {0x36, 1}, {0x37, 1}, {0x32, 1}, {0x33, 1},
    {0x49, 1}, {0x59, 1}, {0x69, 2}, {0x79, 3}, {0x46, 1}, {0x56, 1}, {0x66, 2}, {0x76, 3},
    {0x3B, 1}, {0x39, 1}, {0x10, 1}, {0x82, 2}, {0x92, 2}, {0xA2, 2}, {0xB2, 3}, {0xC2, 2},
    {0xD2, 2}, {0xE2, 2}, {0xF2, 3}, {0x0D, 1}, {0x0F, 1}, {0x0B, 1}, {0x97, 2}, {0xA7, 2},
    {0xB7, 3}, {0xD7, 2}, {0xE7, 2}, {0xF7, 3}, {0x9F, 2}, {0xAF, 2}, {0xBF, 3}, {0xDF, 2},
    {0xEF, 2}, {0xFF, 3}, {0x80, 2}, {0x90, 2}, {0xA0, 2}, {0xB0, 3}, {0xC0, 2}, {0xD0, 2},
    {0xE0, 2}, {0xF0, 3}, {0x3F, 1}, {0x16, 1}, {0x06, 1}, {0x17, 1}, {0x07, 1}, {0x4D, 1},
    {0x5D, 1}, {0x6D, 2}, {0x7D, 3}, {0x30, 1}, {0x35, 1}, {0x3E, 1}
};