#pragma once

#include <memory>
#include <unordered_map>
#include <array>
#include <vector>
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
        std::vector<uint16_t> byteStartPositions;
        void updateByteStartPositions();
        void fixAddressesAfterRemove(size_t where, size_t lenRemoved);
        size_t getNextByteStart(size_t cur);
        size_t getLastByteStart(size_t cur);
        bool isRelative(uint8_t byte);
        bool isRetWai(uint8_t byte);
        bool isPush(uint8_t byte);
        bool isClear(uint8_t byte);
        bool isLoad(uint8_t byte);
        void optimizeBinary();
    } optimizer;
};

inline std::unique_ptr<CCompiler> g_pCompiler;

// OPERATION -> size. 0 = invalid
inline std::array<uint8_t, 255> OPERATIONS_SIZE = { 
    0, 1, 0, 0, 0, 0, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 0, 0, 0, 0, 1, 1, 
    0, 1, 0, 1, 0, 0, 0, 0, 
    2, 0, 2, 2, 2, 2, 2, 2, 
    2, 2, 2, 2, 2, 2, 2, 2, 
    1, 1, 1, 1, 1, 1, 1, 1, 
    0, 1, 0, 1, 0, 0, 1, 1, 
    1, 0, 0, 1, 1, 0, 1, 1, 
    1, 1, 1, 0, 1, 1, 0, 1, 
    1, 0, 0, 1, 1, 0, 1, 1, 
    1, 1, 1, 0, 1, 1, 0, 1, 
    2, 0, 0, 2, 2, 0, 2, 2, 
    2, 2, 2, 0, 2, 2, 2, 2, 
    3, 0, 0, 3, 3, 0, 3, 3, 
    3, 3, 3, 0, 3, 3, 3, 3, 
    2, 2, 2, 0, 2, 2, 2, 0, 
    2, 2, 2, 2, 3, 2, 3, 0, 
    2, 2, 2, 0, 2, 2, 2, 2, 
    2, 2, 2, 2, 2, 0, 2, 2, 
    2, 2, 2, 0, 2, 2, 2, 2, 
    2, 2, 2, 2, 2, 2, 2, 2, 
    3, 3, 3, 0, 3, 3, 3, 3, 
    3, 3, 3, 3, 3, 3, 3, 3, 
    2, 2, 2, 0, 2, 2, 2, 0, 
    2, 2, 2, 2, 0, 0, 3, 0, 
    2, 2, 2, 0, 2, 2, 2, 2, 
    2, 2, 2, 2, 0, 0, 2, 2, 
    2, 2, 2, 0, 2, 2, 2, 2, 
    2, 2, 2, 2, 0, 0, 2, 2, 
    3, 3, 3, 0, 3, 3, 3, 3, 
    3, 3, 3, 3, 0, 0, 3
};
