#include "Compiler.hpp"
#include <fstream>
#include <iostream>
#include "../Debug/Log.hpp"
#include <string.h>
#include <algorithm>
#include "../helpers/MiscFunctions.hpp"
#include <chrono>
#include <functional>

CCompiler::CCompiler(std::string output, bool raw, bool optimize) {
    std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();
    m_bRawOutput = raw;
    m_bOptimize = optimize;
    optimizer.p = this;

    m_pBytes = (BYTE*)malloc(32000);  // 32K

    // compile
    if (!compile()) {
        Debug::log(ERR, "Compilation failed!", "Compiler returned status 1.");
        return;
    }

    // write
    char buffer[1024] = { 0 };
    getcwd(buffer, 1024);
    write(output);

    free(m_pBytes);

    Debug::log(LOG, "Compiling done!", "Time elapsed for compiling and writing the binary: %.2fms", std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - begin).count() / 1000.0);
}

void CCompiler::write(std::string path) {

    // if optimization is enabled, optimize the binary
    if (m_bOptimize)
        optimizer.optimizeBinary();

    // sanitize path
    if (path.empty()) {
        path = g_pLiTokenizer->m_szInputFile;
        path = path.substr(0, path.find_last_of('.'));
    }

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);

    if (m_bRawOutput) {
        for (size_t i = 0; i < m_iBytesSize; ++i) {
            ofs << m_pBytes[i];
        }

        ofs.close();
    } else {
        // write in blocks for the stupid thing
        int left = m_iBytesSize;
        int at = 0;
        int blocks = 0;

        while (left > 0) {
            if (m_iBytesSize > 0x70) {
                std::string reslt = createHippyRecord(m_pBytes + at, 0x70);
                for (auto& c : reslt) {
                    if (c == 0) break;
                    ofs << c;
                }
                at += 0x70;
                left -= 0x70;
            } else {
                std::string reslt = createHippyRecord(m_pBytes + at, left);
                for (auto& c : reslt) {
                    if (c == 0) break;
                    ofs << c;
                }

                blocks++;
                break;
            }

            blocks++;
        }

       // uint8_t checksumS5 = (compl ((0x03 + (uint8_t)(blocks >> 8) + (uint8_t)(blocks & 0xFF)) & 0xFF));
      //  ofs << "S503" << toHexFill(blocks, 4) << toHexFill(checksumS5, 2) << "\x0D\x0A";

        uint8_t checksumS9 = compl((uint8_t)((3 + (m_iBytesSize >> 8) + (m_iBytesSize & 0xFF)) & 0xFF));
        ofs << "S903" << toHexFill(m_iBytesSize, 4) << toHexFill(checksumS9, 2) << "\x0D\x0A";
        ofs.close();
    }
}

std::string CCompiler::createHippyRecord(void* begin, size_t len) {
    std::string result = "S1";

    // size
    result += toHexFill(len + 3, 2);

    // address
    result += toHexFill((uintptr_t)((uintptr_t)begin - (uintptr_t)m_pBytes), 4);

    // data
    int checksum = len + 3 + ((uintptr_t)begin - (uintptr_t)m_pBytes);
    for (size_t i = 0; i < len; ++i) {
        checksum += *((uint8_t*)begin + i);
        result += toHexFill(*((uint8_t*)begin + i), 2);
    }

    // checksum
    checksum &= 0xFF;

    uint8_t finalChecksum = (compl (uint8_t)checksum);

    result += toHexFill(finalChecksum, 2);

    // end block
    result += (char)0x0D;
    result += (char)0x0A;

    return result;
}

bool CCompiler::compile() {
    // parse token for token.

    // global -> we expect a function. No globals allowed.
    // TODO: maybe allow?

    m_iBytesSize = 6; // this is because our header is 6 bytes.

    const std::deque<SToken>& PTOKENS = g_pLiTokenizer->m_dTokens;

    SToken* funcReturnType = nullptr;
    SToken* funcName = nullptr;
    std::deque<std::pair<SToken*, SToken*>> funcParamsList; /* pairs of type + literal */

    for (size_t i = 0; i < PTOKENS.size(); ++i) {

        if (PTOKENS[i].type == TOKEN_EMPTY || PTOKENS[i].type == TOKEN_INVALID)
            continue;

        if (!funcReturnType) {
            // stage 1: look for a type

            if (PTOKENS[i].type != TOKEN_TYPE) {
                Debug::log(ERR, "Invalid token", "Token %i is invalid. Got %s, expected TOKEN_TYPE", i, PTOKENS[i].raw.c_str());
                return false;
            }

            funcReturnType = (SToken*)&PTOKENS[i];
            continue;
        }

        if (!funcName) {
            if (PTOKENS[i].type != TOKEN_LITERAL) {
                Debug::log(ERR, "Invalid token", "Token %i is invalid. Got %s, expected TOKEN_LITERAL", i, PTOKENS[i].raw.c_str());
                return false;
            }

            funcName = (SToken*)&PTOKENS[i];
            continue;
        }

        if (PTOKENS[i].type != TOKEN_OPEN_PARENTHESIS) {
            // error, expecting an arg list
            Debug::log(ERR, "Invalid token", "Token %i is invalid. Got %s, expected TOKEN_OPEN_PARENTHESIS", i, PTOKENS[i].raw.c_str());
            return false;
        }

        i++;

        // if we are here, we add to the deque until we find a TOKEN_CLOSE_PARENTHESIS
        while (PTOKENS[i].type != TOKEN_CLOSE_PARENTHESIS) {

            if (PTOKENS[i].type != TOKEN_TYPE) {
                Debug::log(ERR, "Invalid token", "Token %i is invalid. Got %s, expected TOKEN_TYPE", i, PTOKENS[i].raw.c_str());
                return false;
            }

            if (PTOKENS[i + 1].type != TOKEN_LITERAL) {
                Debug::log(ERR, "Invalid token", "Token %i is invalid. Got %s, expected TOKEN_LITERAL", i + 1, PTOKENS[i].raw.c_str());
                return false;
            }

            funcParamsList.emplace_back(std::make_pair<SToken*, SToken*>((SToken*)&PTOKENS[i], (SToken*)&PTOKENS[i + 1]));

            if (PTOKENS[i + 2].type == TOKEN_COLON) {
                i++;
            }

            i += 2;
        }

        i++;

        while (PTOKENS[i].type == TOKEN_EMPTY)
            i++;

        if (PTOKENS[i].type != TOKEN_OPEN_CURLY) {
            Debug::log(ERR, "Invalid token", "Token %i is invalid. Got %s, expected TOKEN_OPEN_CURLY", i, PTOKENS[i].raw.c_str());
            return false;
        }

        // we should be ready to parse a function
        i++;
        m_iCurrentToken = i;
        if (!compileFunction(funcReturnType, funcName, funcParamsList))
            return false;
        
        funcName = nullptr;
        funcParamsList.clear();
        funcReturnType = nullptr;

        // find the end of the scope to jump to
        int openvsclose = 1;
        int jumpedTokens = 1;
        while (openvsclose != 0) {
            if (PTOKENS[i + jumpedTokens].type == TOKEN_CLOSE_CURLY)
                openvsclose--;
            else if (PTOKENS[i + jumpedTokens].type == TOKEN_OPEN_CURLY) {
                openvsclose++;
            }

            jumpedTokens++;

            if (PTOKENS.size() < i + jumpedTokens) {
                Debug::log(ERR, "Syntax error", "unclosed curly brace detected while parsing token %i (%s)", i, PTOKENS[i].raw.c_str());
                return false;
            }
        }

        i += jumpedTokens - 1; /* i++ in for */
    }

    return true;
}

void CCompiler::initializeBinary(uint16_t mainStart) {
    // first bytes initialize the stack and jump to the main.
    //
    // PC should start at 0x0

    BYTE bytes[] = {
        0x8E, 0xFF, 0xFF,                                             /* LDS #FFFF */
        0x7E, (uint8_t)(mainStart >> 8), (uint8_t)(mainStart & 0xFF)  /* JMP [start]*/
    };

    writeBytes(m_pBytes, bytes, 6);
}

bool CCompiler::compileFunction(SToken* returnType, SToken* name, std::deque<std::pair<SToken*, SToken*>>& args) {

    // create the function in memory
    SFunction newFunction;
    newFunction.signature = returnType->raw + "@" + name->raw + "(";
    for (auto&[type, arg] : args) {
        newFunction.signature += type->raw + "@" + arg->raw + ",";
    }

    if (!args.empty())
        newFunction.signature.pop_back();
    newFunction.signature += ");";

    // verify signature
    if (std::find_if(m_dFunctions.begin(), m_dFunctions.end(), [&] (const SFunction& other) { return other.signature == newFunction.signature; }) != m_dFunctions.end()) {
        Debug::log(ERR, "Error while compiling: duplicate function signature", "Function signature %s was defined more than once.", newFunction.signature);
        return -1;
    }

    newFunction.binaryBegin = m_iBytesSize;
    newFunction.returnType = returnType->raw;

    m_pCurrentFunction = &m_dFunctions.emplace_back(newFunction);

    // if this function is the main, do the init
    const bool ISMAIN = newFunction.signature == "U8@main();";
    if (ISMAIN)
        initializeBinary(newFunction.binaryBegin);

    /* signature -> stack offset */
    std::deque<SLocal> stackVariables;

    /* add locals */
    uint8_t stackOffset = 0;
    for (auto& arg : args) {
        stackVariables.push_back( { arg.first->raw + "@" + arg.second->raw, stackOffset++, true });
    }

    if (!compileScope(stackVariables, ISMAIN, true))
        return false;

    m_pCurrentFunction = nullptr;

    return true;
}

bool CCompiler::compileScope(std::deque<SLocal>& inheritedLocals, bool ISMAIN, bool ISFUNC) {
    // start compiling
    const std::deque<SToken>& PTOKENS = g_pLiTokenizer->m_dTokens;

    /* signature -> stack offset */
    std::deque<SLocal> stackVariables;

    auto findVariable = [&](SToken* TOKEN) -> SLocal* {
        
        const auto LASTPTR = TOKEN->raw.find_last_of('*');
        std::string tokenName = LASTPTR != std::string::npos ? TOKEN->raw.substr(LASTPTR + 1) : TOKEN->raw;

        for (auto& sv : stackVariables) {
            if (sv.name.substr(sv.name.find_first_of('@') + 1).find(tokenName) == 0) {
                // found the variable!
                return &sv;
            }
        }

        // check inherited vars
        for (auto& sv : inheritedLocals) {
            if (sv.name.substr(sv.name.find_first_of('@') + 1).find(tokenName) == 0) {
                // found the variable!
                return &sv;
            }
        }
        
        return nullptr;
    };

    std::function<bool(std::deque<SToken*>&, int)> compileExpression;

    // returns true if function found
    auto callFunction = [&](size_t& i) -> bool {
        int argno = 0;

        // maybe it's a function
        if (PTOKENS[i + 1].type == TOKEN_OPEN_PARENTHESIS) {
            // arg list
            int iter = 0;
            while (PTOKENS[i + 1 + iter].type != TOKEN_CLOSE_PARENTHESIS) {
                if (PTOKENS[i + 1 + iter].type == TOKEN_LITERAL)
                    argno++;

                iter++;
                
                if (i + 1 + argno >= PTOKENS.size()) {
                    Debug::log(ERR, "Syntax error", "unclosed parentheses", PTOKENS[i].raw.c_str());
                    return false;
                }
            }
        }

        const auto FUNCIT = std::find_if(m_dFunctions.begin(), m_dFunctions.end(), [&](const SFunction& other) {
            // U8@main(U8@name)
            auto NAME = other.signature.substr(other.signature.find_first_of('@') + 1);
            NAME = NAME.substr(0, NAME.find_first_of('('));

            auto ARGNO = std::count(other.signature.begin(), other.signature.end(), '@') - 1;

            if (NAME == PTOKENS[i].raw && argno == ARGNO) {
                return true;
            }

            return false;
        });

        if (FUNCIT == m_dFunctions.end()) {
            return false;
        }

        // calling convention:
        // push the args in the order they are defined (reverse on the stack)

        // push B
        {
            BYTE bytes[] = {
                0x37,
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
            m_iBytesSize += 1;
        }

        // Calling convention: push all the args to the stack in their order
        i += 2;
        int pushedVars = 0;
        while (argno > 0 && PTOKENS[i].type != TOKEN_CLOSE_PARENTHESIS) {
            if (i >= PTOKENS.size()) {
                Debug::log(ERR, "Syntax error", "unclosed parentheses", PTOKENS[i].raw.c_str());
                return false;
            }

            // compile to A
            std::deque<SToken*> tokensForExpr;
            while (PTOKENS[i].type != TOKEN_COLON && PTOKENS[i].type != TOKEN_CLOSE_PARENTHESIS) {
                tokensForExpr.emplace_back((SToken*)&PTOKENS[i]);
                i++;
            }

            compileExpression(tokensForExpr, 1);

            BYTE bytes[] = {
                0x36
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
            m_iBytesSize += 1;
            pushedVars++;
        }

        // jump to subroutine
        {
            BYTE bytes[] = {
                0xBD, (uint8_t)((uint16_t)FUNCIT->binaryBegin >> 8), (uint8_t)((uint16_t)FUNCIT->binaryBegin & 0xFF)
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 3);
            m_iBytesSize += 3;
        }

        // Calling convention: pop the stack vars
        for (int j = 0; j < pushedVars; ++j) {
            BYTE bytes[] = {
                0x33 /* PULB */
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
            m_iBytesSize += 1;
        }

        // pop B and update IR
        {
            BYTE bytes[] = {
                0x33,
                0x30 /* TSX */
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
            m_iBytesSize += 2;
        }

        return true;
    };

    auto loadTokenToAccumulator = [&](SToken* token, bool accA) -> bool {
        if (isNumber(token->raw, false)) {
            int CONSTANT = toInt(token->raw);
            if (CONSTANT > UINT8_MAX) {
                Debug::log(WARN, "Constant overflow", "constant %i will overflow in the expression.", CONSTANT);
            }

            BYTE bytes[] = {
                accA ? 0x86 : 0xC6, (uint8_t)CONSTANT
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
            m_iBytesSize += 2;
        } else {
            auto pVariable = findVariable(token);

            if (!pVariable) {
                // get token's i
                size_t foundI = 0;
                for (size_t i = 0; i < PTOKENS.size(); ++i) {
                    if (&PTOKENS[i] == token) {
                        foundI = i;
                        break;
                    }
                }

                if (!accA) {
                    // we need to save the Acc A
                    BYTE bytes[] = {
                        0x36 /* PSHA */
                    };
                    writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
                    m_iBytesSize += 1;
                }

                if (!callFunction(foundI)) {
                    Debug::log(ERR, "Syntax error", "requested variable %s was not declared.", token->raw.c_str());
                    return false;
                } else {
                    // we got the var in A.
                    // Additionally, if !accA, restore A and push to B
                    if (!accA) {
                        BYTE bytes[] = {
                            0x16, /* TAB */
                            0x32 /* PULA */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                        m_iBytesSize += 2;
                    }

                    return true;
                }
            }

            // dereference if needed
            if (token->raw[0] == '*') {
                BYTE bytes[] = {
                    0xEE, (uint8_t)(pVariable->funcParam ? (m_pCurrentFunction->stackOffset - 1 - pVariable->offset) + 2 : (m_pCurrentFunction->stackOffset - 1 - pVariable->offset)), /* LDX [our var] */
                    accA ? 0xA6 : 0xE6, 0x00,                                                                                                                                  /* LDA A/B 0,[X] */
                    0x30,                                                                                                                                                      /* TSX  - revert our damage to the IR */
                };
                writeBytes(m_pBytes + m_iBytesSize, bytes, 5);
                m_iBytesSize += 5;
            } else {
                BYTE bytes[] = {
                    accA ? 0xA6 : 0xE6, (uint8_t)(pVariable->funcParam ? (m_pCurrentFunction->stackOffset - 1 - pVariable->offset) + 2 : (m_pCurrentFunction->stackOffset - 1 - pVariable->offset))
                };
                writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                m_iBytesSize += 2;
            }
        }

        return true;
    };

    // will compile the expression and put the result in ACC B, or A if resultAccumulator is 1
    compileExpression = [&](std::deque<SToken*>& TOKENS, int resultAccumulator = 0) -> bool {
        // operate from left to right
        if (TOKENS.size() == 0)
            return true;

        if (TOKENS.size() == 1) {
            if (!loadTokenToAccumulator(TOKENS[0], resultAccumulator ? true : false))
                return false;
        } else {

            // shunting yard algorithm
            // we return a vec of vecs, because functions will be contained that way.
            std::vector<std::vector<SToken*>> RPNTokens;
            if (!performSYA(TOKENS, RPNTokens))
                return false;

            // now we have it in RPN. Calculating that is easy. We'll use the stack extensively, but who caares. It's easy that way.

            for (size_t i = 0; i < RPNTokens.size(); i++) {
                const auto TOKEN = RPNTokens[i];

                if (TOKEN[0]->type != TOKEN_OPERATOR) {
                    // literal (or func). Load and push onto the stack.
                    // TODO: this is broken with functions for some reason.
                    if (!loadTokenToAccumulator(TOKEN[0], true))
                        return false;

                    // now, push A onto the stack
                    BYTE bytes[] = {
                        0x36 /* PSHA */
                    };
                    writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
                    m_iBytesSize += 1;

                    m_pCurrentFunction->stackOffset++;
                } else {
                    // operator. pop last 2 / 1 values and do math. then push.

                    if (TOKEN[0]->raw == "~" || TOKEN[0]->raw == "!") {
                        // one-param operator. Only AccA
                        BYTE bytes[] = {
                            0x32  /* PUL A*/
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
                        m_iBytesSize += 1;

                        m_pCurrentFunction->stackOffset -= 1;
                    } else {
                        // two-param operator, accA and B.
                        BYTE bytes[] = {
                            0x33, /* PUL B */
                            0x32  /* PUL A*/
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                        m_iBytesSize += 2;

                        m_pCurrentFunction->stackOffset -= 2;
                    }

                    // perform the operation
                    if (TOKEN[0]->raw == "+") {
                        BYTE bytes[] = {
                            0x1B /* ABA */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
                        m_iBytesSize += 1;
                    } else if (TOKEN[0]->raw == "-") {
                        BYTE bytes[] = {
                            0x10 /* SBA */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
                        m_iBytesSize += 1;
                    } else if (TOKEN[0]->raw == "*") {
                        BYTE bytes[] = {
                            0xC1, 0x00,            /* CMPB #0 */
                            0x26, 0x04,            /* BNE [skip 0]*/
                            0x86, 0x00,            /* LDA #0 */
                            0x20, 0x0C,            /* skip 0: BRA [end] */
                            0x5A,                  /* DEC B (because * 1 is done)*/
                            0x36,                  /* PSH A*/
                            0x30,                  /* TSX */
                            0xAB, 0x00,            /* back: ADDA [the thing we pushed] */
                            0x5A,                  /* DEC B*/
                            0xC1, 0x00,            /* CMPB #0 */
                            0x26, (uint8_t)(-0x8), /* BNE [back]*/
                            0x33,                  /* PULB (clean the stack)*/
                            0x30,                  /* TSX */
                            /* end */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 20);
                        m_iBytesSize += 20;
                    } else if (TOKEN[0]->raw == "/") {
                        Debug::log(ERR, "Syntax error", "/ not implemented");
                    } else if (TOKEN[0]->raw == ">") {
                        BYTE bytes[] = {
                            0x11,       /* CBA */
                            0x23, 0x04, /* BLS +4 */
                            0x86, 0x01, /* LDAA 0x01 */
                            0x20, 0x02, /* BRA + 2 */
                            0x86, 0x00, /* LDAA 0x00 */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 9);
                        m_iBytesSize += 9;
                    } else if (TOKEN[0]->raw == "<") {
                        BYTE bytes[] = {
                            0x5A,       /* DECB #1 because BHI is > only */
                            0x11,       /* CBA */
                            0x22, 0x04, /* BHI +4 */
                            0x86, 0x01, /* LDAA 0x00 */
                            0x20, 0x02, /* BRA + 2 */
                            0x86, 0x00, /* LDAA 0x01 */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 10);
                        m_iBytesSize += 10;
                    } else if (TOKEN[0]->raw == "==") {
                        BYTE bytes[] = {
                            0x10,       /* SBA */
                            0x27, 0x04, /* BEQ +4 */
                            0x86, 0x00, /* LDAA 0x00 */
                            0x20, 0x02, /* BRA + 2 */
                            0x86, 0x01, /* LDAA 0x01 */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 9);
                        m_iBytesSize += 9;
                    } else if (TOKEN[0]->raw == "!=") {
                        BYTE bytes[] = {
                            0x10,       /* SBA */
                            0x27, 0x04, /* BEQ +4 */
                            0x86, 0x01, /* LDAA 0x01 */
                            0x20, 0x02, /* BRA + 2 */
                            0x86, 0x00, /* LDAA 0x00 */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 9);
                        m_iBytesSize += 9;
                    } else if (TOKEN[0]->raw == "&") {
                        BYTE bytes[] = {
                            0x37,       /* PSH B */
                            0x30,       /* TSX */
                            0xA4, 0x00, /* ANDA 0,X */
                            0x33,       /* PUL B */
                            0x30        /* TSX */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 6);
                        m_iBytesSize += 6;
                    } else if (TOKEN[0]->raw == "|") {
                        BYTE bytes[] = {
                            0x37,       /* PSH B */
                            0x30,       /* TSX */
                            0xAA, 0x00, /* ORAA 0,X */
                            0x33,       /* PUL B */
                            0x30        /* TSX */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 6);
                        m_iBytesSize += 6;
                    } else if (TOKEN[0]->raw == "||") {
                        // TODO: this can be optimized when I add RPN
                        // && too
                        BYTE bytes[] = {
                            0x4D,       /* TSTA */
                            0x26, 0x06, /* BNE +6 */
                            0x5D,       /* TST B */
                            0x26, 0x03, /* BNE +3 */
                            0x4F,       /* CLRA */
                            0x20, 0x02, /* BRA +2 */
                            0x86, 0x01  /* LDAA #1 */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 11);
                        m_iBytesSize += 11;
                    } else if (TOKEN[0]->raw == "&&") {
                        BYTE bytes[] = {
                            0x4D,       /* TSTA */
                            0x27, 0x07, /* BEQ +7 */
                            0x5D,       /* TST B */
                            0x27, 0x04, /* BEQ +4 */
                            0x86, 0x01, /* LDAA #1 */
                            0x20, 0x01, /* BRA +1 */
                            0x4F        /* CLRA */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 11);
                        m_iBytesSize += 11;
                    } else if (TOKEN[0]->raw == "~") {
                        BYTE bytes[] = {
                            0x40,       /* NEGA */
                            0x4A        /* DEC A */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                        m_iBytesSize += 2;
                    } else if (TOKEN[0]->raw == "!") {
                        BYTE bytes[] = {
                            0x40,       /* NEGA */
                            0x4A,        /* DEC A */
                            0x84, 0x01  /* ANDA #1 */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 4);
                        m_iBytesSize += 4;
                    }

                    // done. Push the result back onto the stack.
                    {
                        BYTE bytes[] = {
                            0x36, /* PSHA */
                            0x30, /* TSX */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                        m_iBytesSize += 2;

                        m_pCurrentFunction->stackOffset++;
                    }
                }
            }

            // done. Let's pop the final result to the desired Accumulator
            // and fix the IR
            BYTE bytes[] = {
                resultAccumulator == 0 ? 0x33 : 0x32, /* PUL B/A */
                0x30 /* TSX, might've gotten bad if there was multiplication */
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
            m_iBytesSize += 2;

            m_pCurrentFunction->stackOffset--;
        }
        
        return true;
    };

    auto popAllLocals = [&](bool accB = false) -> void {
        for (auto it = stackVariables.rbegin(); it != stackVariables.rend(); it++) {
            // pop variable off the stack, to A (doesn't matter)
            BYTE bytes[] = {
                accB ? 0x33 : 0x32
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
            m_iBytesSize += 1;

            m_pCurrentFunction->stackOffset -= 1;
        }

        // fix up the IR
        BYTE bytes[] = {
            0x30 /* TSX */
        };
        writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
        m_iBytesSize += 1;
    };

    if (ISFUNC) {
        if (ISMAIN) {
            // init the IR
            BYTE bytes[] = {
                0xCE, 0xFF, 0xFF /* LDX 0xFFFF */
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 3);
            m_iBytesSize += 3;
        } else {
            // init the IR
            BYTE bytes[] = {
                0x30 /* TSX */
            };
            writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
            m_iBytesSize += 1;
        }
    }
    

    for (size_t i = m_iCurrentToken; PTOKENS[i].type != TOKEN_CLOSE_CURLY; i++) {
        const auto TOKEN = &PTOKENS[i];
        m_iCurrentToken = i;

        if (TOKEN->type == TOKEN_SEMICOLON)
            continue;

        if (TOKEN->type == TOKEN_KEYWORD) {
            // keyword. Parse it.

            if (TOKEN->raw == "return") {
                // end of function. Let's push the return value to A and do a RET.
                // in the case of main, we do a WAI and bail out.

                if (isNumber(PTOKENS[i + 1].raw, false)) {
                    // pop the locals before return
                    popAllLocals();

                    // easy, just use a constant
                    int CONSTANT = toInt(PTOKENS[i + 1].raw);
                    if (CONSTANT > UINT8_MAX) {
                        Debug::log(WARN, "Constant overflow", "The return constant %i will overflow in the return value.", CONSTANT);
                    }

                    BYTE bytes[] {
                        0x86, (uint8_t)CONSTANT, /* LDAA #CONSTANT */
                        ISMAIN ? 0x3E : 0x39     /* WAI / RTS */
                    };

                    writeBytes(m_pBytes + m_iBytesSize, bytes, 3);
                    m_iBytesSize += 3;

                    i += 2; /* +1 with for */
                } else {
                    
                    // it's an expression
                    std::deque<SToken*> tokensForExpr;
                    i += 1;
                    while (PTOKENS[i].type != TOKEN_SEMICOLON) {
                        tokensForExpr.emplace_back((SToken*)&PTOKENS[i]);
                        i++;
                    }

                    compileExpression(tokensForExpr, 1); // store to A, for our return

                    // pop the locals before return
                    popAllLocals(true /* pul to B to not overwrite A */);

                    BYTE bytes[] {
                        ISMAIN ? 0x3E : 0x39     /* WAI / RTS */
                    };

                    writeBytes(m_pBytes + m_iBytesSize, bytes, 1);
                    m_iBytesSize += 1;
                }

                if (PTOKENS[i + 1].type == TOKEN_CLOSE_CURLY) {
                    // end, we dont have to pop locals
                    stackVariables.clear();
                }
            } else if (TOKEN->raw == "while") {
                // while loop, get the cond first

                if (PTOKENS[i + 1].type != TOKEN_OPEN_PARENTHESIS) {
                    Debug::log(ERR, "Syntax error", "expected expression in () after while", TOKEN->raw.c_str());
                    return false;
                }

                i += 2;
                std::deque<SToken*> tokensForExpr;
                while (PTOKENS[i].type != TOKEN_CLOSE_PARENTHESIS) {
                    tokensForExpr.emplace_back((SToken*)&PTOKENS[i]);
                    i++;

                    if (i >= PTOKENS.size()) {
                        Debug::log(ERR, "Syntax error", "unclosed parentheses", TOKEN->raw.c_str());
                        return false;
                    }
                }

                const uint16_t CHECKPOS = m_iBytesSize;

                compileExpression(tokensForExpr, 1);

                const uint16_t AFTERCHECKPOS = m_iBytesSize;

                // Acc A has the result.
                {
                    // check if acc A 0 and if so, exit
                    BYTE bytes[] = {
                        0x4D,            /* TST A */
                        0x26, 0x03,      /* BNE [after] */
                        0x7E, 0xFF, 0xFF /* JMP [placeholder, after loop]*/
                    };
                    writeBytes(m_pBytes + m_iBytesSize, bytes, 6);
                    m_iBytesSize += 6;
                }

                std::deque<SLocal> parentStack;
                for (auto& il : inheritedLocals) {
                    parentStack.emplace_back(il);
                }
                for (auto& il : stackVariables) {
                    parentStack.emplace_back(il);
                }

                i++;
                m_iCurrentToken = i;

                compileScope(parentStack, ISMAIN);

                i = m_iCurrentToken;

                // jump back
                {
                    {
                        BYTE bytes[] = {
                            0x7E, (uint8_t)(CHECKPOS >> 8), (uint8_t)(CHECKPOS & 0xFF), /* JMP [begin of test] */
                        };
                        writeBytes(m_pBytes + m_iBytesSize, bytes, 3);
                        m_iBytesSize += 3;
                    }

                    // overwrite the placeholder before
                    {
                        BYTE bytes[] = {
                            (uint8_t)(m_iBytesSize >> 8), (uint8_t)(m_iBytesSize & 0xFF), /* JMP [end] */
                        };
                        writeBytes(m_pBytes + AFTERCHECKPOS + 4, bytes, 2);
                    }
                }
            } else if (TOKEN->raw == "if") {
                if (PTOKENS[i + 1].type != TOKEN_OPEN_PARENTHESIS) {
                    Debug::log(ERR, "Syntax error", "expected expression in () after if", TOKEN->raw.c_str());
                    return false;
                }

                i += 2;
                std::deque<SToken*> tokensForExpr;
                int parenthdiff = 1;
                while (parenthdiff != 0) {
                    tokensForExpr.emplace_back((SToken*)&PTOKENS[i]);
                    i++;

                    if (PTOKENS[i].type == TOKEN_OPEN_PARENTHESIS)
                        parenthdiff++;
                    else if (PTOKENS[i].type == TOKEN_CLOSE_PARENTHESIS)
                        parenthdiff--;

                    if (i >= PTOKENS.size()) {
                        Debug::log(ERR, "Syntax error", "unclosed parentheses", TOKEN->raw.c_str());
                        return false;
                    }
                }

                compileExpression(tokensForExpr, 1);

                const uint16_t AFTERCHECKPOS = m_iBytesSize;

                // Acc A has the result.
                {
                    // check if acc A 0 and if so, exit
                    BYTE bytes[] = {
                        0x4D,            /* TST A */
                        0x26, 0x03,      /* BNE [after] */
                        0x7E, 0xFF, 0xFF /* JMP [placeholder, after if]*/
                    };
                    writeBytes(m_pBytes + m_iBytesSize, bytes, 6);
                    m_iBytesSize += 6;
                }

                {
                    std::deque<SLocal> parentStack;
                    for (auto& il : inheritedLocals) {
                        parentStack.emplace_back(il);
                    }
                    for (auto& il : stackVariables) {
                        parentStack.emplace_back(il);
                    }

                    i += 2;
                    m_iCurrentToken = i;

                    compileScope(parentStack, ISMAIN);

                    i = m_iCurrentToken;
                }

                // check if this is an else
                if (PTOKENS[i + 1].raw == "else") {
                    // first, add an unconditional jump for the above if
                    const uint16_t AFTERIFBLOCK = m_iBytesSize;
                    {
                        // check if acc A 0 and if so, exit
                        {
                            BYTE bytes[] = {
                                0x7E, 0xFF, 0xFF /* JMP [placeholder, after else]*/
                            };
                            writeBytes(m_pBytes + m_iBytesSize, bytes, 3);
                            m_iBytesSize += 3;
                        }

                        // overwrite the above placeholder to jump to the else block
                        {
                            BYTE bytes[] = {
                                (uint8_t)(m_iBytesSize >> 8), (uint8_t)(m_iBytesSize & 0xFF), /* JMP [here] */
                            };
                            writeBytes(m_pBytes + AFTERCHECKPOS + 4, bytes, 2);
                        }
                    }

                    // write the block
                    {
                        std::deque<SLocal> parentStack;
                        for (auto& il : inheritedLocals) {
                            parentStack.emplace_back(il);
                        }
                        for (auto& il : stackVariables) {
                            parentStack.emplace_back(il);
                        }

                        i += 3;
                        m_iCurrentToken = i;

                        compileScope(parentStack, ISMAIN);

                        i = m_iCurrentToken;
                    }

                    // overwrite the placeholder before
                    {
                        BYTE bytes[] = {
                            (uint8_t)(m_iBytesSize >> 8), (uint8_t)(m_iBytesSize & 0xFF), /* JMP [end] */
                        };
                        writeBytes(m_pBytes + AFTERIFBLOCK + 1, bytes, 2);
                    }
                } else {
                    // overwrite the placeholder before to just jump here
                    {
                        BYTE bytes[] = {
                            (uint8_t)(m_iBytesSize >> 8), (uint8_t)(m_iBytesSize & 0xFF), /* JMP [here] */
                        };
                        writeBytes(m_pBytes + AFTERCHECKPOS + 4, bytes, 2);
                    }
                }
            }
        } else if (TOKEN->type == TOKEN_TYPE) {
            // probably a variable.

            if (PTOKENS[i + 1].type != TOKEN_LITERAL) {
                Debug::log(ERR, "Syntax error", "expected a TOKEN_LITERAL after a TOKEN_TYPE (token %i)", i);
                return false;
            }

            if (PTOKENS[i + 2].raw != "=") {
                Debug::log(ERR, "Syntax error", "expected a = after a variable definition", i);
                return false;
            }

            // the rest is an expression.
            std::deque<SToken*> tokensForExpr;
            
            const SToken* TYPETOKEN = TOKEN;
            const SToken* NAMETOKEN = &PTOKENS[i + 1];

            if (TYPETOKEN->raw == "U0") {
                Debug::log(ERR, "Syntax error", "a variable cannot be U0", i);
                return false;
            }

            i += 3;

            while (PTOKENS[i].type != TOKEN_SEMICOLON) {
                tokensForExpr.emplace_back((SToken*)&PTOKENS[i]);
                i++;
            }

            // compile expr
            if (!compileExpression(tokensForExpr, 0 /* Acc B will have the result */))
                return false;

            // register new local
            m_pCurrentFunction->stackOffset += 1;
            stackVariables.push_back(SLocal{TYPETOKEN->raw + "@" + NAMETOKEN->raw, (uint8_t)(m_pCurrentFunction->stackOffset - 1) /* first var at 0 */, false});

            {
                BYTE bytes[] {
                    0x37, /* PSH B */
                    0x30,  /* TSX */
                };

                writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                m_iBytesSize += 2;
            }

            // finish
        } else if (TOKEN->type == TOKEN_LITERAL) {
            const auto pVariable = findVariable((SToken*)TOKEN);

            if (!pVariable) {

                if (callFunction(i)) {
                    i--;  // for i++ later
                    continue;
                }    

                Debug::log(ERR, "Syntax error", "requested variable %s was not declared.", TOKEN->raw.c_str());
                return false;
            }

            const auto OPERATION = &PTOKENS[i + 1];
            if (OPERATION->raw != "=" || i + 2 >= PTOKENS.size()) {
                Debug::log(ERR, "Syntax error", "expected assignment after variable", TOKEN->raw.c_str());
                return false;
            }

            // calc expr to Acc A
            i += 2;
            std::deque<SToken*> tokensForExpr;
            while (PTOKENS[i].type != TOKEN_SEMICOLON) {
                tokensForExpr.emplace_back((SToken*)&PTOKENS[i]);
                i++;
            }

            // if this is a dereference,
            if (TOKEN->raw[0] == '*') {
                compileExpression(tokensForExpr, 0);

                // store whatever we have to the memory pointed by the variable
                BYTE bytes[] = {
                    0xEE, (uint8_t)(pVariable->funcParam ? (m_pCurrentFunction->stackOffset - 1 - pVariable->offset) + 2 : (m_pCurrentFunction->stackOffset - 1 - pVariable->offset)), /* LDX [our var] */
                    0xE7, 0x00,                                                                        /* STA B 0,[X] */
                    0x30,                                                                              /* TSX  - revert our damage to the IR */
                };
                writeBytes(m_pBytes + m_iBytesSize, bytes, 5);
                m_iBytesSize += 5;
            } else {
                compileExpression(tokensForExpr, 1);

                // copy value from A to the variable
                BYTE bytes[] = {
                    0xA7, (uint8_t)(pVariable->funcParam ? (m_pCurrentFunction->stackOffset - 1 - pVariable->offset) + 2 : (m_pCurrentFunction->stackOffset - 1 - pVariable->offset))
                };
                writeBytes(m_pBytes + m_iBytesSize, bytes, 2);
                m_iBytesSize += 2;
            }
        }

        m_iCurrentToken = i;
    }

    m_iCurrentToken++;

    // check for any locals to pop
    popAllLocals();

    return true;
}

void CCompiler::writeBytes(void* begin, BYTE* bytes, size_t len) {
    memcpy(begin, bytes, len);
}

void CCompiler::SOptimizer::updateByteStartPositions() {
    byteStartPositions.clear();
    for (size_t i = 0; i < p->m_iBytesSize; ++i) {
        byteStartPositions.emplace_back(i);

        const auto SIZE = OPERATIONS_SIZE[p->m_pBytes[i]];

        if (SIZE == 0)
            throw std::logic_error("tried to access size of invalid opcode!");

        i += SIZE - 1;  // +1 for ++i in for
        continue;
    }
}

void CCompiler::SOptimizer::fixAddressesAfterRemove(size_t where, size_t lenRemoved) {
    for (size_t i = 0; i < p->m_iBytesSize; i = getNextByteStart(i)) {
        // check opcode
        if (isRelative(p->m_pBytes[i])) {
            // check if it concerns us
            const auto OPCODELEN = OPERATIONS_SIZE[p->m_pBytes[i]];

            if (OPCODELEN == 0)
                throw std::logic_error("tried to access size of invalid opcode!");

            const bool LEFTSIDEOPCODE = i < where;
            const bool LEFTSIDEDESTINATION = OPCODELEN == 2 ? i + (int8_t)p->m_pBytes[i + 1] < where - 1 : (uint16_t)(((uint16_t)p->m_pBytes[i + 1]) * 0x100 + p->m_pBytes[i + 2]) < where - 1;

            if (LEFTSIDEDESTINATION == LEFTSIDEOPCODE) {
                // no fix needed for this op if it's relative or we are on the left
                if (OPCODELEN == 2 || LEFTSIDEDESTINATION)
                    continue;

                // otherwise, shift to the left
                uint16_t address = (uint16_t)((((uint16_t)p->m_pBytes[i + 1]) << 8) + p->m_pBytes[i + 2]);
                address -= lenRemoved;
                p->m_pBytes[i + 1] = (uint8_t)(address >> 8);
                p->m_pBytes[i + 2] = (uint8_t)(address & 0xFF);
                continue;
            }

            // we need to fix this op
            if (OPCODELEN == 2) {
                if (LEFTSIDEOPCODE) {
                    // right side dest, moved left, subtract len
                    p->m_pBytes[i + 1] -= lenRemoved;
                } else {
                    // left side dest, moved right, add len
                    p->m_pBytes[i + 1] += lenRemoved;
                }
            } else {
                // this is an absolute address
                uint16_t address = (uint16_t)((((uint16_t)p->m_pBytes[i + 1]) << 8) + p->m_pBytes[i + 2]);
                if (LEFTSIDEOPCODE) {
                    // right side dest, moved left, subtract len
                    address -= lenRemoved;

                    // save back
                    p->m_pBytes[i + 1] = (uint8_t)(address >> 8);
                    p->m_pBytes[i + 2] = (uint8_t)(address & 0xFF);
                }

                // if the absolute addr is to the left, ignore. It did not change.
            }
        }
    }
}

size_t CCompiler::SOptimizer::getLastByteStart(size_t cur) {
    for (size_t i = 0; i < byteStartPositions.size(); ++i) {
        if (byteStartPositions[i] >= cur)
            return byteStartPositions[--i];
    }

    return 0;
};

size_t CCompiler::SOptimizer::getNextByteStart(size_t cur) {
    for (size_t i = 0; i < byteStartPositions.size(); ++i) {
        if (byteStartPositions[i] >= cur && i + 1 < byteStartPositions.size())
            return byteStartPositions[++i];
    }

    return 0;
};

bool CCompiler::SOptimizer::isRelative(uint8_t byte) {
    // todo: this is horrible
    return byte == 0x24 || byte == 0x25 || byte == 0x27 || byte == 0x2C || byte == 0x2E || byte == 0x22 || byte == 0x2F || byte == 0x23 || byte == 0x2D || byte == 0x2D || byte == 0x2B || byte == 0x26 || byte == 0x2A || byte == 0x20 || byte == 0x8D || byte == 0x28 || byte == 0x29 || byte == 0x6E || byte == 0x7E || byte == 0xAD || byte == 0xBD;
};

bool CCompiler::SOptimizer::isRetWai(uint8_t byte) {
    return byte == 0x3E || byte == 0x39;
};

bool CCompiler::SOptimizer::isPush(uint8_t byte) {
    return byte == 0x37 || byte == 0x36;
};

bool CCompiler::SOptimizer::isClear(uint8_t byte) {
    return byte == 0x4F || byte == 0x5F;
};

// ignores 16-bit EXT LDAs
bool CCompiler::SOptimizer::isLoad(uint8_t byte) {
    return byte == 0x86 || byte == 0x96 || byte == 0xA6 || byte == 0xC6 || byte == 0xD6 || byte == 0xE6;
};

void CCompiler::SOptimizer::optimizeBinary() {

    std::chrono::system_clock::time_point begin = std::chrono::system_clock::now();

    // go through all the bytes and check all our optimization mechanisms

    size_t removedBytes = 0;

    updateByteStartPositions();

    auto removeBytes = [&](size_t where, size_t howMany) -> void {
        memmove(p->m_pBytes + where, p->m_pBytes + where + howMany, p->m_iBytesSize - where - howMany);

        updateByteStartPositions();

        p->m_iBytesSize -= howMany;
        removedBytes += howMany;

        fixAddressesAfterRemove(where, howMany);
    };

    for (size_t i = 0; i < p->m_iBytesSize; i = getNextByteStart(i)) {
        if (p->m_pBytes[i] == 0x30 /* TSX */ && i + 1 < p->m_iBytesSize && p->m_pBytes[i + 1] == 0x30) {
            // multi-TSX optimization

            int countTSX = 0;
            int iter = 0;
            while (p->m_pBytes[i + iter] == 0x30) {
                countTSX++;
                iter++;
            }

            removeBytes(i + 1, countTSX - 1);
        }

        if (p->m_pBytes[i] == 0x30 /* TSX */ && i + 1 < p->m_iBytesSize && isRetWai(p->m_pBytes[i + 1])) {
            /* TSX before RTS/WAI */

            removeBytes(i, 1);
        }

        if (p->m_pBytes[i] == 0x3E /* WAI */ && i + 1 < p->m_iBytesSize) {
            // stuff after last WAI

            bool foundAnother = false;
            for (size_t j = i; j < p->m_iBytesSize; j = getNextByteStart(j)) {
                if (p->m_pBytes[j] == 0x3E) {
                    foundAnother = true;
                    break;
                }
            }

            if (!foundAnother) {
                size_t howMany = p->m_iBytesSize - i - 1;

                memset(p->m_pBytes + i + 1, 0x00, howMany);
                p->m_iBytesSize -= howMany;
                removedBytes += howMany;
            }
        }

        if (isPush(p->m_pBytes[i]) && i + 1 < p->m_iBytesSize) {
            // possible TSX simplification

            // checks if we can remove the TSX that is above the LDA before the PSH

            const auto LASTBYTE = getLastByteStart(i);
            const auto LASTBYTE2 = getLastByteStart(LASTBYTE);
            const auto NEXTBYTE = getNextByteStart(i);

            if (i - 4 > 0 && (isLoad(p->m_pBytes[LASTBYTE]) || isClear(p->m_pBytes[LASTBYTE])) && p->m_pBytes[LASTBYTE2] == 0x30 /* TSX */ && p->m_pBytes[NEXTBYTE] == 0x30 /* TSX */) {
                i = LASTBYTE2; // go back to the TSX place

                // simplify the TSX
                removeBytes(i, 1);

                // done
            }
        }

        if (isLoad(p->m_pBytes[i])) {

            const auto NEXTBYTE = getNextByteStart(i);
            const auto NEXTBYTE2 = getNextByteStart(NEXTBYTE);

            if (NEXTBYTE && NEXTBYTE2 && p->m_pBytes[NEXTBYTE] == 0xC6 /* LDA B #constant */ && p->m_pBytes[NEXTBYTE2] == 0x1B) {
                // we can turn
                //
                // LDAA <something>
                // LDAB #const
                // ABA
                //
                // into
                //
                // LDAA <something>
                // ADDA #const
                //
                // furthermore if ADDA is +1 we can do an INC A

                const auto NEXTBYTE3 = getNextByteStart(NEXTBYTE2);

                // simplify this to an in-place INC if possible (LDAA LDAB ABA STAA)
                if ((p->m_pBytes[NEXTBYTE3] == 0xA7 || p->m_pBytes[NEXTBYTE3] == 0xE7) && (p->m_pBytes[i] == 0xA6 || p->m_pBytes[i] == 0xE6)) {
                    

                    // offset is in i + 1
                    p->m_pBytes[i] = 0x6C; // INC data8,X
                    // i + 1 is correct

                    // rest are to be removed,
                    removeBytes(i + 1, 5);
                } else {
                    p->m_pBytes[NEXTBYTE] = 0x8B;

                    if (p->m_pBytes[NEXTBYTE + 1] == 0x01) {
                        p->m_pBytes[NEXTBYTE] = 0x4C;
                        removeBytes(NEXTBYTE + 1, 2);
                    } else {
                        removeBytes(NEXTBYTE + 2, 1);
                    }
                }
            }
        }

        if (p->m_pBytes[i] == 0x7E /* JMP <addr16> */) {
            // check if we can turn this into a BRA
            uint16_t address = (uint16_t)((((uint16_t)p->m_pBytes[i + 1]) << 8) + p->m_pBytes[i + 2]);

            if (abs(address - i) < 127) {
                // yes we can!
                p->m_pBytes[i] = 0x20; // BRA
                p->m_pBytes[i + 1] = (int8_t)(address - i - 2 /* BRA adds 2 */); // offset
                removeBytes(i + 2, 1);
            }
        }

        if ((p->m_pBytes[i] == 0x86 || p->m_pBytes[i] == 0xC6) && p->m_pBytes[i + 1] == 0x00) {
            // LDA A/B 0 -> CLR A/B
            p->m_pBytes[i] = p->m_pBytes[i] == 0x86 ? 0x4F : 0x5F;
            removeBytes(i + 1, 1);
        }

        if (i + 1 < p->m_iBytesSize && p->m_pBytes[i] == 0x36 /* PSHA */ && p->m_pBytes[i + 1] == 0x32 /* PULA */) {
            // generated by the RPN notations.
            // optimize out completely
            removeBytes(i, 2);
        }
    }

    memset(p->m_pBytes + p->m_iBytesSize, 0x00, removedBytes + 1);

    Debug::log(LOG, "Optimization complete.", "Elapsed: %.2fms. Bytes optimized out: %i (-%.2f%)",
               std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now() - begin).count() / 1000.f,
               removedBytes,
               ((double)removedBytes / (double)(p->m_iBytesSize + removedBytes)) * 100.0);
}

bool CCompiler::performSYA(std::deque<SToken*>& input, std::vector<std::vector<SToken*>>& output) {

    std::deque<SToken*> operatorStack;

    auto operatorLowerPrecedence = [&] (SToken* what, SToken* from) -> bool {
        return std::find(BUILTIN_OPERATORS.begin(), BUILTIN_OPERATORS.end(), what->raw) > std::find(BUILTIN_OPERATORS.begin(), BUILTIN_OPERATORS.end(), from->raw);
    };

    for (size_t i = 0; i < input.size(); ++i) {
        SToken* token = input[i];

        // check if this is a function with parentheses
        if (i + 1 < input.size() && input[i + 1]->type == TOKEN_OPEN_PARENTHESIS) {
            // gotem
            std::vector<SToken*> toReturn;
            toReturn.push_back(token);
            toReturn.push_back(input[i + 1]);
            int parenthdiff = 1;
            size_t end = 0;
            while(parenthdiff > 0) {
                if (i + 2 + end >= input.size()) {
                    Debug::log(ERR, "Syntax error", "Unclosed parenthesis");
                    return false;
                }

                if (input[i + 2 + end]->type == TOKEN_OPEN_PARENTHESIS)
                    parenthdiff++;
                if (input[i + 2 + end]->type == TOKEN_CLOSE_PARENTHESIS)
                    parenthdiff--;

                toReturn.push_back(input[i + 2 + end]);

                end++;
            }

            toReturn.push_back(input[i + 2 + end]);

            // now we can return it
            output.emplace_back(toReturn);

            i = i + 2 + end;
            continue;
        } else if (token->type == TOKEN_LITERAL) {
            std::vector<SToken*> toReturn;
            toReturn.push_back(token);
            output.emplace_back(toReturn);
            continue;
        } else if (token->type == TOKEN_OPERATOR) {
            if (!operatorStack.empty() && operatorLowerPrecedence(token, operatorStack.back())) {
                // pop the stack to the output
                int topop = 0;
                for (auto it = operatorStack.rbegin(); it != operatorStack.rend(); it++) {

                    if (!operatorLowerPrecedence(token, *it))
                        break;

                    output.push_back({*it});
                    topop++;
                }

                for (int ii = 0; ii < topop; ii++)
                    operatorStack.pop_back();
            }

            operatorStack.push_back(token);
            continue;
        }

        Debug::log(ERR, "Syntax error", "Invalid syntax in expression, expected TOKEN_LITERAL, FUNCTION or TOKEN_OPERATOR");
        return false;
    }

    // pop the operator stack
    for (auto it = operatorStack.rbegin(); it != operatorStack.rend(); it++) {
        output.push_back({*it});
    }
    operatorStack.clear();

    return true;
}