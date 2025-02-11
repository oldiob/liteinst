
#ifndef ASSEMBLY_H
#define ASSEMBLY_H 

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "distorm.h"
#include "mnemonics.h"

#include "defs.hpp"

namespace utils {
namespace assembly {

/// An encoded instruction sequence
class Code {
  public:
    int n_bytes;
    uint8_t* bytes;
};

/// A decoded sequence of instructions
class Sequence {
  public:
    int n_instructions;
    void* instructions;
    utils::Address start;
    utils::Address end;

    Sequence() : instructions(nullptr) {};

    ~Sequence(){ 
      delete[] static_cast<_DInst*>(instructions); 
    }
};

/// Encodes a given sequence of instructions
class Assembler {
  public:
    static const int JMP_REL8_SZ = 2;
    static const int JMP_REL32_SZ = 5;
    static const int COND_JMP8_SZ = 2;
    static const int COND_JMP32_SZ = 5;

    Assembler();
    ~Assembler();

    Code assemble(Sequence seq);
    int emitInstruction(_DInst ins, utils::Address target);
};

/// Decodes a sequence of encoded instructions
class Disassembler {
  public:
    const Sequence* disassemble(utils::Address start,
        utils::Address end);
    int findInstructionIndex(utils::Address instruction, 
        const Sequence* seq);
    int isControlTransferInstruction(const Sequence* seq,
        int index);
    
    // Instrospection methods
    bool isCall(const _DInst& ins);

    bool isNearCall(const _DInst& i);

    bool isDirectCall(const _DInst& i);

    bool isIndirectCall(const _DInst& i);

    bool isShortJump(const _DInst& i);
    
    bool isNearJump(const _DInst& i);

    bool isRelativeJump(const _DInst& i);

    bool isIndirectJump(const _DInst& i);

    bool isFarJump(const _DInst& ins);

    bool isUnconditionalJump(const _DInst& i);

    bool isConditionalJump(const _DInst& i);

    bool isJump(const _DInst& i);

    bool extractJumpTarget(const _DInst& i);

    // bool isUnconditionalBranch(const _DInst& i);

    // bool isConditionalBranch(const _DInst& i);

    // bool isBranch(const _DInst& i);

    bool isHalt(const _DInst& i);

    bool isReturn(const _DInst& ins);

    bool isControlTransfer(const _DInst& ins);
};

} // End assembly
} // End utils

#endif /*ASSEMBLY_H*/
