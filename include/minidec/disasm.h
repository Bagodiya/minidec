#ifndef MINIDEC_DISASM_H
#define MINIDEC_DISASM_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace minidec {

// Our own enum so this header doesn't have to include capstone. Intel by
// default; att is the older GAS style.
enum class Syntax {
    intel,
    att,
};

// One decoded instruction, so nothing downstream touches capstone's cs_insn.
struct Instruction {
    std::uint64_t address = 0;          // virtual address of the first byte
    std::uint16_t size = 0;             // length of the instruction in bytes
    std::vector<std::uint8_t> bytes;    // the raw encoded bytes
    std::string mnemonic;               // e.g. "mov", "call", "ret"
    std::string op_str;                 // the operand text, e.g. "rax, rbx"

    // From capstone's instruction groups, so the CFG doesn't have to re-parse
    // the mnemonic to ask whether something branches.
    bool is_call = false;       // call instruction
    bool is_jump = false;       // jmp / jcc of any kind
    bool is_ret = false;        // ret / retf
    bool is_relative = false;   // target is a pc-relative offset (direct branch)

    // Anything that can send control somewhere other than the next instruction.
    bool is_branch() const { return is_call || is_jump || is_ret; }
};

// RAII around a capstone handle: ctor opens, dtor closes. Construct one, check
// is_open(), then feed it bytes.
//
// x86-64 only. The handle isn't cheap to open, so reuse one across functions.
class Disassembler {
public:
    // Defaults to Intel syntax; pass Syntax::att to get the GAS-style output.
    explicit Disassembler(Syntax syntax = Syntax::intel);
    ~Disassembler();

    // Move-only; copying would double-free the handle.
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;
    Disassembler(Disassembler&& other) noexcept;
    Disassembler& operator=(Disassembler&& other) noexcept;

    // False means the handle never came up and disassemble() returns empty.
    bool is_open() const { return opened_; }

    // Undecodable bytes -- data in code, padding, jump tables -- come back as
    // single-byte ".byte 0xNN" entries so the listing covers the whole range.
    std::vector<Instruction> disassemble(const std::uint8_t* code, std::size_t size,
                                         std::uint64_t address) const;

    // Convenience overload for when the bytes already live in a vector.
    std::vector<Instruction> disassemble(const std::vector<std::uint8_t>& code,
                                         std::uint64_t address) const {
        return disassemble(code.data(), code.size(), address);
    }

private:
    // Plain integer so this header needn't include capstone.h; csh is a size_t.
    std::size_t handle_ = 0;
    bool opened_ = false;
};

}  // namespace minidec

#endif  // MINIDEC_DISASM_H
