#ifndef MINIDEC_DISASM_H
#define MINIDEC_DISASM_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace minidec {

// Which assembly dialect capstone should print the operands in. Intel is what
// we default to (register first, no % or $ sigils) since it's what most people
// reading x86-64 today expect; att is the older GAS style. Kept as our own enum
// so the header doesn't have to include capstone just to name these.
enum class Syntax {
    intel,
    att,
};

// One decoded instruction. This is our own little struct so the rest of the
// program never has to touch capstone's cs_insn directly. The fields are the
// bits we actually use later: where it lives, how long it is, the raw bytes,
// and the text capstone gives us split into the mnemonic and its operands.
struct Instruction {
    std::uint64_t address = 0;          // virtual address of the first byte
    std::uint16_t size = 0;             // length of the instruction in bytes
    std::vector<std::uint8_t> bytes;    // the raw encoded bytes
    std::string mnemonic;               // e.g. "mov", "call", "ret"
    std::string op_str;                 // the operand text, e.g. "rax, rbx"

    // Control-flow classification, filled in from capstone's instruction
    // groups. We pull these out now so the CFG and the output steps later on
    // can ask "is this a branch?" without re-parsing the mnemonic string.
    bool is_call = false;       // call instruction
    bool is_jump = false;       // jmp / jcc of any kind
    bool is_ret = false;        // ret / retf
    bool is_relative = false;   // target is a pc-relative offset (direct branch)

    // Convenience: anything that can move control flow somewhere other than the
    // next instruction. Handy when grouping instructions into basic blocks.
    bool is_branch() const { return is_call || is_jump || is_ret; }
};

// Thin RAII wrapper around a capstone handle. Opening capstone allocates state
// that has to be freed with cs_close, so we tie the handle's lifetime to this
// object: the constructor opens it and the destructor closes it. Construct one,
// check is_open(), then feed it bytes.
//
// We hard-code x86-64 for now since that's the only target minidec handles.
// The handle isn't cheap to open, so the intent is to make one Disassembler and
// reuse it across functions rather than opening a fresh one per call.
class Disassembler {
public:
    // Defaults to Intel syntax; pass Syntax::att to get the GAS-style output.
    explicit Disassembler(Syntax syntax = Syntax::intel);
    ~Disassembler();

    // Capstone state isn't safe to copy, and copying would double-free the
    // handle, so the wrapper is move-only.
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;
    Disassembler(Disassembler&& other) noexcept;
    Disassembler& operator=(Disassembler&& other) noexcept;

    // True once capstone opened cleanly. If this is false the handle never came
    // up (out of memory, unsupported build) and disassemble() will return empty.
    bool is_open() const { return opened_; }

    // Decode a run of bytes starting at the given virtual address. Bytes capstone
    // can't decode (data mixed into the code, padding, jump tables) come back as
    // single-byte ".byte 0xNN" instructions so the listing still covers the whole
    // range instead of stopping at the first one it doesn't like.
    std::vector<Instruction> disassemble(const std::uint8_t* code, std::size_t size,
                                         std::uint64_t address) const;

    // Convenience overload for when the bytes already live in a vector.
    std::vector<Instruction> disassemble(const std::vector<std::uint8_t>& code,
                                         std::uint64_t address) const {
        return disassemble(code.data(), code.size(), address);
    }

private:
    // Stored as a plain integer so this header doesn't have to pull in
    // capstone.h; csh is just a size_t handle under the hood. The .cpp casts it
    // back when it talks to capstone.
    std::size_t handle_ = 0;
    bool opened_ = false;
};

}  // namespace minidec

#endif  // MINIDEC_DISASM_H
