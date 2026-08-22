#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/ssa.h"
#include "minidec/stack.h"

// The pass reads SSA, so these build a real one: instructions by hand, through
// group_into_blocks and connect_blocks, then build_ssa. Writing the SSA directly
// would be shorter but would let a test pass on a shape the lifter never emits,
// and the whole job here is recognising the shapes it does.
//
// Only what lift.cpp parses matters, which is the mnemonic and the operand text.
// Sizes are made up but have to be non-zero, since instructions are laid out end
// to end and a zero would put two of them at the same address.

namespace {

using minidec::CFG;
using minidec::Instruction;
using minidec::SsaFunction;
using minidec::StackFrame;
using minidec::StackVar;

std::string hex(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
    return buffer;
}

Instruction insn(std::string mnemonic, std::string operands, std::uint16_t size = 4) {
    Instruction result;
    result.mnemonic = std::move(mnemonic);
    result.op_str = std::move(operands);
    result.size = size;
    result.is_ret = result.mnemonic == "ret";
    result.is_call = result.mnemonic == "call";
    return result;
}

// A direct jump needs the flags as well as the operand text: without them the
// CFG won't cut a block here and the lifter won't read the target, which leaves
// an unknown that clobbers rbp and takes the frame with it.
Instruction jump(std::string mnemonic, std::uint64_t target, std::uint16_t size = 2) {
    Instruction result = insn(std::move(mnemonic), "", size);
    result.op_str = hex(target);
    result.is_jump = true;
    result.is_relative = true;
    return result;
}

// Lay the instructions out from 0x1000 and run the whole chain over them.
StackFrame analyse(std::vector<Instruction> code) {
    std::uint64_t address = 0x1000;
    for (Instruction& one : code) {
        one.address = address;
        address += one.size;
    }

    CFG cfg;
    cfg.entry = code.front().address;
    cfg.blocks = minidec::group_into_blocks(code);
    minidec::connect_blocks(cfg.blocks);

    SsaFunction fn = minidec::build_ssa(cfg);
    return minidec::find_stack_variables(fn);
}

// The usual -O0 opening. "push rbp" isn't lifted, so what the frame ends up
// hanging off is the rsp version that push left behind -- which is the point of
// keying slots on a value rather than on a register name.
std::vector<Instruction> prologue() {
    return {insn("push", "rbp", 1), insn("mov", "rbp, rsp", 3)};
}

std::vector<Instruction> with_prologue(std::vector<Instruction> body) {
    std::vector<Instruction> code = prologue();
    for (Instruction& one : body) {
        code.push_back(std::move(one));
    }
    code.push_back(insn("ret", "", 1));
    return code;
}

} // namespace

TEST_CASE("a local written through the frame pointer turns up as a slot") {
    StackFrame frame = analyse(with_prologue({insn("mov", "dword ptr [rbp - 4], edi")}));

    REQUIRE(frame.size() == 1);
    REQUIRE(frame.vars[0].offset == -4);
    REQUIRE(frame.vars[0].size == 4);
    REQUIRE(frame.vars[0].is_written());
    REQUIRE_FALSE(frame.vars[0].is_read());
}

TEST_CASE("writing a local and reading it back gives one slot, not two") {
    StackFrame frame = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "eax, dword ptr [rbp - 4]"),
    }));

    REQUIRE(frame.size() == 1);

    const StackVar& var = frame.vars[0];
    REQUIRE(var.accesses.size() == 2);
    REQUIRE(var.is_read());
    REQUIRE(var.is_written());
    REQUIRE(var.accesses[0].address < var.accesses[1].address);
    REQUIRE(var.accesses[0].is_write);
    REQUIRE_FALSE(var.accesses[1].is_write);
}

TEST_CASE("separate offsets are separate slots, listed low to high") {
    StackFrame frame = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "dword ptr [rbp - 0xc], esi"),
        insn("mov", "byte ptr [rbp - 0xd], 0"),
    }));

    REQUIRE(frame.size() == 3);
    REQUIRE(frame.vars[0].offset == -13);
    REQUIRE(frame.vars[1].offset == -12);
    REQUIRE(frame.vars[2].offset == -4);
    REQUIRE(frame.vars[0].size == 1);
}

TEST_CASE("a slot read at two widths keeps the wider one") {
    StackFrame frame = analyse(with_prologue({
        insn("mov", "qword ptr [rbp - 0x10], rdi"),
        insn("mov", "al, byte ptr [rbp - 0x10]"),
    }));

    REQUIRE(frame.size() == 1);
    REQUIRE(frame.vars[0].size == 8);
    REQUIRE(frame.vars[0].accesses.size() == 2);
}

TEST_CASE("offsets follow the stack pointer when it moves") {
    // No frame pointer, so the slot is addressed off an rsp that has already been
    // pushed down. Taken from the entry value it sits at -0x18 + 8.
    StackFrame frame = analyse({
        insn("sub", "rsp, 0x18"),
        insn("mov", "dword ptr [rsp + 8], edi"),
        insn("add", "rsp, 0x18"),
        insn("ret", "", 1),
    });

    REQUIRE(frame.size() == 1);
    REQUIRE(frame.vars[0].base == "rsp");
    REQUIRE(frame.vars[0].base_version == 0);
    REQUIRE(frame.vars[0].offset == -0x10);
}

TEST_CASE("a slot used on both sides of a branch is one slot") {
    // Laid out from 0x1000, so the else arm starts at 0x100f and the two arms
    // meet again at 0x1013.
    StackFrame frame = analyse({
        insn("push", "rbp", 1),
        insn("mov", "rbp, rsp", 3),
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x100f),
        insn("mov", "dword ptr [rbp - 4], edi"),
        jump("jmp", 0x1013),
        insn("mov", "dword ptr [rbp - 4], 0"),
        insn("mov", "eax, dword ptr [rbp - 4]"),
        insn("ret", "", 1),
    });

    REQUIRE(frame.size() == 1);
    REQUIRE(frame.vars[0].offset == -4);
    REQUIRE(frame.vars[0].accesses.size() == 3);
}

TEST_CASE("an address that didn't come from the frame is counted, not guessed at") {
    StackFrame frame = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "eax, dword ptr [rsi]"),
        insn("mov", "ecx, dword ptr [rsi + 8]"),
    }));

    REQUIRE(frame.size() == 1);
    REQUIRE(frame.untracked == 2);
}

TEST_CASE("a stack pointer stored into the frame is a value, not another slot") {
    StackFrame frame = analyse(with_prologue({insn("mov", "qword ptr [rbp - 0x10], rsp")}));

    REQUIRE(frame.size() == 1);
    REQUIRE(frame.vars[0].offset == -0x10);
    REQUIRE(frame.untracked == 0);
}

TEST_CASE("a function that never touches its frame has no slots") {
    StackFrame frame = analyse({
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(frame.empty());
    REQUIRE(frame.untracked == 0);
}

TEST_CASE("var_at finds a slot by its offset") {
    StackFrame frame = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "dword ptr [rbp - 8], esi"),
    }));

    REQUIRE(frame.var_at(-8) != nullptr);
    REQUIRE(frame.var_at(-8)->size == 4);
    REQUIRE(frame.var_at(-16) == nullptr);
}
