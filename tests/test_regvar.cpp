#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/regvar.h"
#include "minidec/ssa.h"

// Built the same way test_stack.cpp builds its frames: instructions by hand,
// through the CFG and build_ssa, then the pass. What matters here is which
// versions the SSA hands out and where the phis land, and writing an SsaFunction
// by hand would be writing down the answer instead of checking it.
//
// Sizes are made up but have to be non-zero and have to add up, since the jump
// targets below are the addresses the layout produces.

namespace {

using minidec::CFG;
using minidec::Instruction;
using minidec::RegVar;
using minidec::RegVars;
using minidec::SsaFunction;

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
    return result;
}

Instruction jump(std::string mnemonic, std::uint64_t target, std::uint16_t size = 2) {
    Instruction result = insn(std::move(mnemonic), hex(target), size);
    result.is_jump = true;
    result.is_relative = true;
    return result;
}

// A direct call. Without is_relative the lifter can't read the target and gives
// up, and the unknown it leaves behind clobbers every register in sight.
Instruction call(std::uint64_t target, std::uint16_t size = 5) {
    Instruction result = insn("call", hex(target), size);
    result.is_call = true;
    result.is_relative = true;
    return result;
}

RegVars analyse(std::vector<Instruction> code) {
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
    return minidec::find_register_variables(fn);
}

// eax = edi + esi, which is about the smallest function that keeps anything in a
// register at all.
std::vector<Instruction> add_two() {
    return {
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    };
}

} // namespace

TEST_CASE("a register written and read back is one variable") {
    RegVars vars = analyse(add_two());

    const RegVar* written = vars.var_for("eax", 1);
    REQUIRE(written != nullptr);
    REQUIRE(written->reg == "rax");
    REQUIRE(written->width == 32);
    REQUIRE(written->defs.size() == 1);
    REQUIRE_FALSE(written->from_caller());

    // More than one use, and all of them at the add: the flags it sets are
    // spelled out as their own operations and they read the same value.
    REQUIRE_FALSE(written->uses.empty());
    for (const minidec::RegUse& use : written->uses) {
        REQUIRE(use.address == 0x1002);
    }
}

TEST_CASE("an argument arrives already live") {
    RegVars vars = analyse(add_two());

    const RegVar* arg = vars.var_for("rdi", 0);
    REQUIRE(arg != nullptr);
    REQUIRE(arg->from_caller());
    REQUIRE(arg->defs.empty());
    REQUIRE(arg->uses.size() == 1);

    REQUIRE(arg->live.size() == 1);
    REQUIRE(arg->live[0].enters);
    REQUIRE_FALSE(arg->live[0].leaves);
}

TEST_CASE("two writes of one register with nothing joining them are two variables") {
    RegVars vars = analyse(add_two());

    const RegVar* first = vars.var_for("rax", 1);
    const RegVar* second = vars.var_for("rax", 2);

    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    REQUIRE(first != second);
}

TEST_CASE("a register is found under any of its spellings") {
    RegVars vars = analyse(add_two());

    REQUIRE(vars.var_for("al", 1) == vars.var_for("rax", 1));
    REQUIRE(vars.var_for("eax", 1) == vars.var_for("rax", 1));
    REQUIRE(vars.var_for("rax", 9) == nullptr);
}

TEST_CASE("a write nothing reads is not a variable") {
    RegVars vars = analyse({
        insn("mov", "eax, edi", 2),
        insn("mov", "ecx, esi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(vars.var_for("ecx", 1) == nullptr);
    REQUIRE(vars.var_for("eax", 1) != nullptr);
}

TEST_CASE("the flags and the frame registers are not variables") {
    RegVars vars = analyse({
        insn("push", "rbp", 1),
        insn("mov", "rbp, rsp", 3),
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x100c),
        insn("mov", "eax, edi", 2),
        insn("ret", "", 1),
    });

    for (const RegVar& var : vars.vars) {
        REQUIRE(var.reg != "rsp");
        REQUIRE(var.reg != "rbp");
        REQUIRE(var.reg != "zf");
        REQUIRE(var.reg != "sf");
        REQUIRE(var.reg != "of");
    }
}

TEST_CASE("a value set on both sides of a branch is one variable") {
    // Laid out from 0x1000: the else arm starts at 0x1009 and the arms meet
    // again at 0x100b.
    RegVars vars = analyse({
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x1009),
        insn("mov", "eax, edi", 2),
        jump("jmp", 0x100b),
        insn("mov", "eax, esi", 2),
        insn("add", "eax, 1", 3),
        insn("ret", "", 1),
    });

    const RegVar* var = vars.var_for("eax", 1);
    REQUIRE(var != nullptr);
    REQUIRE(var == vars.var_for("eax", 2));
    REQUIRE(var->versions == std::vector<unsigned>{1, 2, 3});

    // One arm each, plus the block they meet in. The block above the branch
    // never holds it, so it gets no span.
    REQUIRE(var->live.size() == 3);
    REQUIRE(var->live.back().enters == false);

    unsigned joins = 0;
    for (const minidec::RegDef& def : var->defs) {
        joins += def.is_phi ? 1 : 0;
    }
    REQUIRE(joins == 1);
}

TEST_CASE("a counter round a loop is one variable, not one per trip") {
    // The header is at 0x1004 and the exit at 0x100e, so the back edge closes on
    // a block with two predecessors and the counter picks up a phi.
    RegVars vars = analyse({
        insn("mov", "eax, 0", 4),
        insn("cmp", "eax, edi", 3),
        jump("jge", 0x100e),
        insn("add", "eax, 1", 3),
        jump("jmp", 0x1004),
        insn("mov", "ecx, eax", 2),
        insn("ret", "", 1),
    });

    const RegVar* counter = vars.var_for("eax", 1);
    REQUIRE(counter != nullptr);
    REQUIRE(counter == vars.var_for("eax", 3));
    REQUIRE(counter->versions == std::vector<unsigned>{1, 2, 3});

    // Live in every block: set before the loop, carried round it, read after.
    REQUIRE(counter->live.size() == 4);
    REQUIRE(counter->live[0].leaves);
}

TEST_CASE("a value held across a call is marked as crossing it") {
    RegVars vars = analyse({
        insn("mov", "rbx, rdi", 3),
        call(0x2000),
        insn("mov", "rax, rbx", 3),
        insn("ret", "", 1),
    });

    const RegVar* saved = vars.var_for("rbx", 1);
    REQUIRE(saved != nullptr);
    REQUIRE(saved->crosses_call);

    // rdi is read by the call as an argument and never again, so it stops there.
    const RegVar* arg = vars.var_for("rdi", 0);
    REQUIRE(arg != nullptr);
    REQUIRE_FALSE(arg->crosses_call);
}

TEST_CASE("a function with nothing in it has no variables") {
    REQUIRE(minidec::find_register_variables(SsaFunction{}).empty());
}
