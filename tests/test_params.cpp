#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/params.h"
#include "minidec/ssa.h"

// Same harness as test_regvar.cpp: instructions by hand, through the CFG and
// build_ssa, then the pass. Writing an SsaFunction directly would mean writing
// down which registers came out at version 0, and that is the answer this is
// meant to be checking.
//
// Instruction sizes are invented but have to be non-zero and consistent, since
// the jump targets below are whatever the layout works out to.

namespace {

using minidec::CFG;
using minidec::Instruction;
using minidec::ParamList;
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

Instruction call(std::uint64_t target, std::uint16_t size = 5) {
    Instruction result = insn("call", hex(target), size);
    result.is_call = true;
    result.is_relative = true;
    return result;
}

// "call rdi". No target to read out of the encoding, so the lifter takes the
// register instead of giving up.
Instruction call_through(std::string reg, std::uint16_t size = 2) {
    Instruction result = insn("call", std::move(reg), size);
    result.is_call = true;
    return result;
}

ParamList analyse(std::vector<Instruction> code) {
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
    return minidec::recover_parameters(fn);
}

// int add(int a, int b) at -O2, near enough.
std::vector<Instruction> add_two() {
    return {
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    };
}

} // namespace

TEST_CASE("registers read before anything writes them are the arguments") {
    ParamList params = analyse(add_two());

    REQUIRE(params.size() == 2);
    REQUIRE(params.params[0].reg == "rdi");
    REQUIRE(params.params[0].index == 0);
    REQUIRE(params.params[0].used());
    REQUIRE(params.params[0].width == 32);
    REQUIRE(params.params[1].reg == "rsi");
    REQUIRE(params.params[1].used());
    REQUIRE_FALSE(params.saturated());
}

TEST_CASE("an argument the function ignores still takes up its place") {
    // Only the third register is touched, and the convention fills them in
    // order, so two arguments went past unread rather than never having been
    // there.
    ParamList params = analyse({
        insn("mov", "eax, edx", 2),
        insn("ret", "", 1),
    });

    REQUIRE(params.size() == 3);
    REQUIRE_FALSE(params.params[0].used());
    REQUIRE_FALSE(params.params[1].used());
    REQUIRE(params.params[2].used());

    // Nothing reads the first two, so there is nothing to say how wide they are.
    REQUIRE(params.params[0].width == 0);
    REQUIRE(params.params[2].width == 32);
}

TEST_CASE("a register the function fills in itself was not passed to it") {
    ParamList params = analyse({
        insn("mov", "esi, 5", 5),
        insn("mov", "eax, esi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(params.empty());
}

TEST_CASE("the argument registers a call sets up are not our own arguments") {
    // The lifter names all six at every call because it can't see the callee.
    // Believing it here would give six arguments to every function that calls
    // anything.
    ParamList params = analyse({
        call(0x2000),
        insn("ret", "", 1),
    });

    REQUIRE(params.empty());
    REQUIRE(params.forwarded.size() == 6);
    REQUIRE(params.forwarded.front() == "rdi");
    REQUIRE(params.forwarded.back() == "r9");
}

TEST_CASE("a register read for real is an argument even if a call also takes it") {
    ParamList params = analyse({
        insn("mov", "eax, edi", 2),
        call(0x2000),
        insn("ret", "", 1),
    });

    REQUIRE(params.size() == 1);
    REQUIRE(params.params[0].reg == "rdi");

    // The other five are still only there because the lifter put them there.
    REQUIRE(params.forwarded.size() == 5);
    for (const std::string& reg : params.forwarded) {
        REQUIRE(reg != "rdi");
    }
}

TEST_CASE("the width is the widest spelling anything reads") {
    ParamList params = analyse({
        insn("mov", "eax, edi", 2),
        insn("mov", "rbx, rdi", 3),
        insn("ret", "", 1),
    });

    REQUIRE(params.size() == 1);
    REQUIRE(params.params[0].width == 64);
    REQUIRE(params.params[0].reads.size() == 2);
}

TEST_CASE("a call through an argument reads that argument") {
    ParamList params = analyse({
        call_through("rdi"),
        insn("ret", "", 1),
    });

    REQUIRE(params.size() == 1);
    REQUIRE(params.params[0].reg == "rdi");

    // The target sits in slot 0, ahead of the six the lifter appends.
    REQUIRE(params.params[0].reads.size() == 1);
    REQUIRE(params.params[0].reads[0].arg == 0);
    REQUIRE_FALSE(params.params[0].reads[0].is_phi);
}

TEST_CASE("an argument that reaches a join is read at the join too") {
    // Laid out from 0x1000: the arms meet again at 0x100a, where rdi picks up a
    // phi because one side of the branch overwrote it.
    ParamList params = analyse({
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x100a),
        insn("mov", "edi, 1", 3),
        jump("jmp", 0x100a),
        insn("mov", "eax, edi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(params.size() == 1);

    unsigned at_join = 0;
    for (const minidec::ParamRead& read : params.params[0].reads) {
        if (read.is_phi) {
            ++at_join;
            REQUIRE(read.block == 0x100a);
            REQUIRE(read.address == 0);
        }
    }
    REQUIRE(at_join == 1);
}

TEST_CASE("an argument is found under any of its spellings") {
    ParamList params = analyse(add_two());

    REQUIRE(params.find("edi") == params.at(0));
    REQUIRE(params.find("dil") == params.at(0));
    REQUIRE(params.find("rsi") == params.at(1));
    REQUIRE(params.find("rbx") == nullptr);
    REQUIRE(params.at(7) == nullptr);
}

TEST_CASE("a function with nothing in it has no arguments") {
    REQUIRE(minidec::recover_parameters(SsaFunction{}).empty());
}
