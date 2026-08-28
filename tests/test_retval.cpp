#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/retval.h"
#include "minidec/ssa.h"

// Same harness as test_params.cpp: instructions by hand, through the CFG and
// build_ssa, then the pass. Sizes are invented but have to be consistent,
// because the jump targets below are whatever the layout works out to.

namespace {

using minidec::CFG;
using minidec::Instruction;
using minidec::ReturnSource;
using minidec::ReturnValue;
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

ReturnValue analyse(std::vector<Instruction> code) {
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
    return minidec::recover_return_value(fn);
}

} // namespace

TEST_CASE("a value written into rax before the ret is the result") {
    ReturnValue value = analyse({
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(value.size() == 1);
    REQUIRE(value.returns_value());
    REQUIRE(value.reg == "rax");
    REQUIRE_FALSE(value.floating);

    // Only ever written as eax, so 32 bits is as much as was asked for.
    REQUIRE(value.width == 32);
    REQUIRE(value.sites[0].source == ReturnSource::written);
    REQUIRE_FALSE(value.sites[0].through_phi);
    REQUIRE(value.consistent());
}

TEST_CASE("a function that never writes rax returns nothing") {
    // The lifter names rax at every ret whether or not it means anything, so
    // this is the case the whole pass exists to tell apart.
    ReturnValue value = analyse({
        insn("ret", "", 1),
    });

    REQUIRE(value.size() == 1);
    REQUIRE(value.sites[0].source == ReturnSource::entry);
    REQUIRE(value.sites[0].version == 0);
    REQUIRE_FALSE(value.returns_value());
    REQUIRE_FALSE(value.forwards_call());
    REQUIRE(value.reg.empty());
    REQUIRE(value.width == 0);
}

TEST_CASE("what a call left in rax is not proof of a result") {
    ReturnValue value = analyse({
        call(0x2000),
        insn("ret", "", 1),
    });

    REQUIRE(value.size() == 1);
    REQUIRE(value.sites[0].source == ReturnSource::call);
    REQUIRE(value.forwards_call());
    REQUIRE_FALSE(value.returns_value());

    // The register is named, since something was in it. The width isn't, since
    // the call's rax is i64 by construction and says nothing about the callee.
    REQUIRE(value.reg == "rax");
    REQUIRE(value.width == 0);
}

TEST_CASE("a write after the call is ours again") {
    ReturnValue value = analyse({
        call(0x2000),
        insn("mov", "eax, 1", 5),
        insn("ret", "", 1),
    });

    REQUIRE(value.returns_value());
    REQUIRE_FALSE(value.forwards_call());
    REQUIRE(value.width == 32);
}

TEST_CASE("a result set differently down each arm is still one result") {
    // Laid out from 0x1000: the arms write eax and meet at 0x1011, where rax
    // picks up a phi, and the ret reads the phi rather than either write.
    ReturnValue value = analyse({
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x100c),
        insn("mov", "eax, 1", 5),
        jump("jmp", 0x1011),
        insn("mov", "eax, 2", 5),
        insn("ret", "", 1),
    });

    REQUIRE(value.size() == 1);
    REQUIRE(value.sites[0].block == 0x1011);
    REQUIRE(value.sites[0].through_phi);
    REQUIRE(value.sites[0].source == ReturnSource::written);
    REQUIRE(value.width == 32);
}

TEST_CASE("the widest of several returns is the width of the result") {
    // Two rets, one handing back a whole register and one only its low half.
    ReturnValue value = analyse({
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x1009),
        insn("mov", "rax, rsi", 3),
        insn("ret", "", 1),
        insn("mov", "eax, 1", 5),
        insn("ret", "", 1),
    });

    REQUIRE(value.size() == 2);
    REQUIRE(value.width == 64);
    REQUIRE(value.consistent());
    REQUIRE(value.sites[0].address == 0x1008);
    REQUIRE(value.sites[1].address == 0x100e);
}

TEST_CASE("returns can disagree about where the value came from") {
    ReturnValue value = analyse({
        insn("cmp", "edi, 0", 3),
        jump("jle", 0x100b),
        insn("mov", "eax, 1", 5),
        insn("ret", "", 1),
        call(0x2000),
        insn("ret", "", 1),
    });

    REQUIRE(value.size() == 2);
    REQUIRE_FALSE(value.consistent());

    // One real write is enough. The other arm may be forwarding the call or may
    // be doing nothing, and neither cancels the write.
    REQUIRE(value.returns_value());
    REQUIRE_FALSE(value.forwards_call());
}

TEST_CASE("a function that never returns has no return sites") {
    ReturnValue value = analyse({
        jump("jmp", 0x1000),
    });

    REQUIRE(value.empty());
    REQUIRE_FALSE(value.returns_value());
}

TEST_CASE("a function with nothing in it returns nothing") {
    REQUIRE(minidec::recover_return_value(SsaFunction{}).empty());
}
