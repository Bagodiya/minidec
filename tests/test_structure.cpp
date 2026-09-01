#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/structure.h"

// Same trick as test_cfg.cpp: the instructions are built by hand because this
// pass only looks at the graph shape and the branch mnemonic, and drawing the
// shape directly beats hunting for byte sequences that happen to produce it.
//
// Addresses run end to end, since group_into_blocks treats one block's end as
// the next one's start and the fall-through edge depends on that.

namespace {

using minidec::CFG;
using minidec::IfRegion;
using minidec::IfShape;
using minidec::Instruction;

Instruction plain(std::uint64_t address, std::uint16_t size, std::string mnemonic,
                  std::string operands) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = std::move(mnemonic);
    insn.op_str = std::move(operands);
    return insn;
}

Instruction direct_jump(std::uint64_t address, std::uint16_t size, std::string mnemonic,
                        std::uint64_t target) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = std::move(mnemonic);

    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(target));
    insn.op_str = buffer;

    insn.is_jump = true;
    insn.is_relative = true;
    return insn;
}

Instruction ret_at(std::uint64_t address) {
    Instruction insn;
    insn.address = address;
    insn.size = 1;
    insn.mnemonic = "ret";
    insn.is_ret = true;
    return insn;
}

CFG build_cfg(const std::vector<Instruction>& instructions) {
    CFG cfg;
    cfg.blocks = minidec::group_into_blocks(instructions);
    minidec::connect_blocks(cfg.blocks);
    if (!cfg.blocks.empty()) {
        cfg.entry = cfg.blocks.front().start;
    }
    return cfg;
}

// if (edi) eax = 1; else eax = 2; return eax;
//
//   0x1000  test edi, edi     head, 0x1000 .. 0x1004
//   0x1002  je   0x100b
//   0x1004  mov  eax, 1       then, 0x1004 .. 0x100b
//   0x1009  jmp  0x1010
//   0x100b  mov  eax, 2       else, 0x100b .. 0x1010
//   0x1010  ret               join
std::vector<Instruction> if_else() {
    return {
        plain(0x1000, 2, "test", "edi, edi"), direct_jump(0x1002, 2, "je", 0x100b),
        plain(0x1004, 5, "mov", "eax, 1"),    direct_jump(0x1009, 2, "jmp", 0x1010),
        plain(0x100b, 5, "mov", "eax, 2"),    ret_at(0x1010),
    };
}

// if (edi) eax++; return eax;
//
//   0x1000  test edi, edi     head, 0x1000 .. 0x1004
//   0x1002  je   0x1009
//   0x1004  add  eax, 1       body, 0x1004 .. 0x1009
//   0x1009  ret               join
std::vector<Instruction> one_armed() {
    return {
        plain(0x1000, 2, "test", "edi, edi"),
        direct_jump(0x1002, 2, "je", 0x1009),
        plain(0x1004, 5, "add", "eax, 1"),
        ret_at(0x1009),
    };
}

} // namespace

TEST_CASE("a diamond comes back as one if/else", "[structure]") {
    CFG cfg = build_cfg(if_else());
    std::vector<IfRegion> regions = minidec::find_if_regions(cfg);

    REQUIRE(regions.size() == 1);
    const IfRegion& region = regions.front();

    CHECK(region.head == 0x1000);
    CHECK(region.shape == IfShape::if_else);
    CHECK(region.has_else());

    // The je is written to skip the first arm, so the arm on the fall-through
    // is the one that runs when the source condition held.
    CHECK(region.then_body == 0x1004);
    CHECK(region.else_body == 0x100b);
    CHECK(region.join == 0x1010);
    CHECK(region.rejoins());
    CHECK(region.negated);
}

TEST_CASE("a single arm keeps the fall-through as its body", "[structure]") {
    CFG cfg = build_cfg(one_armed());
    std::vector<IfRegion> regions = minidec::find_if_regions(cfg);

    REQUIRE(regions.size() == 1);
    const IfRegion& region = regions.front();

    CHECK(region.head == 0x1000);
    CHECK(region.shape == IfShape::then_only);
    CHECK_FALSE(region.has_else());
    CHECK(region.then_body == 0x1004);
    CHECK(region.else_body == 0);
    CHECK(region.join == 0x1009);
    CHECK(region.negated);
}

TEST_CASE("an if whose arms both return has no join", "[structure]") {
    std::vector<Instruction> insns = {
        plain(0x1000, 2, "test", "edi, edi"), direct_jump(0x1002, 2, "je", 0x100a),
        plain(0x1004, 5, "mov", "eax, 1"),    ret_at(0x1009),
        plain(0x100a, 5, "mov", "eax, 2"),    ret_at(0x100f),
    };

    CFG cfg = build_cfg(insns);
    std::vector<IfRegion> regions = minidec::find_if_regions(cfg);

    REQUIRE(regions.size() == 1);
    const IfRegion& region = regions.front();

    CHECK(region.shape == IfShape::if_else);
    CHECK(region.then_body == 0x1004);
    CHECK(region.else_body == 0x100a);

    // Both arms leave the function, so there is nothing after the statement.
    CHECK(region.join == 0);
    CHECK_FALSE(region.rejoins());
}

TEST_CASE("a body reached by the branch itself isn't negated", "[structure]") {
    // An early return: the jne goes to the return and everything else carries
    // on below it.
    //
    //   0x1000  test edi, edi     head
    //   0x1002  jne  0x100b
    //   0x1004  mov  eax, 0       carries on at 0x100c, so not an arm
    //   0x1009  jmp  0x100c
    //   0x100b  ret               the body, reached only by the jne
    //   0x100c  mov  eax, 1
    //   0x1011  ret
    std::vector<Instruction> insns = {
        plain(0x1000, 2, "test", "edi, edi"),
        direct_jump(0x1002, 2, "jne", 0x100b),
        plain(0x1004, 5, "mov", "eax, 0"),
        direct_jump(0x1009, 2, "jmp", 0x100c),
        ret_at(0x100b),
        plain(0x100c, 5, "mov", "eax, 1"),
        ret_at(0x1011),
    };

    CFG cfg = build_cfg(insns);
    std::vector<IfRegion> regions = minidec::find_if_regions(cfg);

    REQUIRE(regions.size() == 1);
    const IfRegion& region = regions.front();

    CHECK(region.shape == IfShape::then_only);
    CHECK(region.then_body == 0x100b);
    CHECK(region.join == 0x1004);

    // The branch is taken to get into the body, so its condition is the one to
    // print as written.
    CHECK_FALSE(region.negated);
}

TEST_CASE("a function with no conditional branch has no regions", "[structure]") {
    std::vector<Instruction> insns = {
        plain(0x1000, 3, "mov", "eax, edi"),
        plain(0x1003, 3, "add", "eax, esi"),
        ret_at(0x1006),
    };

    CFG cfg = build_cfg(insns);
    CHECK(minidec::find_if_regions(cfg).empty());
}

TEST_CASE("an arm something else jumps into isn't an if", "[structure]") {
    // The diamond again, with a stray block jumping straight into the else arm.
    // Control can now reach that block without going through the branch, so it
    // isn't the inside of a statement any more.
    std::vector<Instruction> insns = if_else();
    insns.push_back(direct_jump(0x1011, 5, "jmp", 0x100b));

    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.block_at(0x100b) != nullptr);
    CHECK(minidec::find_if_regions(cfg).empty());
}

TEST_CASE("a branch out of the function leaves nothing to structure", "[structure]") {
    // The je goes somewhere outside the function, so only the fall-through
    // became an edge and there is no second arm to look at.
    std::vector<Instruction> insns = {
        plain(0x1000, 2, "test", "edi, edi"),
        direct_jump(0x1002, 2, "je", 0x9000),
        plain(0x1004, 5, "add", "eax, 1"),
        ret_at(0x1009),
    };

    CFG cfg = build_cfg(insns);
    CHECK(minidec::find_if_regions(cfg).empty());
}

TEST_CASE("a loop exit test still matches the one armed shape", "[structure]") {
    // while (ecx < 10) ecx++; return;
    //
    // The header's jge skips the body exactly the way an if's branch does, and
    // from one block away there is nothing to tell them apart. This is the case
    // the header warns about: whatever prints the function has to handle loops
    // before falling back on these regions.
    std::vector<Instruction> insns = {
        plain(0x2000, 5, "mov", "ecx, 0"),     plain(0x2005, 3, "cmp", "ecx, 0xa"),
        direct_jump(0x2008, 2, "jge", 0x2012), plain(0x200a, 3, "add", "ecx, 1"),
        direct_jump(0x200d, 5, "jmp", 0x2005), ret_at(0x2012),
    };

    CFG cfg = build_cfg(insns);
    std::vector<IfRegion> regions = minidec::find_if_regions(cfg);

    REQUIRE(regions.size() == 1);
    CHECK(regions.front().head == 0x2005);
    CHECK(regions.front().then_body == 0x2012);
    CHECK_FALSE(regions.front().negated);
}

TEST_CASE("regions are looked up by their head block", "[structure]") {
    CFG cfg = build_cfg(if_else());
    std::vector<IfRegion> regions = minidec::find_if_regions(cfg);

    REQUIRE(minidec::region_at(regions, 0x1000) != nullptr);
    CHECK(minidec::region_at(regions, 0x1000)->join == 0x1010);

    // Asking about a block that isn't a head, and one that isn't in the graph.
    CHECK(minidec::region_at(regions, 0x1004) == nullptr);
    CHECK(minidec::region_at(regions, 0x9999) == nullptr);
}

TEST_CASE("an empty graph has no regions", "[structure]") {
    CFG cfg;
    CHECK(minidec::find_if_regions(cfg).empty());
}
