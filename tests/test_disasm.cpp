#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "minidec/disasm.h"

// These tests feed the disassembler byte sequences I encoded by hand so the
// expected output is fixed and doesn't depend on any binary on disk. All of
// these are x86-64, and the expected operand text is Intel syntax since that's
// what the Disassembler defaults to.

TEST_CASE("a short prologue decodes into the expected mnemonics", "[disasm]") {
    minidec::Disassembler dis;
    REQUIRE(dis.is_open());

    // push rbp        55
    // mov  rbp, rsp   48 89 e5
    // add  rax, rdi   48 01 f8
    // pop  rbp        5d
    // ret             c3
    std::vector<std::uint8_t> code = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x01, 0xf8, 0x5d, 0xc3};

    auto insns = dis.disassemble(code, 0x1000);
    REQUIRE(insns.size() == 5);

    CHECK(insns[0].mnemonic == "push");
    CHECK(insns[0].op_str == "rbp");

    CHECK(insns[1].mnemonic == "mov");
    CHECK(insns[1].op_str == "rbp, rsp");

    CHECK(insns[2].mnemonic == "add");
    CHECK(insns[2].op_str == "rax, rdi");

    CHECK(insns[3].mnemonic == "pop");
    CHECK(insns[4].mnemonic == "ret");
}

TEST_CASE("addresses and sizes line up with where each instruction starts", "[disasm]") {
    minidec::Disassembler dis;
    REQUIRE(dis.is_open());

    // Same bytes as above. push and pop/ret are 1 byte, the two REX.W ops are
    // 3 bytes each, so the addresses should walk forward from the base by the
    // size of whatever came before.
    std::vector<std::uint8_t> code = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x01, 0xf8, 0x5d, 0xc3};

    auto insns = dis.disassemble(code, 0x400000);
    REQUIRE(insns.size() == 5);

    CHECK(insns[0].address == 0x400000);
    CHECK(insns[0].size == 1);
    CHECK(insns[1].address == 0x400001);
    CHECK(insns[1].size == 3);
    CHECK(insns[2].address == 0x400004);
    CHECK(insns[2].size == 3);
    CHECK(insns[3].address == 0x400007);
    CHECK(insns[4].address == 0x400008);

    // The bytes we stored back should be the exact bytes we handed in.
    CHECK(insns[0].bytes == std::vector<std::uint8_t>{0x55});
    CHECK(insns[1].bytes == std::vector<std::uint8_t>{0x48, 0x89, 0xe5});
}

TEST_CASE("ret gets flagged as a return and nothing else", "[disasm]") {
    minidec::Disassembler dis;
    auto insns = dis.disassemble(std::vector<std::uint8_t>{0xc3}, 0x1000);
    REQUIRE(insns.size() == 1);

    CHECK(insns[0].is_ret);
    CHECK(insns[0].is_branch());
    CHECK_FALSE(insns[0].is_call);
    CHECK_FALSE(insns[0].is_jump);
}

TEST_CASE("a direct call is a relative call with the right target", "[disasm]") {
    minidec::Disassembler dis;

    // call rel32, displacement 0. The instruction is 5 bytes, so a rel32 of 0
    // points at the byte right after it: base 0x1000 -> target 0x1005.
    std::vector<std::uint8_t> code = {0xe8, 0x00, 0x00, 0x00, 0x00};

    auto insns = dis.disassemble(code, 0x1000);
    REQUIRE(insns.size() == 1);

    CHECK(insns[0].mnemonic == "call");
    CHECK(insns[0].is_call);
    CHECK(insns[0].is_relative);
    CHECK(insns[0].is_branch());
    CHECK_FALSE(insns[0].is_jump);
    CHECK(insns[0].op_str == "0x1005");
}

TEST_CASE("a short jump is a relative jump", "[disasm]") {
    minidec::Disassembler dis;

    // jmp rel8, displacement -2 (0xfe). That's a two byte instruction jumping
    // back to its own start, i.e. a tight infinite loop: base 0x2000 -> 0x2000.
    std::vector<std::uint8_t> code = {0xeb, 0xfe};

    auto insns = dis.disassemble(code, 0x2000);
    REQUIRE(insns.size() == 1);

    CHECK(insns[0].mnemonic == "jmp");
    CHECK(insns[0].is_jump);
    CHECK(insns[0].is_relative);
    CHECK_FALSE(insns[0].is_call);
    CHECK_FALSE(insns[0].is_ret);
    CHECK(insns[0].op_str == "0x2000");
}

TEST_CASE("nothing to decode gives back an empty list", "[disasm]") {
    minidec::Disassembler dis;

    CHECK(dis.disassemble(std::vector<std::uint8_t>{}, 0x1000).empty());
    CHECK(dis.disassemble(nullptr, 0, 0x1000).empty());
}

TEST_CASE("att syntax prints registers with the gas percent sigil", "[disasm]") {
    minidec::Disassembler dis(minidec::Syntax::att);
    REQUIRE(dis.is_open());

    // mov rbp, rsp. Intel would say "rbp, rsp"; att prints "%rsp, %rbp" with the
    // operands swapped and each register prefixed by %. att also tacks the size
    // suffix on so the mnemonic comes out as "movq", hence rfind at 0 instead of
    // an exact match.
    auto insns = dis.disassemble(std::vector<std::uint8_t>{0x48, 0x89, 0xe5}, 0x1000);
    REQUIRE(insns.size() == 1);

    CHECK(insns[0].mnemonic.rfind("mov", 0) == 0);
    CHECK(insns[0].op_str.find('%') != std::string::npos);
}
