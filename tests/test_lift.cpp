#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/disasm.h"
#include "minidec/ir.h"
#include "minidec/lift.h"

// Instructions built by hand rather than run through capstone, same as
// test_cfg.cpp -- the operand text decides what comes out, so writing it directly
// beats hunting for an encoding.
//
// It does have to match capstone's spelling: Intel order, a bare hex number for a
// branch target, "qword ptr [...]" for memory.

namespace {

using minidec::Instruction;
using minidec::IrInst;
using minidec::IrOperand;
using minidec::IrType;
using minidec::Lifter;
using minidec::Opcode;
using minidec::OperandKind;

Instruction plain(std::string mnemonic, std::string operands, std::uint64_t address = 0x1000,
                  std::uint16_t size = 4) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = std::move(mnemonic);
    insn.op_str = std::move(operands);
    return insn;
}

// The only shape carrying a readable target. is_relative marks the operand as an
// address capstone already worked out.
Instruction direct_branch(std::string mnemonic, std::uint64_t target,
                          std::uint64_t address = 0x1000, std::uint16_t size = 6) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = std::move(mnemonic);

    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(target));
    insn.op_str = buffer;

    insn.is_relative = true;
    insn.is_jump = insn.mnemonic != "call";
    insn.is_call = insn.mnemonic == "call";
    return insn;
}

bool is_reg(const IrOperand& operand, const std::string& name, IrType type) {
    return operand.kind == OperandKind::reg && operand.reg == name && operand.type == type;
}

bool is_imm(const IrOperand& operand, std::uint64_t value) {
    return operand.kind == OperandKind::imm && operand.imm == value;
}

bool is_temp(const IrOperand& operand) { return operand.kind == OperandKind::temp; }

// The operation writing a given flag, so the tests don't count indices.
const IrInst* flag_write(const std::vector<IrInst>& out, const std::string& flag) {
    for (const IrInst& inst : out) {
        if (inst.writes_result() && is_reg(inst.dst, flag, IrType::i1)) {
            return &inst;
        }
    }
    return nullptr;
}

}  // namespace

TEST_CASE("register_type knows the legacy names at every width", "[lift]") {
    using minidec::register_type;

    REQUIRE(register_type("rax") == IrType::i64);
    REQUIRE(register_type("eax") == IrType::i32);
    REQUIRE(register_type("ax") == IrType::i16);
    REQUIRE(register_type("al") == IrType::i8);
}

TEST_CASE("register_type treats the flags as one-bit registers", "[lift]") {
    using minidec::register_type;

    REQUIRE(register_type("zf") == IrType::i1);
    REQUIRE(register_type("cf") == IrType::i1);
    REQUIRE(register_type("of") == IrType::i1);
}

TEST_CASE("register_type reads the numbered registers off their suffix", "[lift]") {
    using minidec::register_type;

    REQUIRE(register_type("r10") == IrType::i64);
    REQUIRE(register_type("r10d") == IrType::i32);
    REQUIRE(register_type("r10w") == IrType::i16);
    REQUIRE(register_type("r10b") == IrType::i8);
}

TEST_CASE("register_type rejects what isn't a general-purpose register", "[lift]") {
    using minidec::register_type;

    // Past r15, so not a register even though it parses like one.
    REQUIRE_FALSE(register_type("r16").has_value());
    REQUIRE_FALSE(register_type("xmm0").has_value());
    REQUIRE_FALSE(register_type("").has_value());
}

TEST_CASE("a register to register mov is one assign", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("mov", "rbp, rsp"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::assign);
    REQUIRE(out[0].type == IrType::i64);
    REQUIRE(is_reg(out[0].dst, "rbp", IrType::i64));
    REQUIRE(is_reg(out[0].args.at(0), "rsp", IrType::i64));
}

TEST_CASE("a constant takes the width of the register it's moved into", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("mov", "eax, 0x2a"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].type == IrType::i32);
    REQUIRE(is_imm(out[0].args.at(0), 0x2a));
    REQUIRE(out[0].args.at(0).type == IrType::i32);
}

TEST_CASE("a negative constant is cut down to the operand's width", "[lift]") {
    Lifter lifter;

    // Read back as a 64-bit value this is all ones, which would be wrong sitting
    // in an eight-bit operand.
    std::vector<IrInst> out = lifter.lift(plain("mov", "al, -1"));

    REQUIRE(out.size() == 1);
    REQUIRE(is_imm(out[0].args.at(0), 0xff));
}

TEST_CASE("a mov whose operands disagree in width is not lifted", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("mov", "rax, ecx"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("reading memory becomes an address calculation and a load", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("mov", "eax, dword ptr [rbp - 4]"));

    REQUIRE(out.size() == 2);

    // -4 is stored as its two's complement, so the subtraction is one add.
    REQUIRE(out[0].op == Opcode::add);
    REQUIRE(is_reg(out[0].args.at(0), "rbp", IrType::i64));
    REQUIRE(is_imm(out[0].args.at(1), 0xfffffffffffffffcULL));

    REQUIRE(out[1].op == Opcode::load);
    REQUIRE(out[1].type == IrType::i32);
    REQUIRE(is_reg(out[1].dst, "eax", IrType::i32));
    REQUIRE(is_temp(out[1].args.at(0)));
    REQUIRE(out[1].args.at(0).temp_id == out[0].dst.temp_id);
}

TEST_CASE("writing memory becomes an address calculation and a store", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("mov", "dword ptr [rbp - 4], eax"));

    REQUIRE(out.size() == 2);
    REQUIRE(out[1].op == Opcode::store);
    REQUIRE(out[1].type == IrType::i32);
    REQUIRE_FALSE(out[1].writes_result());
    REQUIRE(is_temp(out[1].args.at(0)));
    REQUIRE(is_reg(out[1].args.at(1), "eax", IrType::i32));
}

TEST_CASE("a scaled index becomes a multiply and two adds", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("mov", "rax, qword ptr [rbx + rcx*8 + 0x10]"));

    REQUIRE(out.size() == 4);
    REQUIRE(out[0].op == Opcode::mul);
    REQUIRE(is_reg(out[0].args.at(0), "rcx", IrType::i64));
    REQUIRE(is_imm(out[0].args.at(1), 8));

    REQUIRE(out[1].op == Opcode::add);  // base + index*scale
    REQUIRE(is_reg(out[1].args.at(0), "rbx", IrType::i64));

    REQUIRE(out[2].op == Opcode::add);  // + displacement
    REQUIRE(is_imm(out[2].args.at(1), 0x10));

    REQUIRE(out[3].op == Opcode::load);
}

TEST_CASE("a rip-relative address folds into a constant", "[lift]") {
    Lifter lifter;

    // rip reads as the address of the next instruction, which is known here, so
    // there is no register left in the address and nothing to compute.
    std::vector<IrInst> out =
        lifter.lift(plain("mov", "rax, qword ptr [rip + 0x10]", 0x1000, 7));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::load);
    REQUIRE(is_imm(out[0].args.at(0), 0x1000 + 7 + 0x10));
}

TEST_CASE("a segment-relative address is not lifted", "[lift]") {
    Lifter lifter;

    // The stack cookie. There's no register holding the fs base, so there's no
    // honest address to compute.
    std::vector<IrInst> out = lifter.lift(plain("mov", "rax, qword ptr fs:[0x28]"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("add computes into a temporary before writing the register", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("add", "rax, rcx"));

    REQUIRE(out.front().op == Opcode::add);
    REQUIRE(is_temp(out.front().dst));

    // The register is only written on the last line, so the flag operations in
    // between still see the value rax had going in.
    REQUIRE(out.back().op == Opcode::assign);
    REQUIRE(is_reg(out.back().dst, "rax", IrType::i64));
    REQUIRE(out.back().args.at(0).temp_id == out.front().dst.temp_id);
}

TEST_CASE("add writes the four flags every conditional jump reads", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("add", "rax, rcx"));

    REQUIRE(flag_write(out, "zf") != nullptr);
    REQUIRE(flag_write(out, "sf") != nullptr);
    REQUIRE(flag_write(out, "cf") != nullptr);
    REQUIRE(flag_write(out, "of") != nullptr);

    // pf and af are the two deliberately left alone.
    REQUIRE(flag_write(out, "pf") == nullptr);
    REQUIRE(flag_write(out, "af") == nullptr);
}

TEST_CASE("an add carries when the sum lands below what it started from", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("add", "rax, rcx"));

    const IrInst* carry = flag_write(out, "cf");
    REQUIRE(carry != nullptr);
    REQUIRE(carry->op == Opcode::cmp_lt_u);
    REQUIRE(is_temp(carry->args.at(0)));                    // the result
    REQUIRE(is_reg(carry->args.at(1), "rax", IrType::i64)); // the left operand
}

TEST_CASE("a sub borrows when the left side was the smaller unsigned", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("sub", "rax, rcx"));

    REQUIRE(out.front().op == Opcode::sub);

    const IrInst* carry = flag_write(out, "cf");
    REQUIRE(carry != nullptr);
    REQUIRE(carry->op == Opcode::cmp_lt_u);
    REQUIRE(is_reg(carry->args.at(0), "rax", IrType::i64));
    REQUIRE(is_reg(carry->args.at(1), "rcx", IrType::i64));
}

TEST_CASE("cmp sets the flags without writing a register", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("cmp", "eax, ecx"));

    // It's a sub whose result goes nowhere.
    REQUIRE(out.front().op == Opcode::sub);
    REQUIRE(is_temp(out.front().dst));

    REQUIRE(flag_write(out, "zf") != nullptr);
    REQUIRE(flag_write(out, "sf") != nullptr);
    REQUIRE(flag_write(out, "cf") != nullptr);
    REQUIRE(flag_write(out, "of") != nullptr);

    // Nothing may write eax or ecx -- that's the whole difference from sub.
    for (const IrInst& inst : out) {
        REQUIRE_FALSE(is_reg(inst.dst, "eax", IrType::i32));
        REQUIRE_FALSE(is_reg(inst.dst, "ecx", IrType::i32));
    }
}

TEST_CASE("a cmp followed by a jcc writes the flags that jcc reads", "[lift]") {
    Lifter lifter;

    // The pairing the whole conditional-jump path depends on: without cmp being
    // lifted, the branch below would be reading flags nothing had written.
    std::vector<IrInst> compare = lifter.lift(plain("cmp", "eax, ecx"));
    std::vector<IrInst> jump = lifter.lift(direct_branch("jl", 0x1100));

    REQUIRE(flag_write(compare, "sf") != nullptr);
    REQUIRE(flag_write(compare, "of") != nullptr);

    REQUIRE(jump.front().op == Opcode::cmp_ne);
    REQUIRE(is_reg(jump.front().args.at(0), "sf", IrType::i1));
    REQUIRE(is_reg(jump.front().args.at(1), "of", IrType::i1));
}

TEST_CASE("test is a bitwise and that keeps only the flags", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("test", "eax, eax"));

    REQUIRE(out.front().op == Opcode::bit_and);
    REQUIRE(is_temp(out.front().dst));

    for (const IrInst& inst : out) {
        REQUIRE_FALSE(is_reg(inst.dst, "eax", IrType::i32));
    }
}

TEST_CASE("a bitwise instruction clears carry and overflow outright", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("xor", "eax, eax"));

    const IrInst* carry = flag_write(out, "cf");
    const IrInst* overflow = flag_write(out, "of");
    REQUIRE(carry != nullptr);
    REQUIRE(overflow != nullptr);

    // Assigned zero, not computed -- a bit operation has no carry to work out.
    REQUIRE(carry->op == Opcode::assign);
    REQUIRE(is_imm(carry->args.at(0), 0));
    REQUIRE(overflow->op == Opcode::assign);
    REQUIRE(is_imm(overflow->args.at(0), 0));
}

TEST_CASE("xor, and and or write their result back", "[lift]") {
    Lifter lifter;

    std::vector<IrInst> x = lifter.lift(plain("xor", "eax, ecx"));
    REQUIRE(x.front().op == Opcode::bit_xor);
    REQUIRE(x.back().op == Opcode::assign);
    REQUIRE(is_reg(x.back().dst, "eax", IrType::i32));

    Lifter b;
    REQUIRE(b.lift(plain("and", "eax, ecx")).front().op == Opcode::bit_and);

    Lifter c;
    REQUIRE(c.lift(plain("or", "eax, ecx")).front().op == Opcode::bit_or);
}

TEST_CASE("arithmetic reads a memory operand through a load", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("add", "eax, dword ptr [rbp - 8]"));

    // Address, load, then the add over the value that came back -- the operation
    // itself never sees the address.
    REQUIRE(out[0].op == Opcode::add);   // rbp + displacement
    REQUIRE(out[1].op == Opcode::load);
    REQUIRE(out[1].type == IrType::i32);
    REQUIRE(out[2].op == Opcode::add);   // the instruction's own add
    REQUIRE(out[2].args.at(1).temp_id == out[1].dst.temp_id);
    REQUIRE(out.back().op == Opcode::assign);
    REQUIRE(is_reg(out.back().dst, "eax", IrType::i32));
}

TEST_CASE("cmp reads a memory operand the same way", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("cmp", "eax, dword ptr [rbp - 4]"));

    REQUIRE(out[1].op == Opcode::load);
    REQUIRE(out[2].op == Opcode::sub);
    REQUIRE(flag_write(out, "zf") != nullptr);
}

TEST_CASE("a memory width that disagrees with the register is not lifted", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("add", "rax, dword ptr [rbp - 8]"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("writing back to a memory destination is not lifted yet", "[lift]") {
    Lifter lifter;

    // Read, operate, store back is a shape none of the callers have, so it has
    // to come out as an unknown rather than a half-modelled add.
    std::vector<IrInst> out = lifter.lift(plain("add", "dword ptr [rbp - 8], eax"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("the two-operand imul reuses the destination as a factor", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("imul", "eax, ecx"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::mul);
    REQUIRE(is_reg(out[0].dst, "eax", IrType::i32));
    REQUIRE(is_reg(out[0].args.at(0), "eax", IrType::i32));
    REQUIRE(is_reg(out[0].args.at(1), "ecx", IrType::i32));
}

TEST_CASE("the three-operand imul names both factors", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("imul", "eax, ecx, 4"));

    REQUIRE(out.size() == 1);
    REQUIRE(is_reg(out[0].dst, "eax", IrType::i32));
    REQUIRE(is_reg(out[0].args.at(0), "ecx", IrType::i32));
    REQUIRE(is_imm(out[0].args.at(1), 4));
}

TEST_CASE("the one-operand imul is left as an unknown", "[lift]") {
    Lifter lifter;

    // The product spreads across rdx:rax, and there's no IR type that wide.
    std::vector<IrInst> out = lifter.lift(plain("imul", "rcx"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("div produces both halves before writing either register", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("div", "rcx"));

    REQUIRE(out.size() == 4);
    REQUIRE(out[0].op == Opcode::div_u);
    REQUIRE(out[1].op == Opcode::rem_u);

    // Both read rax, so neither register can be written until both are done.
    REQUIRE(is_reg(out[0].args.at(0), "rax", IrType::i64));
    REQUIRE(is_reg(out[1].args.at(0), "rax", IrType::i64));

    REQUIRE(out[2].op == Opcode::assign);
    REQUIRE(is_reg(out[2].dst, "rax", IrType::i64));
    REQUIRE(out[3].op == Opcode::assign);
    REQUIRE(is_reg(out[3].dst, "rdx", IrType::i64));
}

TEST_CASE("idiv picks the signed opcodes and the width's register pair", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("idiv", "ecx"));

    REQUIRE(out[0].op == Opcode::div_s);
    REQUIRE(out[1].op == Opcode::rem_s);
    REQUIRE(is_reg(out[0].args.at(0), "eax", IrType::i32));
    REQUIRE(is_reg(out[3].dst, "edx", IrType::i32));
}

TEST_CASE("an eight-bit divide is left as an unknown", "[lift]") {
    Lifter lifter;

    // It divides ax rather than a register pair, so it doesn't fit the shape.
    std::vector<IrInst> out = lifter.lift(plain("div", "cl"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("a direct jump carries its target as a constant", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("jmp", 0x1100));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::jump);
    REQUIRE(is_imm(out[0].args.at(0), 0x1100));
}

TEST_CASE("a jump through a register keeps the register as the target", "[lift]") {
    Lifter lifter;
    Instruction insn = plain("jmp", "rax");
    insn.is_jump = true;

    std::vector<IrInst> out = lifter.lift(insn);

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::jump);
    REQUIRE(is_reg(out[0].args.at(0), "rax", IrType::i64));
}

TEST_CASE("a jump through a table loads the target first", "[lift]") {
    Lifter lifter;
    Instruction insn = plain("jmp", "qword ptr [rax*8 + 0x4020]");
    insn.is_jump = true;

    std::vector<IrInst> out = lifter.lift(insn);

    REQUIRE(out.size() == 4);
    REQUIRE(out[0].op == Opcode::mul);
    REQUIRE(out[1].op == Opcode::add);
    REQUIRE(out[2].op == Opcode::load);
    REQUIRE(out[3].op == Opcode::jump);
    REQUIRE(out[3].args.at(0).temp_id == out[2].dst.temp_id);
}

TEST_CASE("a single-flag condition is read where it sits", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("je", 0x1100, 0x1000, 6));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::branch);
    REQUIRE(is_reg(out[0].args.at(0), "zf", IrType::i1));
}

TEST_CASE("a branch spells out both destinations", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("je", 0x1100, 0x1000, 6));

    REQUIRE(out[0].args.size() == 3);
    REQUIRE(is_imm(out[0].args.at(1), 0x1100));  // taken
    REQUIRE(is_imm(out[0].args.at(2), 0x1006));  // fall-through, past this insn
}

TEST_CASE("the negated half of a condition pair costs one bit_not", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("jne", 0x1100));

    REQUIRE(out.size() == 2);
    REQUIRE(out[0].op == Opcode::bit_not);
    REQUIRE(is_reg(out[0].args.at(0), "zf", IrType::i1));
    REQUIRE(out[1].args.at(0).temp_id == out[0].dst.temp_id);
}

TEST_CASE("signed less-than compares the sign and overflow flags", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("jl", 0x1100));

    REQUIRE(out.size() == 2);
    REQUIRE(out[0].op == Opcode::cmp_ne);
    REQUIRE(is_reg(out[0].args.at(0), "sf", IrType::i1));
    REQUIRE(is_reg(out[0].args.at(1), "of", IrType::i1));
}

TEST_CASE("signed less-or-equal adds the zero flag on top", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("jle", 0x1100));

    REQUIRE(out.size() == 3);
    REQUIRE(out[0].op == Opcode::cmp_ne);
    REQUIRE(out[1].op == Opcode::bit_or);
    REQUIRE(is_reg(out[1].args.at(0), "zf", IrType::i1));
    REQUIRE(out[2].op == Opcode::branch);
}

TEST_CASE("unsigned below-or-equal is carry or zero", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("jbe", 0x1100));

    REQUIRE(out.size() == 2);
    REQUIRE(out[0].op == Opcode::bit_or);
    REQUIRE(is_reg(out[0].args.at(0), "cf", IrType::i1));
    REQUIRE(is_reg(out[0].args.at(1), "zf", IrType::i1));
}

TEST_CASE("the aliases lift the same as the spelling capstone prefers", "[lift]") {
    Lifter a;
    Lifter b;

    // jz is je and jnae is jb, so each pair should come out identical.
    REQUIRE(a.lift(direct_branch("jz", 0x1100)).size() ==
            b.lift(direct_branch("je", 0x1100)).size());

    Lifter c;
    Lifter d;
    std::vector<IrInst> nae = c.lift(direct_branch("jnae", 0x1100));
    std::vector<IrInst> below = d.lift(direct_branch("jb", 0x1100));
    REQUIRE(nae.size() == below.size());
    REQUIRE(is_reg(nae[0].args.at(0), "cf", IrType::i1));
    REQUIRE(is_reg(below[0].args.at(0), "cf", IrType::i1));
}

TEST_CASE("a jump that tests rcx rather than a flag is an unknown", "[lift]") {
    Lifter lifter;

    // jrcxz decrements and tests a register, so it doesn't fit the flag shape
    // even though it starts with a j.
    std::vector<IrInst> out = lifter.lift(direct_branch("jrcxz", 0x1100));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("a call names every register the convention could hand an argument in",
          "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("call", 0x2000));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::call);

    // The target, then the six System V integer argument registers.
    REQUIRE(out[0].args.size() == 7);
    REQUIRE(is_imm(out[0].args.at(0), 0x2000));
    REQUIRE(is_reg(out[0].args.at(1), "rdi", IrType::i64));
    REQUIRE(is_reg(out[0].args.at(6), "r9", IrType::i64));

    // Every call is said to write rax, whether or not the result is used.
    REQUIRE(is_reg(out[0].dst, "rax", IrType::i64));
}

TEST_CASE("a call leaves rsp alone", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(direct_branch("call", 0x2000));

    // The push of the return address and the callee's pop cancel out, so writing
    // either one here would shift every rsp-relative offset after the call.
    for (const IrInst& inst : out) {
        REQUIRE_FALSE(is_reg(inst.dst, "rsp", IrType::i64));
    }
}

TEST_CASE("a call through the got loads the target before calling it", "[lift]") {
    Lifter lifter;
    Instruction insn = plain("call", "qword ptr [rip + 0x2f42]", 0x1000, 6);
    insn.is_call = true;

    std::vector<IrInst> out = lifter.lift(insn);

    REQUIRE(out.size() == 2);
    REQUIRE(out[0].op == Opcode::load);
    REQUIRE(is_imm(out[0].args.at(0), 0x1000 + 6 + 0x2f42));
    REQUIRE(out[1].op == Opcode::call);
    REQUIRE(out[1].args.at(0).temp_id == out[0].dst.temp_id);
}

TEST_CASE("a return reads rax", "[lift]") {
    Lifter lifter;
    Instruction insn = plain("ret", "");
    insn.is_ret = true;

    std::vector<IrInst> out = lifter.lift(insn);

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::ret);
    REQUIRE(is_reg(out[0].args.at(0), "rax", IrType::i64));
}

TEST_CASE("a return that pops arguments is still just a return", "[lift]") {
    Lifter lifter;
    Instruction insn = plain("ret", "0x10");
    insn.is_ret = true;

    std::vector<IrInst> out = lifter.lift(insn);

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::ret);
}

TEST_CASE("the wide nop forms are still a nop", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("nop", "word ptr [rax + rax]"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::nop);
}

TEST_CASE("an instruction the lifter doesn't model becomes one unknown", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("cpuid", ""));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
    REQUIRE_FALSE(out[0].writes_result());
}

TEST_CASE("a failed lift leaves nothing half-emitted behind it", "[lift]") {
    Lifter lifter;

    // xmm0 isn't a register the IR has, so the store can't be modelled -- but
    // the address arithmetic is emitted before that's discovered, and the result
    // still has to be a single unknown rather than an address followed by one.
    std::vector<IrInst> out = lifter.lift(plain("mov", "qword ptr [rbp - 8], xmm0"));

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].op == Opcode::unknown);
}

TEST_CASE("every operation carries the address of the instruction behind it", "[lift]") {
    Lifter lifter;
    std::vector<IrInst> out = lifter.lift(plain("add", "rax, rcx", 0x4040));

    REQUIRE(out.size() > 1);
    for (const IrInst& inst : out) {
        REQUIRE(inst.address == 0x4040);
    }
}

TEST_CASE("temporaries keep counting up across instructions", "[lift]") {
    Lifter lifter;

    lifter.lift(plain("add", "rax, rcx"));
    unsigned after_first = lifter.temp_count();
    REQUIRE(after_first > 0);

    std::vector<IrInst> second = lifter.lift(plain("add", "rbx, rdx"));
    REQUIRE(lifter.temp_count() > after_first);

    // A temp id identifies one value for the whole function, so the second
    // instruction must not reuse the first one's numbers.
    REQUIRE(second.front().dst.temp_id >= after_first);
}

TEST_CASE("reset starts the temp numbering over for a new function", "[lift]") {
    Lifter lifter;

    lifter.lift(plain("add", "rax, rcx"));
    REQUIRE(lifter.temp_count() > 0);

    lifter.reset();
    REQUIRE(lifter.temp_count() == 0);
}
