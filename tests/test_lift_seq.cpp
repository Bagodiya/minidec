#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "minidec/disasm.h"
#include "minidec/ir.h"
#include "minidec/lift.h"

// test_lift.cpp takes one instruction at a time. This file runs whole sequences
// through a single Lifter, which is how the ir command uses it, and checks the
// things that can only go wrong once there is more than one instruction: temp
// numbering that has to stay unique for the whole function, flags one
// instruction writes and the next one reads, and branch targets that depend on
// where the instructions were laid out.

namespace {

using minidec::Instruction;
using minidec::IrInst;
using minidec::IrOperand;
using minidec::IrType;
using minidec::Lifter;
using minidec::Opcode;
using minidec::OperandKind;

// One line of the little test programs below. `target` is the index of the line
// a branch goes to rather than an address, because the address isn't known until
// everything has been laid out.
struct Line {
    std::string mnemonic;
    std::string operands;
    std::uint16_t size = 4;
    int target = -1;
};

Line insn(std::string mnemonic, std::string operands, std::uint16_t size = 4) {
    return Line{std::move(mnemonic), std::move(operands), size, -1};
}

Line branch_to(std::string mnemonic, int target, std::uint16_t size = 6) {
    return Line{std::move(mnemonic), "", size, target};
}

std::string hex(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
    return buffer;
}

// Lay the lines out back to back from `start` and fill in the branch targets.
// Two passes, since a forward jump names a line that hasn't been placed yet.
//
// Doing this properly matters: a fall-through address is the instruction's own
// address plus its size, so sequences built with everything at one address would
// pass tests that a real function fails.
std::vector<Instruction> assemble(const std::vector<Line>& lines,
                                  std::uint64_t start = 0x1000) {
    std::vector<std::uint64_t> addresses;
    std::uint64_t address = start;
    for (const Line& line : lines) {
        addresses.push_back(address);
        address += line.size;
    }

    std::vector<Instruction> out;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const Line& line = lines[i];

        Instruction result;
        result.address = addresses[i];
        result.size = line.size;
        result.mnemonic = line.mnemonic;
        result.op_str = line.operands;

        result.is_call = line.mnemonic == "call";
        result.is_ret = line.mnemonic == "ret";
        result.is_jump = !result.is_call && !result.is_ret && line.mnemonic.front() == 'j';

        if (line.target >= 0) {
            result.op_str = hex(addresses[static_cast<std::size_t>(line.target)]);
            result.is_relative = true;
        }

        out.push_back(std::move(result));
    }
    return out;
}

std::vector<IrInst> lift_all(Lifter& lifter, const std::vector<Instruction>& insns) {
    std::vector<IrInst> out;
    for (const Instruction& one : insns) {
        for (IrInst& ir : lifter.lift(one)) {
            out.push_back(std::move(ir));
        }
    }
    return out;
}

bool is_reg(const IrOperand& operand, const std::string& name) {
    return operand.kind == OperandKind::reg && operand.reg == name;
}

bool is_imm(const IrOperand& operand, std::uint64_t value) {
    return operand.kind == OperandKind::imm && operand.imm == value;
}

bool is_temp(const IrOperand& operand) { return operand.kind == OperandKind::temp; }

std::size_t count_op(const std::vector<IrInst>& ir, Opcode op) {
    std::size_t total = 0;
    for (const IrInst& one : ir) {
        if (one.op == op) {
            ++total;
        }
    }
    return total;
}

// Every operation that came from the instruction at `address`, in order.
std::vector<IrInst> from_address(const std::vector<IrInst>& ir, std::uint64_t address) {
    std::vector<IrInst> out;
    for (const IrInst& one : ir) {
        if (one.address == address) {
            out.push_back(one);
        }
    }
    return out;
}

// Two IR streams match when they say the same thing. Only the fields the tests
// below care about, which is enough to tell whether two lifts of the same
// instructions came out the same way.
bool same_operand(const IrOperand& a, const IrOperand& b) {
    return a.kind == b.kind && a.type == b.type && a.reg == b.reg && a.temp_id == b.temp_id &&
           a.imm == b.imm;
}

bool same_inst(const IrInst& a, const IrInst& b) {
    if (a.op != b.op || a.type != b.type || a.address != b.address ||
        a.args.size() != b.args.size() || !same_operand(a.dst, b.dst)) {
        return false;
    }
    for (std::size_t i = 0; i < a.args.size(); ++i) {
        if (!same_operand(a.args[i], b.args[i])) {
            return false;
        }
    }
    return true;
}

// int add_one(int x) { return x + 1; }
//
// The parameter goes to the stack and comes straight back off it, which is what
// an unoptimised build does and what most of the fixtures look like.
std::vector<Instruction> add_one_program() {
    return assemble({
        insn("push", "rbp", 1),
        insn("mov", "rbp, rsp", 3),
        insn("mov", "dword ptr [rbp - 4], edi", 3),
        insn("mov", "eax, dword ptr [rbp - 4]", 3),
        insn("add", "eax, 1", 3),
        insn("pop", "rbp", 1),
        insn("ret", "", 1),
    });
}

// int pick(int a, int b) { return a > b ? a : b; }
//
//   0  cmp edi, esi
//   1  jle 4
//   2  mov eax, edi
//   3  jmp 5
//   4  mov eax, esi
//   5  ret
std::vector<Instruction> pick_program() {
    return assemble({
        insn("cmp", "edi, esi", 2),
        branch_to("jle", 4, 2),
        insn("mov", "eax, edi", 2),
        branch_to("jmp", 5, 2),
        insn("mov", "eax, esi", 2),
        insn("ret", "", 1),
    });
}

// A counting loop, so there's a jump that goes backwards.
//
//   0  mov eax, 0
//   1  cmp eax, 0xa
//   2  jge 5
//   3  add eax, 1
//   4  jmp 1
//   5  ret
std::vector<Instruction> loop_program() {
    return assemble({
        insn("mov", "eax, 0", 5),
        insn("cmp", "eax, 0xa", 3),
        branch_to("jge", 5, 2),
        insn("add", "eax, 1", 3),
        branch_to("jmp", 1, 2),
        insn("ret", "", 1),
    });
}

}  // namespace

TEST_CASE("every instruction in a sequence leaves something behind", "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = add_one_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    // An instruction that lifted to nothing would be a hole in the function that
    // no later pass could see, so the count matters more than the contents.
    for (const Instruction& one : program) {
        REQUIRE_FALSE(from_address(ir, one.address).empty());
    }
}

TEST_CASE("operations come out in the order their instructions did", "[lift][seq]") {
    Lifter lifter;
    std::vector<IrInst> ir = lift_all(lifter, add_one_program());

    // Passes downstream read the stream front to back and assume that's
    // execution order.
    for (std::size_t i = 1; i < ir.size(); ++i) {
        REQUIRE(ir[i].address >= ir[i - 1].address);
    }
}

TEST_CASE("no temporary is written twice in one function", "[lift][seq]") {
    Lifter lifter;
    std::vector<IrInst> ir = lift_all(lifter, loop_program());

    // The whole point of the numbering: an id names one value, so use-def can
    // find the one operation that produced it.
    std::set<unsigned> written;
    for (const IrInst& one : ir) {
        if (one.writes_result() && is_temp(one.dst)) {
            REQUIRE(written.insert(one.dst.temp_id).second);
        }
    }
    REQUIRE_FALSE(written.empty());
}

TEST_CASE("a temporary is written before anything reads it", "[lift][seq]") {
    Lifter lifter;
    std::vector<IrInst> ir = lift_all(lifter, pick_program());

    std::set<unsigned> written;
    for (const IrInst& one : ir) {
        for (const IrOperand& arg : one.args) {
            if (is_temp(arg)) {
                REQUIRE(written.count(arg.temp_id) == 1);
            }
        }
        if (one.writes_result() && is_temp(one.dst)) {
            written.insert(one.dst.temp_id);
        }
    }
}

TEST_CASE("temp_count covers every temporary the function used", "[lift][seq]") {
    Lifter lifter;
    std::vector<IrInst> ir = lift_all(lifter, loop_program());

    for (const IrInst& one : ir) {
        if (one.writes_result() && is_temp(one.dst)) {
            REQUIRE(one.dst.temp_id < lifter.temp_count());
        }
    }
}

TEST_CASE("an instruction the lifter skips costs one operation and nothing else",
          "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = add_one_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    // push and pop aren't modelled yet. Each should be one unknown sitting in
    // place, with the instructions on either side lifted as usual.
    REQUIRE(count_op(ir, Opcode::unknown) == 2);
    REQUIRE(from_address(ir, program[0].address).size() == 1);
    REQUIRE(from_address(ir, program[0].address)[0].op == Opcode::unknown);
    REQUIRE(from_address(ir, program[5].address).size() == 1);

    REQUIRE(from_address(ir, program[1].address)[0].op == Opcode::assign);
    REQUIRE(from_address(ir, program[6].address)[0].op == Opcode::ret);
}

TEST_CASE("a spill and the load after it compute the address separately", "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = add_one_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    std::vector<IrInst> spill = from_address(ir, program[2].address);
    std::vector<IrInst> reload = from_address(ir, program[3].address);

    REQUIRE(spill.size() == 2);
    REQUIRE(spill[1].op == Opcode::store);
    REQUIRE(reload.size() == 2);
    REQUIRE(reload[1].op == Opcode::load);

    // Same address, worked out twice: there's no common subexpression pass yet,
    // and the two temporaries have to stay separate values until there is one.
    REQUIRE(is_reg(spill[0].args.at(0), "rbp"));
    REQUIRE(is_reg(reload[0].args.at(0), "rbp"));
    REQUIRE(spill[0].args.at(1).imm == reload[0].args.at(1).imm);
    REQUIRE(spill[0].dst.temp_id != reload[0].dst.temp_id);
}

TEST_CASE("the flags a compare writes are the ones the jump after it reads", "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = pick_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    std::set<std::string> set_by_cmp;
    for (const IrInst& one : from_address(ir, program[0].address)) {
        if (one.writes_result() && one.dst.kind == OperandKind::reg) {
            set_by_cmp.insert(one.dst.reg);
        }
    }

    // jle reads zf, sf and of. If the compare didn't write one of them the
    // branch would be testing whatever the function started with.
    for (const IrInst& one : from_address(ir, program[1].address)) {
        for (const IrOperand& arg : one.args) {
            if (arg.kind == OperandKind::reg && arg.type == IrType::i1) {
                REQUIRE(set_by_cmp.count(arg.reg) == 1);
            }
        }
    }
}

TEST_CASE("a branch names the instruction that follows it as the fall-through",
          "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = pick_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    std::vector<IrInst> jle = from_address(ir, program[1].address);
    REQUIRE(jle.back().op == Opcode::branch);
    REQUIRE(is_imm(jle.back().args.at(1), program[4].address));  // taken
    REQUIRE(is_imm(jle.back().args.at(2), program[2].address));  // fall-through
}

TEST_CASE("a jump backwards keeps pointing at the instruction it started from",
          "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = loop_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    // The back edge the CFG will find its loop from.
    std::vector<IrInst> back = from_address(ir, program[4].address);
    REQUIRE(back.size() == 1);
    REQUIRE(back[0].op == Opcode::jump);
    REQUIRE(is_imm(back[0].args.at(0), program[1].address));
    REQUIRE(back[0].args.at(0).imm < program[4].address);
}

TEST_CASE("only the instructions that branch end a block", "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = loop_program();
    std::vector<IrInst> ir = lift_all(lifter, program);

    for (const IrInst& one : ir) {
        if (!one.ends_block()) {
            continue;
        }
        // jge, jmp and ret, and nothing else in this program.
        REQUIRE((one.address == program[2].address || one.address == program[4].address ||
                 one.address == program[5].address));
    }

    // And a terminator is always the last thing its instruction produced.
    for (const Instruction& one : program) {
        std::vector<IrInst> lifted = from_address(ir, one.address);
        for (std::size_t i = 0; i + 1 < lifted.size(); ++i) {
            REQUIRE_FALSE(lifted[i].ends_block());
        }
    }
}

TEST_CASE("a call's result is there for the instruction after it to read", "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = assemble({
        insn("mov", "edi, 1", 5),
        branch_to("call", 3, 5),
        insn("add", "eax, 1", 3),
        insn("ret", "", 1),
    });
    std::vector<IrInst> ir = lift_all(lifter, program);

    std::vector<IrInst> call = from_address(ir, program[1].address);
    REQUIRE(call.size() == 1);
    REQUIRE(is_reg(call[0].dst, "rax"));

    // eax rather than rax, but whole_register() folds the two together, so the
    // add is reading what the call wrote.
    REQUIRE(is_reg(from_address(ir, program[2].address).front().args.at(0), "eax"));
    REQUIRE(minidec::whole_register("eax") == minidec::whole_register("rax"));
}

TEST_CASE("reset makes the next function lift the same as the first did", "[lift][seq]") {
    Lifter lifter;
    std::vector<Instruction> program = pick_program();

    std::vector<IrInst> first = lift_all(lifter, program);
    lifter.reset();
    std::vector<IrInst> second = lift_all(lifter, program);

    // Without the reset the second run would start numbering where the first
    // left off, and two functions lifted by one Lifter would never compare equal.
    REQUIRE(first.size() == second.size());
    for (std::size_t i = 0; i < first.size(); ++i) {
        REQUIRE(same_inst(first[i], second[i]));
    }
}

TEST_CASE("lifting one function after another without a reset keeps the ids apart",
          "[lift][seq]") {
    Lifter lifter;

    lift_all(lifter, add_one_program());
    unsigned after_first = lifter.temp_count();

    std::vector<IrInst> second = lift_all(lifter, loop_program());
    for (const IrInst& one : second) {
        if (one.writes_result() && is_temp(one.dst)) {
            REQUIRE(one.dst.temp_id >= after_first);
        }
    }
}
