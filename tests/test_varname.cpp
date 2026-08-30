#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/params.h"
#include "minidec/regvar.h"
#include "minidec/ssa.h"
#include "minidec/stack.h"
#include "minidec/varname.h"

// The naming pass is the one place the three recovery passes meet, so these run
// all four over the same function rather than handing name_variables lists made
// up here. A ParamList written by hand would agree with whatever this file
// expects and with nothing else, and the numbering is only worth anything if it
// holds over what the earlier passes actually produce.
//
// Same harness as test_stack.cpp and test_regvar.cpp. Sizes are invented but
// non-zero, since the instructions are laid out end to end.

namespace {

using minidec::CFG;
using minidec::Instruction;
using minidec::NamedVar;
using minidec::NameTable;
using minidec::SsaFunction;
using minidec::StackFrame;
using minidec::VarKind;

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

SsaFunction lift(std::vector<Instruction> code) {
    std::uint64_t address = 0x1000;
    for (Instruction& one : code) {
        one.address = address;
        address += one.size;
    }

    CFG cfg;
    cfg.entry = code.front().address;
    cfg.blocks = minidec::group_into_blocks(code);
    minidec::connect_blocks(cfg.blocks);
    return minidec::build_ssa(cfg);
}

NameTable analyse(std::vector<Instruction> code) {
    SsaFunction fn = lift(std::move(code));
    return minidec::name_variables(minidec::recover_parameters(fn),
                                   minidec::find_stack_variables(fn),
                                   minidec::find_register_variables(fn));
}

std::vector<Instruction> with_prologue(std::vector<Instruction> body) {
    std::vector<Instruction> code = {insn("push", "rbp", 1), insn("mov", "rbp, rsp", 3)};
    for (Instruction& one : body) {
        code.push_back(std::move(one));
    }
    code.push_back(insn("ret", "", 1));
    return code;
}

std::vector<std::string> names_of(const NameTable& table, VarKind kind) {
    std::vector<std::string> found;
    for (const NamedVar& var : table.vars) {
        if (var.kind == kind) {
            found.push_back(var.name);
        }
    }
    return found;
}

// eax = edi + esi. Two arguments, no frame, one value kept in a register.
std::vector<Instruction> add_two() {
    return {
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    };
}

} // namespace

TEST_CASE("arguments are named apart from the locals") {
    NameTable table = analyse(add_two());

    REQUIRE(names_of(table, VarKind::parameter) == std::vector<std::string>{"arg_0", "arg_1"});

    const NamedVar* first = table.find("arg_0");
    REQUIRE(first != nullptr);
    REQUIRE(first->index == 0);
    REQUIRE(first->reg == "rdi");
    REQUIRE(first->width == 32);
}

TEST_CASE("a name that isn't in the table comes back null") {
    NameTable table = analyse(add_two());

    REQUIRE(table.find("arg_7") == nullptr);
    REQUIRE(table.find("") == nullptr);
}

TEST_CASE("stack slots are numbered low offset first") {
    NameTable table = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "dword ptr [rbp - 0xc], esi"),
        insn("mov", "eax, dword ptr [rbp - 4]"),
    }));

    // Same order find_stack_variables gave them, which is by offset, so the slot
    // furthest down the frame is var_0.
    const NamedVar* low = table.find("var_0");
    const NamedVar* high = table.find("var_1");
    REQUIRE(low != nullptr);
    REQUIRE(high != nullptr);
    REQUIRE(low->offset == -0xc);
    REQUIRE(high->offset == -4);
    REQUIRE(low->kind == VarKind::stack);
}

TEST_CASE("a slot's width is its size in bits") {
    NameTable table = analyse(with_prologue({
        insn("mov", "qword ptr [rbp - 0x10], rdi"),
        insn("mov", "rax, qword ptr [rbp - 0x10]"),
    }));

    const NamedVar* slot = table.find("var_0");
    REQUIRE(slot != nullptr);
    REQUIRE(slot->width == 64);
}

TEST_CASE("a slot is found by the value its offset is measured from") {
    std::vector<Instruction> code = with_prologue({insn("mov", "dword ptr [rbp - 4], edi")});
    SsaFunction fn = lift(code);

    StackFrame frame = minidec::find_stack_variables(fn);
    REQUIRE(frame.size() == 1);

    NameTable table = minidec::name_variables(minidec::recover_parameters(fn), frame,
                                              minidec::find_register_variables(fn));

    const NamedVar* slot = table.stack_slot(frame.vars[0].base, frame.vars[0].base_version, -4);
    REQUIRE(slot != nullptr);
    REQUIRE(slot->name == "var_0");

    // Right base, wrong offset, and an offset that is right against a base the
    // function never used.
    REQUIRE(table.stack_slot(frame.vars[0].base, frame.vars[0].base_version, -8) == nullptr);
    REQUIRE(table.stack_slot(frame.vars[0].base, frame.vars[0].base_version + 9, -4) == nullptr);
}

TEST_CASE("register locals carry on from where the slots stopped") {
    NameTable table = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "eax, dword ptr [rbp - 4]"),
        insn("add", "eax, 1", 3),
    }));

    const NamedVar* slot = table.find("var_0");
    REQUIRE(slot != nullptr);
    REQUIRE(slot->kind == VarKind::stack);

    // Whatever the register pass turned up starts at var_1. Numbering the two
    // kinds separately would put a second var_0 in the listing.
    const std::vector<std::string> locals = names_of(table, VarKind::reg);
    REQUIRE_FALSE(locals.empty());
    REQUIRE(locals.front() == "var_1");
}

TEST_CASE("an argument read further down keeps the name it arrived with") {
    NameTable table = analyse(add_two());

    // rdi#0 is both the first parameter and a register variable. Naming it twice
    // would print one value under two names.
    const NamedVar* arg = table.find("arg_0");
    REQUIRE(arg != nullptr);
    REQUIRE(table.value("rdi", 0) == arg);

    for (const NamedVar& var : table.vars) {
        REQUIRE_FALSE((var.kind == VarKind::reg && var.reg == "rdi"));
    }
}

TEST_CASE("a name lookup takes a register at any of its spellings") {
    NameTable table = analyse(add_two());

    const NamedVar* arg = table.find("arg_0");
    REQUIRE(arg != nullptr);
    REQUIRE(table.value("edi", 0) == arg);
    REQUIRE(table.value("dil", 0) == arg);
    REQUIRE(table.value("rdi", 4) == nullptr);
    REQUIRE(table.value("r15", 0) == nullptr);
}

TEST_CASE("the versions a phi joins share one name") {
    // A counter round a loop: the header is at 0x1004 and the exit at 0x100e, so
    // the back edge closes on a block with two predecessors.
    NameTable table = analyse({
        insn("mov", "eax, 0", 4),
        insn("cmp", "eax, edi", 3),
        jump("jge", 0x100e),
        insn("add", "eax, 1", 3),
        jump("jmp", 0x1004),
        insn("mov", "ecx, eax", 2),
        insn("ret", "", 1),
    });

    const NamedVar* counter = table.value("eax", 1);
    REQUIRE(counter != nullptr);
    REQUIRE(counter->kind == VarKind::reg);
    REQUIRE(counter->versions.size() > 1);
    REQUIRE(table.value("eax", counter->versions.back()) == counter);
}

TEST_CASE("names hold still across two runs over the same function") {
    NameTable first = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "dword ptr [rbp - 0xc], esi"),
        insn("mov", "eax, dword ptr [rbp - 0xc]"),
        insn("add", "eax, dword ptr [rbp - 4]"),
    }));
    NameTable second = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 4], edi"),
        insn("mov", "dword ptr [rbp - 0xc], esi"),
        insn("mov", "eax, dword ptr [rbp - 0xc]"),
        insn("add", "eax, dword ptr [rbp - 4]"),
    }));

    REQUIRE(first.size() == second.size());
    for (std::size_t i = 0; i < first.size(); ++i) {
        REQUIRE(first.vars[i].name == second.vars[i].name);
        REQUIRE(first.vars[i].offset == second.vars[i].offset);
        REQUIRE(first.vars[i].reg == second.vars[i].reg);
    }
}

TEST_CASE("adding a slot at the top of the frame leaves the ones below it alone") {
    NameTable before = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 8], edi"),
        insn("mov", "eax, dword ptr [rbp - 8]"),
    }));
    NameTable after = analyse(with_prologue({
        insn("mov", "dword ptr [rbp - 8], edi"),
        insn("mov", "dword ptr [rbp - 0x10], esi"),
        insn("mov", "eax, dword ptr [rbp - 8]"),
    }));

    // The new slot is further down, so it takes var_0 and the old one shifts.
    // Nothing better is possible while the numbering follows the offsets, but
    // the offsets themselves have to keep meaning the same thing.
    REQUIRE(before.find("var_0")->offset == -8);
    REQUIRE(after.find("var_0")->offset == -0x10);
    REQUIRE(after.find("var_1")->offset == -8);
}

TEST_CASE("every kind has a name to print") {
    REQUIRE(std::string(minidec::var_kind_name(VarKind::parameter)) == "parameter");
    REQUIRE(std::string(minidec::var_kind_name(VarKind::stack)) == "stack");
    REQUIRE(std::string(minidec::var_kind_name(VarKind::reg)) == "register");
}

TEST_CASE("a function with nothing in it gets no names") {
    NameTable table =
        minidec::name_variables(minidec::ParamList{}, minidec::StackFrame{}, minidec::RegVars{});

    REQUIRE(table.empty());
    REQUIRE(table.size() == 0);
}
