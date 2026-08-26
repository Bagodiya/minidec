#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/datatype.h"
#include "minidec/disasm.h"
#include "minidec/ssa.h"

// Same setup as test_regvar.cpp: instructions by hand, through the CFG and
// build_ssa, then the pass. The versions matter here as much as they do there --
// a register is a number at one version and an address at another -- so the
// input has to be real SSA rather than something written out by hand.

namespace {

using minidec::DataType;
using minidec::Instruction;
using minidec::SsaFunction;
using minidec::TypeMap;

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

TypeMap analyse(std::vector<Instruction> code) {
    std::uint64_t address = 0x1000;
    for (Instruction& one : code) {
        one.address = address;
        address += one.size;
    }

    minidec::CFG cfg;
    cfg.entry = code.front().address;
    cfg.blocks = minidec::group_into_blocks(code);
    minidec::connect_blocks(cfg.blocks);

    return minidec::infer_data_types(minidec::build_ssa(cfg));
}

} // namespace

TEST_CASE("an argument that gets dereferenced is a pointer") {
    TypeMap types = analyse({
        insn("mov", "eax, dword ptr [rdi]", 2),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("rdi", 0) == DataType::pointer);
}

TEST_CASE("a value the function only ever adds up is a number") {
    TypeMap types = analyse({
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("edi", 0) == DataType::integer);
    REQUIRE(types.type_of("rax", 1) == DataType::integer);
}

TEST_CASE("a type is found under any spelling of the register") {
    TypeMap types = analyse({
        insn("mov", "eax, edi", 2),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("al", 0) == types.type_of("rax", 0));
    REQUIRE(types.type_of("rax", 99) == DataType::unknown);
}

TEST_CASE("the frame registers hold addresses") {
    TypeMap types = analyse({
        insn("push", "rbp", 1),
        insn("mov", "rbp, rsp", 3),
        insn("mov", "dword ptr [rbp - 4], edi", 3),
        insn("pop", "rbp", 1),
        insn("ret", "", 1),
    });

    // Which version each of them ends up at depends on where the clobbers from
    // the unlifted push and pop fall, so the claim is about all of them.
    unsigned seen = 0;
    for (const minidec::ValueType& value : types.values) {
        if (value.reg == "rsp" || value.reg == "rbp") {
            REQUIRE(value.type == DataType::pointer);
            ++seen;
        }
    }
    REQUIRE(seen > 0);
}

TEST_CASE("a displacement off a pointer is still a pointer") {
    TypeMap types = analyse({
        insn("mov", "rax, rdi", 3),
        insn("add", "rax, 8", 4),
        insn("mov", "ecx, dword ptr [rax]", 2),
        insn("ret", "", 1),
    });

    // The load names rax#2 as an address; from there the add hands it back to
    // rax#1, and the copy hands that to the argument.
    REQUIRE(types.type_of("rax", 2) == DataType::pointer);
    REQUIRE(types.type_of("rax", 1) == DataType::pointer);
    REQUIRE(types.type_of("rdi", 0) == DataType::pointer);
}

TEST_CASE("an index scaled into a pointer stays a number") {
    TypeMap types = analyse({
        insn("mov", "eax, dword ptr [rdi + rsi*4]", 4),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("rdi", 0) == DataType::pointer);
    REQUIRE(types.type_of("rsi", 0) == DataType::integer);
}

TEST_CASE("a multiplied value is a number even at full width") {
    TypeMap types = analyse({
        insn("mov", "rax, rdi", 3),
        insn("imul", "rax, rsi", 4),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("rax", 1) == DataType::integer);
    REQUIRE(types.type_of("rdi", 0) == DataType::integer);
    REQUIRE(types.type_of("rsi", 0) == DataType::integer);
}

TEST_CASE("the flags stay conditions") {
    TypeMap types = analyse({
        insn("cmp", "edi, 0", 3),
        jump("jne", 0x1007),
        insn("mov", "eax, 1", 5),
        insn("ret", "", 1),
    });

    // jne lifts to a bit_not over zf, and the bitwise rule would call that a
    // number if width did not have the last word.
    REQUIRE(types.type_of("zf", 1) == DataType::boolean);
    REQUIRE(types.type_of("sf", 1) == DataType::boolean);
}

TEST_CASE("a value carried round a loop keeps one answer") {
    // The header is at 0x1004 and the exit at 0x100e, the same shape the regvar
    // tests use, so the counter picks up a phi at the top of the loop.
    TypeMap types = analyse({
        insn("mov", "eax, 0", 4),
        insn("cmp", "eax, edi", 3),
        jump("jge", 0x100e),
        insn("add", "eax, 1", 3),
        jump("jmp", 0x1004),
        insn("mov", "ecx, eax", 2),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("eax", 1) == DataType::integer);
    REQUIRE(types.type_of("eax", 2) == DataType::integer);
    REQUIRE(types.type_of("eax", 3) == DataType::integer);
}

TEST_CASE("a value used both ways is reported rather than picked") {
    TypeMap types = analyse({
        insn("mov", "eax, dword ptr [rdi]", 2),
        insn("imul", "rdi, rdi", 4),
        insn("ret", "", 1),
    });

    REQUIRE(types.type_of("rdi", 0) == DataType::conflict);
    REQUIRE(types.conflicts() == 1);
}

TEST_CASE("values come out in a stable order") {
    TypeMap types = analyse({
        insn("mov", "eax, edi", 2),
        insn("add", "eax, esi", 2),
        insn("ret", "", 1),
    });

    REQUIRE_FALSE(types.empty());
    for (std::size_t i = 1; i < types.values.size(); ++i) {
        const minidec::ValueType& before = types.values[i - 1];
        const minidec::ValueType& after = types.values[i];

        if (before.kind != after.kind) {
            REQUIRE(before.kind == minidec::OperandKind::reg);
            continue;
        }
        if (before.kind == minidec::OperandKind::temp) {
            REQUIRE(before.temp_id < after.temp_id);
        } else if (before.reg == after.reg) {
            REQUIRE(before.version < after.version);
        } else {
            REQUIRE(before.reg < after.reg);
        }
    }
}

TEST_CASE("a function with nothing in it has no values") {
    REQUIRE(minidec::infer_data_types(SsaFunction{}).empty());
}
