#ifndef MINIDEC_LIFT_H
#define MINIDEC_LIFT_H

#include <optional>
#include <string_view>
#include <vector>

#include "minidec/disasm.h"
#include "minidec/ir.h"

namespace minidec {

// x86 into the IR from ir.h. The only place that has to know what a machine
// instruction means; everything downstream works on the IR.
//
// One instruction at a time: an x86 instruction can only reach its neighbours
// through registers, flags and memory, and the IR spells all three out, so a
// wider view would add nothing.
//
// Anything outside the modelled subset becomes a single Opcode::unknown. That's
// deliberate -- it holds the instruction's place in the stream, so downstream
// sees a gap instead of a wrong answer.
//
// Calls and returns are where the lifter has to know something the encoding
// doesn't say: which registers carry arguments and results. That comes from the
// System V convention, and the lifter writes those registers into the operation
// for a later pass to narrow.

// Defined in lift.cpp -- only the lifter's own helpers ever handle one.
struct MemoryOperand;

// Width of a machine register, or nothing if the name isn't one we know. Covers
// the integer registers and the flag bits, which the IR treats as i1 registers.
std::optional<IrType> register_type(std::string_view name);

// Carries the temp counter across instructions. Temps are numbered per function
// and never reused, so use one Lifter per function and reset() between them.
class Lifter {
public:
    // In execution order, every operation tagged with the machine instruction's
    // address. Never empty -- an instruction we don't model still yields one
    // unknown.
    std::vector<IrInst> lift(const Instruction& insn);

    unsigned temp_count() const { return next_temp_; }
    void reset() { next_temp_ = 0; }

private:
    IrOperand new_temp(IrType type);

    // One mnemonic each. Return false without touching `out` when the operands
    // aren't a shape we model. Members rather than free functions because they
    // all invent temporaries.
    bool lift_mov(const Instruction& insn, std::vector<IrInst>& out);
    bool lift_add_sub(const Instruction& insn, bool subtract, std::vector<IrInst>& out);
    bool lift_bitwise(const Instruction& insn, Opcode op, std::vector<IrInst>& out);
    // cmp and test, which compute a value only to set flags off it and then
    // throw it away. `logical` picks test (bit_and) over cmp (sub).
    bool lift_cmp_test(const Instruction& insn, bool logical, std::vector<IrInst>& out);
    bool lift_imul(const Instruction& insn, std::vector<IrInst>& out);
    bool lift_div(const Instruction& insn, bool is_signed, std::vector<IrInst>& out);
    bool lift_jmp(const Instruction& insn, std::vector<IrInst>& out);
    bool lift_jcc(const Instruction& insn, std::vector<IrInst>& out);
    bool lift_call(const Instruction& insn, std::vector<IrInst>& out);
    bool lift_ret(const Instruction& insn, std::vector<IrInst>& out);

    // Read the two operands shared by the arithmetic, bitwise and compare
    // instructions. The right-hand side may be in memory, in which case the load
    // is emitted into `out` and `src` names the temporary it landed in, so the
    // caller only ever sees registers, temporaries and constants.
    bool read_binary_operands(const Instruction& insn, std::optional<IrOperand>& dst,
                              std::optional<IrOperand>& src, std::vector<IrInst>& out);

    // The i1 a conditional jump tests: the flag register itself for the
    // single-flag conditions, a temporary otherwise. Nothing, having emitted
    // nothing, when the mnemonic isn't a conditional jump we know.
    std::optional<IrOperand> emit_condition(std::string_view mnemonic, std::uint64_t address,
                                            std::vector<IrInst>& out);

    // The two halves of a mov touching memory. `reg_text` stays unparsed because
    // its width comes from the memory operand opposite it.
    bool lift_load(const Instruction& insn, std::string_view reg_text, const MemoryOperand& mem,
                   std::vector<IrInst>& out);
    bool lift_store(const Instruction& insn, const MemoryOperand& mem, std::string_view value_text,
                    std::vector<IrInst>& out);

    // Address arithmetic into `out`, returning the operand holding the result.
    // Always succeeds, and emits as it goes -- so finish every other check first.
    IrOperand emit_address(const MemoryOperand& mem, const Instruction& insn,
                           std::vector<IrInst>& out);

    // Flag writes shared by add and sub.
    void emit_arith_flags(const IrOperand& lhs, const IrOperand& rhs, const IrOperand& result,
                          bool subtract, std::uint64_t address, std::vector<IrInst>& out);

    // Flag writes for the bitwise instructions and test: zf and sf from the
    // result, cf and of cleared.
    void emit_logic_flags(const IrOperand& result, std::uint64_t address,
                          std::vector<IrInst>& out);

    unsigned next_temp_ = 0;
};

}  // namespace minidec

#endif  // MINIDEC_LIFT_H
