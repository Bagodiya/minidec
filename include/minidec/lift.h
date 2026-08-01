#ifndef MINIDEC_LIFT_H
#define MINIDEC_LIFT_H

#include <optional>
#include <string_view>
#include <vector>

#include "minidec/disasm.h"
#include "minidec/ir.h"

namespace minidec {

// Turning x86 into the IR from ir.h. This is the one place in the program that
// has to know what a machine instruction actually means, and everything after it
// works on the IR instead, so it's worth keeping the boundary sharp: a decoded
// Instruction goes in, a short run of IrInst comes out, and nothing leaks back.
//
// The lifting happens one instruction at a time on purpose. An x86 instruction
// can't affect its neighbours except through registers, flags and memory, and all
// three of those are already spelled out in the IR the lifter emits, so there's
// nothing a wider view would tell us. Doing it per-instruction also means every
// later step can be tested by handing over a single Instruction and reading back
// the operations, without having to build a whole function first.
//
// Only a small slice of x86 is handled so far -- moves between registers and
// constants, nop, and the integer arithmetic that works register to register.
// Everything else becomes a single Opcode::unknown, which is deliberate: an
// instruction we can't model yet still shows up in the right place in the
// stream, so the passes downstream see a gap rather than a wrong answer, and the
// function around it stays analysable. Memory, branches and calls each get
// filled in over the steps after this one.

// How wide a machine register is, or nothing if the name isn't one we know.
// Covers the 64/32/16/8-bit integer registers under their usual names plus the
// flag bits, which the IR treats as ordinary i1 registers.
std::optional<IrType> register_type(std::string_view name);

// Holds the state that has to survive between instructions -- which is only the
// temporary counter, but that's enough to need an object. Temps are numbered
// per function and never reused, so a single Lifter should be used for one
// function's worth of instructions and then reset (or thrown away) before the
// next, otherwise the numbering runs on and two functions share a range.
class Lifter {
public:
    // Lift a single decoded instruction. The result is in execution order, and
    // every operation in it carries the machine instruction's address so the
    // output stage can line the two up later. Never returns an empty vector: an
    // instruction we don't understand still produces one unknown operation.
    std::vector<IrInst> lift(const Instruction& insn);

    // How many temporaries have been handed out so far. Really only useful for
    // tests and for sizing tables in the passes that come later.
    unsigned temp_count() const { return next_temp_; }

    // Start the temp numbering over, for when the same Lifter moves on to a new
    // function.
    void reset() { next_temp_ = 0; }

private:
    // Hand out the next unused temporary at the given width.
    IrOperand new_temp(IrType type);

    // One mnemonic each, appending to `out` and returning false without having
    // touched it when the operands aren't a shape we can model. These are
    // members rather than file-local helpers because they all invent
    // temporaries, and the counter for those lives here.
    bool lift_add_sub(const Instruction& insn, bool subtract, std::vector<IrInst>& out);
    bool lift_imul(const Instruction& insn, std::vector<IrInst>& out);
    bool lift_div(const Instruction& insn, bool is_signed, std::vector<IrInst>& out);

    // The flag writes shared by add and sub, given the two operands and the
    // temporary holding the result.
    void emit_arith_flags(const IrOperand& lhs, const IrOperand& rhs, const IrOperand& result,
                          bool subtract, std::uint64_t address, std::vector<IrInst>& out);

    unsigned next_temp_ = 0;
};

}  // namespace minidec

#endif  // MINIDEC_LIFT_H
