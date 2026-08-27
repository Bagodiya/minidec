#ifndef MINIDEC_PARAMS_H
#define MINIDEC_PARAMS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "minidec/ir.h"
#include "minidec/ssa.h"

namespace minidec {

// What the function was handed.
//
// A compiled function has no parameter list. The caller puts values in agreed
// registers and jumps, and the callee reads them or doesn't; nothing in the
// bytes of either side says how many there were meant to be. The agreement is
// the whole of the evidence, so this pass is the System V rules read backwards.
//
// SSA does most of the work. A register the caller filled in is a register this
// function never wrote, which is exactly what version 0 means, so a read of
// rdi#0 is a read of the first argument and there is nothing further to prove.
// The awkward part is the other direction: the six registers are filled in a
// fixed order, so a function reading r8 was handed five arguments before it
// whether or not it bothers with any of them. The count therefore comes from the
// last register read and the gaps below it are listed as parameters nothing
// looks at, which is what a function ignoring its second argument really does.
//
// One thing has to be discounted. The lifter writes all six registers into every
// call it emits, since it can't see what the callee reads and would rather name
// an argument that isn't there than lose one that is. Those reads are a guess
// about somebody else's parameters, and taking them at face value here would
// give six arguments to every function that calls anything at all. So a call's
// argument slots aren't evidence, and a register that turns up in nothing else
// is reported apart, under `forwarded` -- it is either an argument being passed
// straight through or a register that happened to be sitting there, and the two
// look identical from inside.
//
// Two kinds of argument are missing. The seventh onwards arrive on the stack
// above the return address, and reaching them means measuring from the caller's
// rsp through a "push rbp" the lifter doesn't model, so the offsets aren't
// trustworthy yet. Floats arrive in xmm0-7, which the lifter doesn't produce.
// Neither is rare in real code; both need work elsewhere first. `saturated()`
// says when the register side is full, which is when a stack argument could be
// hiding behind it.

// One place a parameter is read.
struct ParamRead {
    std::uint64_t block = 0;   // block this happens in
    std::size_t inst = 0;      // index into SsaBlock::code, or into phis for a phi
    std::size_t arg = 0;       // which argument slot of that instruction
    std::uint64_t address = 0; // machine instruction behind it, 0 for a phi
    unsigned width = 0;        // bits the read spelled it at

    // A phi argument rather than a real instruction. Still a read -- the value
    // reached a join alive -- but there is no address to point at.
    bool is_phi = false;
};

// One argument.
struct Parameter {
    unsigned index = 0; // position in the argument list, counting from 0
    std::string reg;    // the 64-bit name it arrives in

    // Widest spelling any read used. A parameter only ever touched as edi is 32
    // bits wide, which is the closest thing to a declared type available here.
    // Zero when nothing reads it, since an unused argument leaves no clue.
    unsigned width = 0;

    std::vector<ParamRead> reads; // in block order, then instruction order

    // False for the gaps: an argument the convention says was passed but this
    // function never looks at.
    bool used() const { return !reads.empty(); }
};

struct ParamList {
    // By index, with no holes -- a gap is a Parameter with no reads, not a
    // missing entry.
    std::vector<Parameter> params;

    // Argument registers whose only appearance at version 0 was in a call's
    // argument slots. See the note above: not counted, not discarded.
    std::vector<std::string> forwarded;

    bool empty() const { return params.empty(); }
    std::size_t size() const { return params.size(); }

    // All six registers accounted for, so the real argument list may run on into
    // the stack where this pass can't follow it.
    bool saturated() const { return params.size() == 6; }

    const Parameter* at(unsigned index) const;

    // By arrival register, spelled at any width.
    const Parameter* find(const std::string& reg) const;
};

// Recover the parameter list of one function.
ParamList recover_parameters(const SsaFunction& fn);

} // namespace minidec

#endif // MINIDEC_PARAMS_H
