#ifndef MINIDEC_USEDEF_H
#define MINIDEC_USEDEF_H

#include <cstddef>
#include <vector>

#include "minidec/ir.h"

namespace minidec {

// Use-def chains over a run of IR: for every value an operation reads, the
// operation that wrote it, and for every write, the list of reads that see it.
//
// Straight-line only. Operations are taken in order and a definition reaches
// forward until something overwrites it, which is the whole story inside a basic
// block. Across blocks a value can arrive from two places at once and there is
// no single definition to name -- that's what SSA is for, and it's built on top
// of this rather than instead of it.
//
// Everything is an index into the vector the chains were computed from, so the
// IR carries no links of its own and stays cheap to copy. The chains go stale
// the moment that vector is edited.

// Where a value is read: the operation, and which of its arguments does it.
struct Use {
    std::size_t inst = 0;
    std::size_t arg = 0;
};

// One write, and everything that reads it back.
struct Def {
    std::size_t inst = 0;  // the operation doing the writing
    IrOperand value;       // the register or temporary written
    std::vector<Use> uses;

    // Nothing here reads it. Normal rather than suspicious: almost every
    // arithmetic instruction writes four flags and the next one overwrites them
    // untouched.
    //
    // Not on its own a reason to delete the operation. A chain that runs into
    // an unknown or a call stops there, so a definition something past the cut
    // still reads comes back dead.
    bool dead() const { return uses.empty(); }
};

struct UseDefChains {
    // Stands in for a definition index wherever there isn't one.
    static constexpr std::size_t none = static_cast<std::size_t>(-1);

    std::vector<Def> defs;  // in the order the operations write them

    // Per operation, the definition reaching each argument. Laid out alongside
    // IrInst::args, so reaching[i][a] answers for argument a of operation i.
    std::vector<std::vector<std::size_t>> reaching;

    // Per operation, the definition it writes, or none when it writes nothing.
    std::vector<std::size_t> written;

    // Values read before anything here wrote them, in the order first read. At
    // the top of a function that's the arguments and the stack pointer; further
    // in it's whatever the code above left behind.
    std::vector<IrOperand> live_in;

    // Both hand back nullptr when there's nothing to point at, so a caller can
    // ask about any operation without checking the index first.
    const Def* reaching_def(std::size_t inst, std::size_t arg) const;
    const Def* def_written_by(std::size_t inst) const;
};

// Chains for one run of operations, which is a basic block's worth of lifted IR
// or a whole function when it doesn't branch.
//
// Two things end a register's chain besides an ordinary overwrite: an
// Opcode::unknown, which stands for an instruction we couldn't model and so
// could have written anything, and a call, which is allowed to leave the
// caller-saved registers changed.
UseDefChains compute_use_def(const std::vector<IrInst>& code);

}  // namespace minidec

#endif  // MINIDEC_USEDEF_H
