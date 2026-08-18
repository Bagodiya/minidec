#ifndef MINIDEC_SSA_H
#define MINIDEC_SSA_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/ir.h"

namespace minidec {

// A function's IR with every register read pointing at exactly one write.
//
// Use-def already does that inside a block. The problem is the joins: at the
// bottom of an if/else, "rax" means one thing down one edge and another down the
// other, and no single write can be named. SSA fixes it by giving every write
// its own version and putting a phi at the join to say which version arrived.
//
// Only registers are versioned. The lifter hands out a fresh temporary for every
// value it invents and never reuses one, so temporaries come out of it already
// single-assignment and are left exactly as they are.
//
// Versions count from 1. Version 0 is whatever the register held on entry to the
// function -- nothing here wrote it -- which for rdi or rsp is the whole point
// rather than a gap.
//
// Aliases fold the way use-def folds them: a write to eax or al counts as a
// write to rax, so one version counter covers every spelling of a register.

// A value picked by the edge control arrived on. One incoming operand per
// predecessor, in the same order as SsaBlock::predecessors, so slot i is the
// version live at the end of predecessor i.
struct SsaPhi {
    IrOperand dst;
    std::vector<IrOperand> incoming;

    // The register, by the name every version of it is spelled with.
    const std::string& reg() const { return dst.reg; }
};

// Registers a call or an unknown instruction may have written without saying so:
// a call is allowed to trample the caller-saved ones, and an unknown could have
// done anything at all. Each gets a fresh version, since a read after this point
// is not reading what was there before.
//
// They live out here rather than in the instruction because there's one dst slot
// and this is a dozen registers at once.
struct SsaClobber {
    std::size_t inst = 0;           // index into SsaBlock::code
    std::vector<IrOperand> values;  // the new versions, one per register
};

// One block's worth. Phis run before the code, all at once and reading the
// versions from the ends of the predecessors, which is the usual way to read
// them -- ordering them against each other would be meaningless.
struct SsaBlock {
    std::uint64_t start = 0;

    // Both sorted by address, and predecessors is what fixes the phi argument
    // order.
    std::vector<std::uint64_t> predecessors;
    std::vector<std::uint64_t> successors;

    std::vector<SsaPhi> phis;
    std::vector<IrInst> code;
    std::vector<SsaClobber> clobbers;  // by rising instruction index
};

struct SsaFunction {
    std::uint64_t entry = 0;

    // Sorted by start address. Only blocks reachable from the entry are here:
    // dominators say nothing useful about the rest, so there's no honest way to
    // version them.
    std::vector<SsaBlock> blocks;

    // Registers read at version 0, in the order the renamer first met them. At
    // the top of a function that's the arguments, the stack pointer, and
    // whatever the code reads before writing.
    std::vector<IrOperand> live_in;

    // How many temporaries the lifter handed out, so a later pass adding its own
    // knows where to carry on from.
    unsigned temp_count = 0;

    bool empty() const { return blocks.empty(); }
    std::size_t size() const { return blocks.size(); }

    const SsaBlock* block_at(std::uint64_t address) const;
};

// Lift the CFG and put the result into SSA form.
//
// Phis go where two definitions can meet, which is the dominance frontier and
// nowhere else, so this needs the dominator tree rather than a fixed point over
// the whole graph. Placement is the usual worklist: a block defining a register
// forces a phi across its frontier, and each phi it plants is itself a
// definition that has to be pushed across its own.
//
// Renaming then walks the dominator tree with a version stack per register. The
// tree is what makes one walk enough -- a block's dominator is the last place a
// value could have come from, so by the time we get there the stack already
// holds it.
SsaFunction build_ssa(const CFG& cfg);

}  // namespace minidec

#endif  // MINIDEC_SSA_H
