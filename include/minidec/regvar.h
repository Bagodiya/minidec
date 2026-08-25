#ifndef MINIDEC_REGVAR_H
#define MINIDEC_REGVAR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "minidec/ir.h"
#include "minidec/ssa.h"

namespace minidec {

// The locals the compiler never gave a stack slot.
//
// The stack pass finds the ones that live in the frame, which at -O0 is nearly
// all of them. Anything built with optimisation on keeps its hot values in
// registers instead, and those have to be found a different way: there is no
// address to key on, only a value that gets written once and read a few
// instructions later.
//
// SSA already names those values -- one version per write -- but a version is
// not a variable. A counter incremented round a loop is one variable in the
// source and one version per trip through the header here, tied together by the
// phi at the top. So the variable is the whole set of versions a chain of phis
// joins up, and that set is what this pass builds.
//
// The other half is the live range: where in the function the variable holds
// something worth reading. That falls out of ordinary backward liveness, with
// the one wrinkle every SSA liveness has -- a phi argument is live at the end of
// the predecessor it came down from, not at the top of the block the phi is in.

// One write. Phis and clobbers both count, since both leave a version behind
// that a later read can see.
struct RegDef {
    std::uint64_t block = 0;   // block this happens in
    std::size_t inst = 0;      // index into SsaBlock::code; 0 for a phi
    std::uint64_t address = 0; // machine instruction behind it, 0 for a phi
    unsigned version = 0;

    bool is_phi = false; // a join rather than a real write

    // A call or an unmodelled instruction left this version behind without
    // saying so. Reading one is reading whatever the callee happened to leave,
    // so a variable with nothing but clobbers behind it is one the function
    // never really set. Flagged rather than dropped -- which of those are worth
    // anything is the next pass's call, not this one's.
    bool is_clobber = false;
};

// One read, by a real instruction.
//
// Phi arguments are left out on purpose. A phi reads versions of the variable it
// writes, so after the versions are merged its arguments are the variable
// reading itself, which says nothing about where the value is wanted.
struct RegUse {
    std::uint64_t block = 0;
    std::size_t inst = 0; // index into SsaBlock::code
    std::size_t arg = 0;  // which argument of that instruction
    std::uint64_t address = 0;
    unsigned version = 0;
};

// The stretch of one block the variable is live across.
//
// `begin` and `end` are indices into SsaBlock::code, end exclusive, so a
// variable written at 3 and last read at 7 spans [3, 8). A variable that arrives
// live starts at 0 and one that leaves live ends at code.size(), which is what
// `enters` and `leaves` say -- they are worth keeping separately because a phi
// also starts its span at 0 without anything having flowed in.
//
// One span per block, even where the variable is written, dies, and is written
// again inside that block. Splitting those would need the hole to mean
// something to a caller, and nothing downstream is asking yet.
struct LiveSpan {
    std::uint64_t block = 0;
    std::size_t begin = 0;
    std::size_t end = 0;

    bool enters = false; // live on the way into the block
    bool leaves = false; // still live on the way out

    bool empty() const { return begin >= end; }
};

// One variable: every version of a register that the phis tie together.
struct RegVar {
    std::string reg; // the 64-bit name, so eax and al both read as rax

    std::vector<unsigned> versions; // ascending
    std::vector<RegDef> defs;       // in block order, then instruction order
    std::vector<RegUse> uses;       // likewise
    std::vector<LiveSpan> live;     // by block address

    // The widest access seen. A variable held in eax and read back as al is
    // still 32 bits wide, the same way a stack slot takes its size from the
    // widest thing that touches it.
    unsigned width = 0;

    // Live across a call, which means it survived one. Only the callee-saved
    // registers can manage that -- SSA gives every caller-saved register a fresh
    // version at each call, so a value in one of those never reaches past it.
    bool crosses_call = false;

    // Version 0 is in the set: the value was already there when the function
    // started. Arguments account for most of these, and the rest are
    // callee-saved registers a function reads only to put back before it
    // returns.
    bool from_caller() const;
};

struct RegVars {
    // Sorted by register name, then by first version, so the same function
    // always gives the same list.
    std::vector<RegVar> vars;

    bool empty() const { return vars.empty(); }
    std::size_t size() const { return vars.size(); }

    // The variable a given version belongs to, or nullptr. `reg` may be spelled
    // at any width.
    const RegVar* var_for(const std::string& reg, unsigned version) const;
};

// Every register variable in the function.
//
// Three kinds of register are left out. The flags, because nothing in the source
// was ever kept in one -- they are how the lifter spells the side effects of an
// arithmetic instruction. rsp and rbp, because a function using either as a
// frame base is not keeping a local in it, and telling that apart from a
// function that ran out of registers and used rbp for real needs the stack pass,
// not this one. And rip, which is not storage.
//
// Versions nothing reads are dropped too. A write with no reader is dead code,
// and a variable is what a value is called when something wants it later.
RegVars find_register_variables(const SsaFunction& fn);

} // namespace minidec

#endif // MINIDEC_REGVAR_H
