#ifndef MINIDEC_VARNAME_H
#define MINIDEC_VARNAME_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "minidec/params.h"
#include "minidec/regvar.h"
#include "minidec/stack.h"

namespace minidec {

// Names for the variables the earlier passes found.
//
// Each of those passes describes a variable by where it lives: eight bytes at
// rbp-0x14, the versions of rax that a phi ties together, the third argument
// register. None of that can appear in output meant to read as C, so somewhere
// between recovery and printing the addresses and versions have to turn into
// names, and this is that step and nothing more. No new analysis happens here.
//
// The one real requirement is that the names hold still. A slot named var_2
// today has to be var_2 tomorrow, and adding a variable at the top of the frame
// must not renumber everything below it any more than it has to -- otherwise two
// runs over the same binary produce listings that can't be diffed. That rules
// out numbering in discovery order, since the passes discover through hash
// tables. The lists they hand back are all sorted already, so the order they are
// in is the order used here.
//
// Parameters are named apart from the locals. Which argument a value arrived as
// is worth keeping in the name, and a reader who sees arg_1 knows not to look
// for where it was set.
//
// A parameter also turns up in the register pass, as version 0 of the register
// it came in. Naming it twice would print one value under two names, so those
// versions are folded onto the parameter's name instead of getting their own.
// Nothing else is merged: overlapping stack slots stay separate for the reason
// given in stack.h, and a variable the compiler kept partly in the frame and
// partly in a register gets a name for each half. Deciding those are the same
// variable needs evidence this pass doesn't have.

enum class VarKind {
    parameter, // arrived in a register the caller filled in
    stack,     // a slot in the frame
    reg,       // versions of a register, joined by phis
};

const char* var_kind_name(VarKind kind);

// One named variable.
//
// The fields that say where it lives depend on the kind: a stack slot has a base
// and an offset, everything else has a register and the versions of it the name
// covers.
struct NamedVar {
    std::string name;
    VarKind kind = VarKind::stack;

    // Position within the kind, so arg_1 has index 1. Locals share one sequence
    // across the two kinds, since a listing with two var_0 in it would be worse
    // than useless.
    unsigned index = 0;

    // Widest access seen, in bits. Zero for a parameter nothing reads, which is
    // the only case where there is nothing to measure.
    unsigned width = 0;

    std::string reg;                // 64-bit name; empty for a stack slot
    std::vector<unsigned> versions; // ascending

    std::int64_t offset = 0; // stack only, and negative below the base
    std::string base;
    unsigned base_version = 0;
};

struct NameTable {
    // Parameters first, then the stack slots, then the registers, each in the
    // order the pass that found them gave.
    std::vector<NamedVar> vars;

    bool empty() const { return vars.empty(); }
    std::size_t size() const { return vars.size(); }

    const NamedVar* find(const std::string& name) const;

    // The slot at an offset from a given frame base, or nullptr.
    const NamedVar* stack_slot(const std::string& base, unsigned base_version,
                               std::int64_t offset) const;

    // The variable holding a register version, or nullptr. `reg` may be spelled
    // at any width.
    const NamedVar* value(const std::string& reg, unsigned version) const;
};

// Name everything the three recovery passes turned up.
NameTable name_variables(const ParamList& params, const StackFrame& frame, const RegVars& regs);

} // namespace minidec

#endif // MINIDEC_VARNAME_H
