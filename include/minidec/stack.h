#ifndef MINIDEC_STACK_H
#define MINIDEC_STACK_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "minidec/ssa.h"

namespace minidec {

// The slots a function keeps its locals in.
//
// After lifting there is nothing left called a variable: a local is a run of
// bytes somewhere below the frame base, reached by an address the lifter built
// out of adds. This walks those adds back to the register they started from, so
// every load and store that lands in the frame can be filed under the slot it
// touches.
//
// Two things stop it being a matter of reading displacements off the operands.
// The address arithmetic is spread over several operations by the time we see
// it, and the frame base isn't always rsp -- a function that sets up rbp does
// all its work off that instead, and one compiled without a frame pointer moves
// rsp around mid-function and addresses off whatever it currently holds.
//
// Both fall out of tracking values rather than registers, which is what SSA is
// for: rsp before and after a "sub rsp, 0x20" are separate values there, so an
// offset from one is never mistaken for an offset from the other.

// One instruction touching a slot.
struct StackAccess {
    std::uint64_t address = 0; // the machine instruction doing it
    unsigned size = 0;         // bytes it reads or writes
    bool is_write = false;
};

// A slot: somewhere in the frame that gets used as one unit.
//
// `base` and `base_version` name the value the offset is measured from, which is
// a value and not just a register. Both are needed -- "rsp" on its own would put
// the slots of a function that adjusts its stack pointer into one pile with the
// offsets meaning different things.
//
// A frame that ends up with more than one base is a function we couldn't tie
// together, usually because the instruction that linked them isn't lifted yet.
// Better to say so than to pick one and quietly rebase the rest onto it.
struct StackVar {
    std::string base;
    unsigned base_version = 0;
    std::int64_t offset = 0; // negative below the base, which is where locals live

    // The widest access seen, since a 4-byte local can still be read a byte at a
    // time. Overlapping slots stay separate: two offsets four bytes apart is
    // equally an int array and a pair of ints, and nothing here can tell.
    unsigned size = 0;

    std::vector<StackAccess> accesses; // by rising address

    bool is_read() const;
    bool is_written() const;
};

struct StackFrame {
    // Sorted by base, then version, then offset, so the same function always
    // gives the same list.
    std::vector<StackVar> vars;

    // Loads and stores whose address didn't come back to a base register. Globals
    // and pointer chasing account for most of them; a high count next to few
    // slots means the frame is bigger than what's listed here.
    std::size_t untracked = 0;

    bool empty() const { return vars.empty(); }
    std::size_t size() const { return vars.size(); }

    // The first slot at this offset, or nullptr. Only unambiguous while the
    // frame has a single base, which is the usual case.
    const StackVar* var_at(std::int64_t offset) const;
};

// Every stack slot the function uses.
//
// Nothing here is a guess about what the source said. A slot means bytes at a
// fixed spot in the frame that something reads or writes, so a local the
// compiler kept in a register the whole way through doesn't appear -- that's
// what the next pass is for.
StackFrame find_stack_variables(const SsaFunction& fn);

} // namespace minidec

#endif // MINIDEC_STACK_H
