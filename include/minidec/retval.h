#ifndef MINIDEC_RETVAL_H
#define MINIDEC_RETVAL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "minidec/ir.h"
#include "minidec/ssa.h"

namespace minidec {

// What the function hands back.
//
// The mirror of the parameter pass, and harder for one reason: there is no
// ordering to lean on. Arguments arrive in six registers filled in sequence, so
// a read of r8 proves five more went past. A result comes back in rax and that
// is the end of the convention, so the only question is whether the value in
// there at the ret was put there on purpose.
//
// The lifter is no help by itself. It writes rax into every ret it emits,
// because a discarded result is cheaper to live with than a lost one, which
// means a void function and an int function produce exactly the same ret. So the
// answer has to come from the other side: what wrote the version the ret reads.
//
// Four things can have, and they say different amounts:
//
//   - nothing at all, which is version 0. The function never touched rax, so
//     whatever is in there belongs to the caller and this returns void.
//   - an ordinary instruction here. That is a real result, and its width is the
//     nearest thing to a declared return type -- a function that only ever
//     writes eax returns 32 bits.
//   - a call. Either the result is being forwarded, or this is a void function
//     that happened to call something last. Both look the same from here, so it
//     is reported as its own case rather than guessed at.
//   - a clobber, which only comes from an instruction the lifter couldn't model.
//     No claim either way.
//
// Phis are walked through. A value set differently down each arm of an if is
// still one result, and the join is where the two versions meet, so resolving
// stops at the writes behind the phi rather than at the phi itself.
//
// xmm0 is where a float or a double comes back. Nothing produces one yet -- the
// lifter has no xmm registers -- so a function returning a double reads here as
// returning nothing. The register is named anyway so that the pass doesn't need
// changing when the lifter grows them.

// Where the value at a ret came from.
enum class ReturnSource {
    entry,   // nothing in this function ever wrote it
    written, // an instruction here put it there
    call,    // a call left it, and nothing since has touched it
    clobber, // an unmodelled instruction left it
};

const char* return_source_name(ReturnSource source);

// One ret.
struct ReturnSite {
    std::uint64_t block = 0;   // block the ret is in
    std::size_t inst = 0;      // index into SsaBlock::code
    std::uint64_t address = 0; // machine instruction behind it

    std::string reg;      // the register it reads, 64-bit name
    unsigned version = 0; // 0 when the function never wrote it

    // Width of the write behind this site, in bits. Zero unless the source is a
    // real write, since a call's rax and a phi's rax are both i64 by
    // construction and neither says anything about the source type.
    unsigned width = 0;

    ReturnSource source = ReturnSource::entry;

    // The version arrived through at least one join, so more than one write can
    // be responsible for it.
    bool through_phi = false;
};

struct ReturnValue {
    // The register the result comes back in, or empty when nothing was returned.
    std::string reg;

    // Widest write reaching any ret. Zero for a function that returns nothing,
    // and also for one that only forwards a call, where there is no write of
    // ours to measure.
    unsigned width = 0;

    bool floating = false; // came back in xmm0 rather than rax

    std::vector<ReturnSite> sites; // in block order, then instruction order

    // No ret anywhere: an endless loop, a tail call, or a function that wasn't
    // lifted.
    bool empty() const { return sites.empty(); }
    std::size_t size() const { return sites.size(); }

    // Something in this function deliberately set the result.
    bool returns_value() const;

    // No write of our own, but a call's result was sitting in the register. See
    // the note above -- forwarding and void are indistinguishable here.
    bool forwards_call() const;

    // Every ret agrees about where the value came from. A function with one ret,
    // which is most of them at -O0, trivially does.
    bool consistent() const;
};

// Recover the return value of one function.
ReturnValue recover_return_value(const SsaFunction& fn);

} // namespace minidec

#endif // MINIDEC_RETVAL_H
