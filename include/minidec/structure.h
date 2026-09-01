#ifndef MINIDEC_STRUCTURE_H
#define MINIDEC_STRUCTURE_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "minidec/cfg.h"

namespace minidec {

// Turning branches back into if statements.
//
// The CFG knows a block ends in a jcc and that control carries on in two places.
// It has no idea that those two edges came from an `if`, and printing them as
// they stand gives labels and gotos, which is what we're trying to get away
// from. This pass looks for the shape an if compiles into and hands back a
// description an emitter can print without going near the branch again.
//
// The shape is the diamond: one block splits, the arms run, the arms meet.
//
//        head            head
//       /    \          /    \
//    then    else    then     |
//       \    /          \     |
//        join            join
//
// Only arms that are a single block are recognised. A real function has plenty
// that aren't -- an arm with a loop in it, an arm with another if inside -- and
// those need the arms collapsed into regions first, which is a bigger change
// than this step is. What's here covers the small ifs that show up constantly
// and leaves the rest to be printed as branches.
//
// A loop's exit test matches the one-armed shape too, since `jge over the body`
// and `jge past the loop` look the same from one block away. Nothing here can
// tell them apart, so whatever prints the function has to structure loops first
// and only fall back on these regions for the heads a loop didn't claim.
//
// Two things have to hold before a diamond is one of ours. The arm must have
// the head as its only predecessor, otherwise something else jumps into the
// middle of the if and it isn't a statement any more. And the arm has to leave
// where we expect: to the join, or not at all because it returns. An arm ending
// in an indirect jump has neither, so it's left alone.

enum class IfShape {
    then_only, // one arm; the other edge is already the join
    if_else,   // two arms meeting at a join
};

const char* if_shape_name(IfShape shape);

// One recovered if statement.
struct IfRegion {
    std::uint64_t head = 0;      // the block ending in the conditional jump
    std::uint64_t then_body = 0; // the arm that runs when the printed condition holds
    std::uint64_t else_body = 0; // the other arm; zero when the shape is then_only
    std::uint64_t join = 0;      // where control carries on afterwards

    IfShape shape = IfShape::then_only;

    // The jcc is written to skip the body, so nine times out of ten the
    // condition an emitter should print is the opposite of the one the branch
    // tests: `je` over a body means `if (x != 0)`. That inversion isn't
    // something the caller can work out from the mnemonic alone -- it depends
    // on which edge the body sits on -- so it gets recorded here.
    bool negated = false;

    bool has_else() const { return shape == IfShape::if_else; }

    // False when both arms leave the function instead of meeting up, which is
    // what `if (x) return 1; return 0;` looks like from here.
    bool rejoins() const { return join != 0; }
};

// Every if in the function, ordered by head address so two runs over the same
// binary agree.
//
// Regions don't nest, since an arm is a single block. Each head appears once:
// where a diamond could be read either as a one-armed if or as its mirror
// image, the arm on the fall-through wins, because that keeps the printed
// statements in the order the compiler laid the blocks out.
std::vector<IfRegion> find_if_regions(const CFG& cfg);

// The region headed by a given block, or nullptr.
const IfRegion* region_at(const std::vector<IfRegion>& regions, std::uint64_t head);

} // namespace minidec

#endif // MINIDEC_STRUCTURE_H
