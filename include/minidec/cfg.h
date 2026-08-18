#ifndef MINIDEC_CFG_H
#define MINIDEC_CFG_H

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "minidec/disasm.h"

namespace minidec {

// A straight-line run of instructions: enter at the first, leave from the last,
// no branching in between.
//
// Instructions are copied rather than pointed at so a block stays valid if the
// original vector moves. Cheap enough at the function sizes we deal with.
struct BasicBlock {
    std::uint64_t start = 0;  // address of the first instruction
    std::uint64_t end = 0;    // address just past the last instruction (exclusive)
    std::vector<Instruction> instructions;

    // Where control can go from here, as addresses rather than pointers so the
    // list survives the block vector being resized while it's still being built.
    std::vector<std::uint64_t> successors;

    bool empty() const { return instructions.empty(); }

    // The instruction that decides where we go next. Only valid on a non-empty
    // block.
    const Instruction& terminator() const { return instructions.back(); }
};

// One function's control-flow graph. Blocks stay sorted by start address.
struct CFG {
    std::uint64_t entry = 0;
    std::vector<BasicBlock> blocks;

    bool empty() const { return blocks.empty(); }
    std::size_t size() const { return blocks.size(); }

    // The block beginning at exactly this address, or nullptr. Successors always
    // name a block start, so this is how you walk an edge.
    const BasicBlock* block_at(std::uint64_t address) const {
        for (const auto& block : blocks) {
            if (block.start == address) {
                return &block;
            }
        }
        return nullptr;
    }
};

// Addresses that start a basic block: the first instruction, any in-range jump
// target, and whatever follows a jump or ret.
//
// Sorted and de-duplicated. Targets that land outside the function are left out,
// since they don't split anything we're building.
std::vector<std::uint64_t> find_block_leaders(const std::vector<Instruction>& instructions);

// Cut the instruction list at the leaders. Successors are left empty; that's
// connect_blocks' job.
std::vector<BasicBlock> group_into_blocks(const std::vector<Instruction>& instructions);

// Fill in each block's successors from what it ends on:
//
//   ret        -> none, control leaves the function
//   jmp        -> the block it jumps to
//   jcc        -> the target and the fall-through
//   anything   -> falls into the block that starts where this one ends
//
// A target we can't pin down (indirect jump, or outside the function) gets no
// edge, since there's no block of ours to point at.
void connect_blocks(std::vector<BasicBlock>& blocks);

// Dominator sets keyed by block start address, each including the block itself.
using DominatorSets = std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>>;

// A dominates B when you can't reach B from the entry without passing A first.
//
// Iterative version: assume everything dominates everything, then keep applying
//
//     dom(b) = {b} + intersection of dom(p) over b's predecessors
//
// until it settles. Sets only shrink, so it terminates.
//
// Unreachable blocks come back dominated by everything, which is what falls out
// of intersecting no predecessors and keeps them from dragging real answers down.
DominatorSets compute_dominators(const CFG& cfg);

// Each block's parent in the dominator tree: the one block that dominates it and
// is itself dominated by all its other dominators, so it's the closest of them.
//
// Keyed by block start. The entry isn't in the map -- nothing dominates it but
// itself -- and neither is anything unreachable, whose dominator set is a
// leftover rather than an answer.
using ImmediateDominators = std::unordered_map<std::uint64_t, std::uint64_t>;

ImmediateDominators compute_immediate_dominators(const CFG& cfg, const DominatorSets& dominators);

// Where a block's control stops being the only way in. D is in the frontier of B
// when B dominates one of D's predecessors but not D itself -- so B's values
// reach D down one edge and something else reaches it down another.
//
// That's exactly where two definitions meet, which is why SSA puts its phis
// here and nowhere else.
using DominanceFrontiers = std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>>;

// Walked the cheap way rather than by comparing dominator sets: for a block with
// more than one predecessor, climb the dominator tree from each predecessor up
// to the block's immediate dominator, adding the block to everything passed on
// the way. Blocks with one predecessor are skipped because the climb from it
// stops immediately.
DominanceFrontiers compute_dominance_frontiers(const CFG& cfg, const ImmediateDominators& idom);

// A loop found from a back edge. Nested loops come back separately, and two
// latches jumping to the same header give two entries.
struct NaturalLoop {
    std::uint64_t header = 0;  // the block the back edge points at
    std::uint64_t latch = 0;   // the block the back edge comes from
    std::unordered_set<std::uint64_t> body;

    bool contains(std::uint64_t address) const { return body.count(address) != 0; }
    std::size_t size() const { return body.size(); }
};

// Every natural loop in the function.
//
// A loop shows up as an edge B -> A where A already dominates B: the only way to
// reach B was through A, so jumping back to A runs the same code again. The body
// is everything that reaches B without leaving through A, found by walking
// predecessors back from B and stopping at A.
//
// Unreachable blocks are skipped -- they're dominated by everything, so every
// edge out of one would look like a back edge.
//
// Ordered by latch address, so the same function always gives the same list.
std::vector<NaturalLoop> find_natural_loops(const CFG& cfg, const DominatorSets& dominators);

// Block start addresses in reverse postorder: every block comes after all its
// predecessors except those reaching it by a back edge. That's what lets a
// forward dataflow pass see real answers for its inputs on the first sweep
// instead of iterating over placeholders. Address order gives no such guarantee.
//
// Only blocks reachable from the entry are included, so "not in this list" means
// "not worth analysing".
std::vector<std::uint64_t> compute_reverse_postorder(const CFG& cfg);

}  // namespace minidec

#endif  // MINIDEC_CFG_H
