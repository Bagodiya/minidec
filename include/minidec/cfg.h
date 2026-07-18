#ifndef MINIDEC_CFG_H
#define MINIDEC_CFG_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "minidec/disasm.h"

namespace minidec {

// A straight-line run of instructions with one way in and one way out. Once you
// enter a block at its first instruction you always run every instruction in it
// and leave from the last one; the only branching happens on the way out. That's
// the whole point of splitting a function up this way before we try to recover
// its control flow.
//
// The instructions are copied in rather than pointed at so a block owns its own
// listing and doesn't go stale if the original vector gets moved around. For the
// function sizes minidec deals with that copy is cheap enough not to worry about.
struct BasicBlock {
    std::uint64_t start = 0;  // address of the first instruction
    std::uint64_t end = 0;    // address just past the last instruction (exclusive)
    std::vector<Instruction> instructions;

    // Addresses of the blocks control can flow to from here. A plain jmp has one,
    // a conditional branch has two (taken + fall-through), a ret has none, and a
    // block that just falls off the end into the next one has that one. We store
    // addresses instead of pointers so the list survives the block vector being
    // resized while it's still being built.
    std::vector<std::uint64_t> successors;

    // Handy shorthands used while grouping and wiring things up.
    bool empty() const { return instructions.empty(); }

    // The instruction that decides where we go next, i.e. the last one in the
    // block. Only call this when the block actually has something in it.
    const Instruction& terminator() const { return instructions.back(); }
};

// The control-flow graph of a single function: every basic block plus the entry
// point to start from. Blocks are kept sorted by start address so we can find
// the one covering a given address with a binary search later on. The CFG owns
// all of its blocks.
struct CFG {
    std::uint64_t entry = 0;  // start address of the first block
    std::vector<BasicBlock> blocks;

    bool empty() const { return blocks.empty(); }
    std::size_t size() const { return blocks.size(); }

    // Look up the block that begins at exactly this address, or nullptr if no
    // block starts there. Successor addresses always point at block starts, so
    // this is what you use to walk from one block to the next.
    const BasicBlock* block_at(std::uint64_t address) const {
        for (const auto& block : blocks) {
            if (block.start == address) {
                return &block;
            }
        }
        return nullptr;
    }
};

// Work out which instructions start a basic block. A leader is any instruction
// you might land on out of the ordinary top-to-bottom flow, and there are three
// ways that happens: the function's first instruction, the target an in-range
// jump points at, and whatever comes right after something that ends a block
// (a jump or a ret). The next step groups the instructions up by cutting at
// these addresses, so this is really just finding the cut points.
//
// The returned addresses are sorted and de-duplicated, and only ever name a real
// instruction in the list -- jump targets that land outside the function (or that
// we can't read off a direct operand) are left out since they don't split any
// block we're building here.
std::vector<std::uint64_t> find_block_leaders(const std::vector<Instruction>& instructions);

// Cut the instruction list into basic blocks at the leader addresses. Each block
// runs from one leader up to (but not including) the next one, so every leader
// starts exactly one block and the instructions in between all belong to it. The
// blocks come back in the same order the instructions were in, which is sorted by
// address, and each one has its start, end, and instruction list filled in.
//
// Successors are left empty on purpose -- wiring the edges between blocks is the
// next step. This one only worries about where each block begins and ends.
std::vector<BasicBlock> group_into_blocks(const std::vector<Instruction>& instructions);

// Fill in each block's successor list now that we know where every block starts
// and ends. group_into_blocks lays the blocks out in order but leaves them with no
// edges, so here we look at what instruction each block ends on to decide where
// control goes next:
//
//   - ends on a ret        -> nowhere, the function returns (no successors)
//   - ends on a plain jmp  -> just the block it jumps to
//   - ends on a jcc        -> two of them: the branch target and the fall-through
//   - anything else         -> falls straight into the block that comes after it
//
// A jump whose target we can't pin down (an indirect "jmp rax", or a target that
// lands outside the function) gets no edge for that side, since there's no block
// of ours to point it at. The blocks are edited in place.
void connect_blocks(std::vector<BasicBlock>& blocks);

}  // namespace minidec

#endif  // MINIDEC_CFG_H
