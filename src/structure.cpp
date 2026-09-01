#include "minidec/structure.h"

#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace minidec {

namespace {

using PredCounts = std::unordered_map<std::uint64_t, std::size_t>;

// How many edges come into each block. The whole pass turns on "does anything
// else jump in here", and that is all we need to know to answer it.
PredCounts count_predecessors(const CFG& cfg) {
    PredCounts counts;
    counts.reserve(cfg.size());
    for (const BasicBlock& block : cfg.blocks) {
        for (std::uint64_t succ : block.successors) {
            ++counts[succ];
        }
    }
    return counts;
}

std::size_t predecessors_of(const PredCounts& counts, std::uint64_t block) {
    auto it = counts.find(block);
    return it == counts.end() ? 0 : it->second;
}

// A block that splits: it ends in a jump that isn't `jmp`, and both edges made
// it into the graph. A jcc whose target fell outside the function has one edge
// and nothing to structure.
bool splits(const BasicBlock& block) {
    if (block.empty() || block.successors.size() != 2) {
        return false;
    }
    const Instruction& term = block.terminator();
    return term.is_jump && term.mnemonic != "jmp";
}

// A block that runs to its end and hands control back to the caller. Told apart
// from an unresolved jump, which also has no successors but is going somewhere
// we can't see.
bool returns(const BasicBlock& block) {
    return !block.empty() && block.terminator().is_ret;
}

// Could `arm` be the body of an if whose head is `head` and which carries on at
// `other`?
bool is_arm(const CFG& cfg, const PredCounts& counts, std::uint64_t head, std::uint64_t arm,
            std::uint64_t other) {
    if (arm == head || arm == other) {
        return false;
    }

    const BasicBlock* block = cfg.block_at(arm);
    if (block == nullptr || block->empty()) {
        return false;
    }

    // Anything else jumping in makes this a label, not the inside of a
    // statement.
    if (predecessors_of(counts, arm) != 1) {
        return false;
    }

    if (block->successors.empty()) {
        return returns(*block);
    }
    return block->successors.size() == 1 && block->successors.front() == other;
}

} // namespace

const char* if_shape_name(IfShape shape) {
    switch (shape) {
    case IfShape::then_only:
        return "if";
    case IfShape::if_else:
        return "if/else";
    }
    return "?";
}

std::vector<IfRegion> find_if_regions(const CFG& cfg) {
    std::vector<IfRegion> regions;
    if (cfg.empty()) {
        return regions;
    }

    const PredCounts counts = count_predecessors(cfg);

    for (const BasicBlock& block : cfg.blocks) {
        if (!splits(block)) {
            continue;
        }

        // A jcc always drops through to the instruction after it, so of the two
        // edges the one landing at the end of the block is the fall-through and
        // the other is the taken one. Reading them off the successor list by
        // position would work today and break the moment connect_blocks pushes
        // them in the other order.
        const std::uint64_t fallthrough = block.end;
        std::uint64_t taken = 0;
        std::size_t matched = 0;
        for (std::uint64_t succ : block.successors) {
            if (succ == fallthrough) {
                ++matched;
            } else {
                taken = succ;
            }
        }
        if (matched != 1 || taken == 0) {
            // Either the branch jumps to the instruction after itself, so both
            // edges are the same block and nothing is conditional in practice,
            // or the fall-through never became an edge at all.
            continue;
        }

        IfRegion region;
        region.head = block.start;

        const BasicBlock* taken_block = cfg.block_at(taken);
        const BasicBlock* fall_block = cfg.block_at(fallthrough);

        // Neither arm is worth calling an arm unless the head is the only way
        // into it. Checked once here because both of the two-armed shapes below
        // want it.
        const bool private_arms = taken_block != nullptr && fall_block != nullptr &&
                                  taken != fallthrough && predecessors_of(counts, taken) == 1 &&
                                  predecessors_of(counts, fallthrough) == 1;

        // Two arms meeting again. Tested before the one-armed shape, which an
        // if/else also passes on whichever arm gets looked at first.
        if (private_arms && taken_block->successors.size() == 1 &&
            fall_block->successors.size() == 1 &&
            taken_block->successors.front() == fall_block->successors.front()) {
            const std::uint64_t join = taken_block->successors.front();
            if (join != taken && join != fallthrough && join != block.start) {
                region.shape = IfShape::if_else;
                region.then_body = fallthrough;
                region.else_body = taken;
                region.join = join;
                region.negated = true;
                regions.push_back(region);
                continue;
            }
        }

        // Two arms that both leave: `if (x) return 1; else return 2;`. Still an
        // if/else even though there is nothing after it to join at.
        if (private_arms && taken_block->successors.empty() && returns(*taken_block) &&
            fall_block->successors.empty() && returns(*fall_block)) {
            region.shape = IfShape::if_else;
            region.then_body = fallthrough;
            region.else_body = taken;
            region.join = 0;
            region.negated = true;
            regions.push_back(region);
            continue;
        }

        // One arm. The fall-through gets asked first: when both edges would do,
        // taking the one the compiler put immediately after the branch keeps
        // the printed code in the order it was laid out.
        if (is_arm(cfg, counts, block.start, fallthrough, taken)) {
            region.shape = IfShape::then_only;
            region.then_body = fallthrough;
            region.join = taken;
            region.negated = true;
            regions.push_back(region);
            continue;
        }

        if (is_arm(cfg, counts, block.start, taken, fallthrough)) {
            region.shape = IfShape::then_only;
            region.then_body = taken;
            region.join = fallthrough;
            region.negated = false;
            regions.push_back(region);
        }
    }

    // Blocks are already sorted by start address, so this is only insurance
    // against that stopping being true.
    std::sort(regions.begin(), regions.end(),
              [](const IfRegion& a, const IfRegion& b) { return a.head < b.head; });
    return regions;
}

const IfRegion* region_at(const std::vector<IfRegion>& regions, std::uint64_t head) {
    for (const IfRegion& region : regions) {
        if (region.head == head) {
            return &region;
        }
    }
    return nullptr;
}

} // namespace minidec
