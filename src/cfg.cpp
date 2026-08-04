#include "minidec/cfg.h"

#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <optional>
#include <unordered_set>

namespace minidec {

namespace {

// A jump or a ret. Not a call -- that comes back to the next instruction, so the
// block keeps running past it.
bool ends_block(const Instruction& insn) {
    return insn.is_jump || insn.is_ret;
}

// Capstone writes a direct jump's destination as a plain number, so read it back.
// Indirect jumps have no static target and come back as nothing. If strtoull
// doesn't eat the whole string it wasn't an address and we don't trust it.
std::optional<std::uint64_t> jump_target(const Instruction& insn) {
    if (!insn.is_jump || !insn.is_relative) {
        return std::nullopt;
    }

    const char* start = insn.op_str.c_str();
    char* stop = nullptr;
    std::uint64_t target = std::strtoull(start, &stop, 0);
    if (stop == start || *stop != '\0') {
        return std::nullopt;
    }
    return target;
}

// Blocks only record where they go, but the dominator pass and the loop-body walk
// both need the reverse. Successors always name a block start, so the keys line up.
std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> build_predecessors(const CFG& cfg) {
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> predecessors;
    for (const BasicBlock& block : cfg.blocks) {
        for (std::uint64_t succ : block.successors) {
            predecessors[succ].push_back(block.start);
        }
    }
    return predecessors;
}

// What's reachable from the entry. Dead blocks are real -- padding, tails the
// compiler proved unreachable -- and dominators give them a meaningless answer.
std::unordered_set<std::uint64_t> reachable_blocks(const CFG& cfg) {
    std::unordered_set<std::uint64_t> seen;
    if (cfg.empty() || cfg.block_at(cfg.entry) == nullptr) {
        return seen;
    }

    std::vector<std::uint64_t> worklist{cfg.entry};
    seen.insert(cfg.entry);
    while (!worklist.empty()) {
        std::uint64_t current = worklist.back();
        worklist.pop_back();

        const BasicBlock* block = cfg.block_at(current);
        if (block == nullptr) {
            continue;
        }
        for (std::uint64_t succ : block->successors) {
            if (seen.insert(succ).second) {
                worklist.push_back(succ);
            }
        }
    }
    return seen;
}

}  // namespace

std::vector<std::uint64_t> find_block_leaders(const std::vector<Instruction>& instructions) {
    std::vector<std::uint64_t> leaders;
    if (instructions.empty()) {
        return leaders;
    }

    // A target only splits a block if it names an instruction we decoded. One
    // landing mid-instruction or outside the function is no use to us.
    std::unordered_set<std::uint64_t> known;
    known.reserve(instructions.size());
    for (const Instruction& insn : instructions) {
        known.insert(insn.address);
    }

    // A set first, so the three rules can overlap without producing duplicates.
    std::unordered_set<std::uint64_t> found;

    // Rule 1: you always enter the function at its first instruction.
    found.insert(instructions.front().address);

    for (std::size_t i = 0; i < instructions.size(); ++i) {
        const Instruction& insn = instructions[i];

        // Rule 2: wherever a jump can send us is the start of a block, as long as
        // it's one of our own instructions.
        if (auto target = jump_target(insn)) {
            if (known.count(*target)) {
                found.insert(*target);
            }
        }

        // Rule 3: whatever follows a block-ender starts a new one. Covers both the
        // fall-through of a jcc and the dead drop after a jmp or ret.
        if (ends_block(insn) && i + 1 < instructions.size()) {
            found.insert(instructions[i + 1].address);
        }
    }

    leaders.assign(found.begin(), found.end());
    std::sort(leaders.begin(), leaders.end());
    return leaders;
}

std::vector<BasicBlock> group_into_blocks(const std::vector<Instruction>& instructions) {
    std::vector<BasicBlock> blocks;
    if (instructions.empty()) {
        return blocks;
    }

    // Leaders are the only places we ever cut, so a set for quick lookups.
    std::vector<std::uint64_t> leaders = find_block_leaders(instructions);
    std::unordered_set<std::uint64_t> is_leader(leaders.begin(), leaders.end());

    BasicBlock current;
    for (const Instruction& insn : instructions) {
        // A leader ends the previous block. The first instruction is a leader too,
        // but current is empty then so there's nothing to push.
        if (is_leader.count(insn.address) && !current.empty()) {
            blocks.push_back(std::move(current));
            current = BasicBlock{};
        }

        if (current.empty()) {
            current.start = insn.address;
        }
        current.instructions.push_back(insn);
        current.end = insn.address + insn.size;
    }

    // Whatever we were building when the instructions ran out is the last block.
    if (!current.empty()) {
        blocks.push_back(std::move(current));
    }

    return blocks;
}

void connect_blocks(std::vector<BasicBlock>& blocks) {
    // Every edge has to name a real block start, so check each target against this.
    // Anything landing elsewhere gets no edge.
    std::unordered_set<std::uint64_t> block_starts;
    block_starts.reserve(blocks.size());
    for (const BasicBlock& block : blocks) {
        block_starts.insert(block.start);
    }

    // Blocks are contiguous, so block.end is the fall-through target. The last one
    // ends past the final instruction where no block starts, which is how "falls off
    // the end" comes out with no edge.
    for (BasicBlock& block : blocks) {
        if (block.empty()) {
            continue;
        }

        const Instruction& term = block.terminator();

        // A ret hands control back to the caller, not to another block here.
        if (term.is_ret) {
            continue;
        }

        if (term.is_jump) {
            // jmp is the only unconditional one; a jcc also falls through.
            bool conditional = term.mnemonic != "jmp";

            if (auto target = jump_target(term)) {
                if (block_starts.count(*target)) {
                    block.successors.push_back(*target);
                }
            }

            if (conditional && block_starts.count(block.end)) {
                block.successors.push_back(block.end);
            }
            continue;
        }

        // No branch at the tail: cut short only because something jumps to the next
        // instruction. Control runs straight on.
        if (block_starts.count(block.end)) {
            block.successors.push_back(block.end);
        }
    }
}

DominatorSets compute_dominators(const CFG& cfg) {
    DominatorSets dominators;
    if (cfg.empty()) {
        return dominators;
    }

    // The dominator rule reads the edges backwards, so get the reverse map first.
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> predecessors =
        build_predecessors(cfg);

    std::unordered_set<std::uint64_t> everything;
    everything.reserve(cfg.size());
    for (const BasicBlock& block : cfg.blocks) {
        everything.insert(block.start);
    }

    // Start pessimistic and whittle down. The entry is the exception: nothing comes
    // before it, so only it dominates it.
    for (const BasicBlock& block : cfg.blocks) {
        dominators[block.start] = everything;
    }
    dominators[cfg.entry] = {cfg.entry};

    bool changed = true;
    while (changed) {
        changed = false;

        for (const BasicBlock& block : cfg.blocks) {
            if (block.start == cfg.entry) {
                continue;
            }

            auto preds = predecessors.find(block.start);
            if (preds == predecessors.end()) {
                continue;  // unreachable, leave it dominated by everything
            }

            // Intersect: start from the first predecessor, drop what the rest lack.
            std::unordered_set<std::uint64_t> updated = dominators[preds->second.front()];
            for (std::size_t i = 1; i < preds->second.size(); ++i) {
                const std::unordered_set<std::uint64_t>& other = dominators[preds->second[i]];
                for (auto it = updated.begin(); it != updated.end();) {
                    it = other.count(*it) ? std::next(it) : updated.erase(it);
                }
            }
            updated.insert(block.start);

            if (updated != dominators[block.start]) {
                dominators[block.start] = std::move(updated);
                changed = true;
            }
        }
    }

    return dominators;
}

std::vector<NaturalLoop> find_natural_loops(const CFG& cfg, const DominatorSets& dominators) {
    std::vector<NaturalLoop> loops;
    if (cfg.empty()) {
        return loops;
    }

    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> predecessors =
        build_predecessors(cfg);
    std::unordered_set<std::uint64_t> reachable = reachable_blocks(cfg);

    // Blocks are sorted by address, which is what makes the list deterministic.
    for (const BasicBlock& block : cfg.blocks) {
        if (!reachable.count(block.start)) {
            continue;
        }

        auto doms = dominators.find(block.start);
        if (doms == dominators.end()) {
            continue;
        }

        for (std::uint64_t succ : block.successors) {
            // The whole test. A block dominates itself, so a one-block loop falls
            // out without a special case.
            if (!doms->second.count(succ)) {
                continue;
            }

            NaturalLoop loop;
            loop.header = succ;
            loop.latch = block.start;

            // Seed with the header first. The walk only adds unseen blocks, so this
            // is what stops it climbing past the top of the loop.
            loop.body.insert(loop.header);

            std::vector<std::uint64_t> worklist;
            if (loop.body.insert(loop.latch).second) {
                worklist.push_back(loop.latch);
            }

            // Anything reaching the latch without passing the header is inside.
            while (!worklist.empty()) {
                std::uint64_t current = worklist.back();
                worklist.pop_back();

                auto preds = predecessors.find(current);
                if (preds == predecessors.end()) {
                    continue;
                }
                for (std::uint64_t pred : preds->second) {
                    if (loop.body.insert(pred).second) {
                        worklist.push_back(pred);
                    }
                }
            }

            loops.push_back(std::move(loop));
        }
    }

    return loops;
}

std::vector<std::uint64_t> compute_reverse_postorder(const CFG& cfg) {
    std::vector<std::uint64_t> order;
    if (cfg.empty() || cfg.block_at(cfg.entry) == nullptr) {
        return order;
    }

    // Explicit stack rather than recursion. A frame remembers which successor it
    // was up to, and the block is recorded once that counter runs off the end.
    struct Frame {
        std::uint64_t block = 0;
        std::size_t next_successor = 0;
    };

    std::unordered_set<std::uint64_t> visited;
    std::vector<Frame> stack;

    visited.insert(cfg.entry);
    stack.push_back(Frame{cfg.entry, 0});

    while (!stack.empty()) {
        Frame& frame = stack.back();
        const BasicBlock* block = cfg.block_at(frame.block);

        if (block != nullptr && frame.next_successor < block->successors.size()) {
            std::uint64_t succ = block->successors[frame.next_successor];
            ++frame.next_successor;

            // Mark on the way in: a loop means meeting the header again from inside
            // the body. The push invalidates `frame`, so we're done with it here.
            if (visited.insert(succ).second && cfg.block_at(succ) != nullptr) {
                stack.push_back(Frame{succ, 0});
            }
            continue;
        }

        // Out of successors, so everything below is recorded and it's this one's
        // turn. Reversed at the end.
        order.push_back(frame.block);
        stack.pop_back();
    }

    std::reverse(order.begin(), order.end());
    return order;
}

}  // namespace minidec
