#include "minidec/cfg.h"

#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <optional>
#include <unordered_set>

namespace minidec {

namespace {

// An instruction ends a basic block when it hands control somewhere other than
// the very next instruction, i.e. a jump or a ret. We deliberately don't count
// a call here: a call comes back to the instruction right after it, so as far as
// the intra-function control flow goes the block just keeps running past it.
bool ends_block(const Instruction& insn) {
    return insn.is_jump || insn.is_ret;
}

// Pull the destination address out of a direct jump. Capstone writes it into the
// operand text as a plain number (e.g. "0x1140"), so for a pc-relative jump we
// can just read it back. Indirect jumps (jmp rax, jmp [rip+..]) don't carry an
// address we can follow statically, so they come back as no target. Same strtoull
// trick cmd_disasm uses to resolve call names -- if it doesn't eat the whole
// string it wasn't a bare address and we don't trust it.
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

}  // namespace

std::vector<std::uint64_t> find_block_leaders(const std::vector<Instruction>& instructions) {
    std::vector<std::uint64_t> leaders;
    if (instructions.empty()) {
        return leaders;
    }

    // Every jump target has to point at an instruction we actually decoded for it
    // to split a block, so keep the real addresses around to check against. A
    // target that lands mid-instruction or outside the function isn't a leader we
    // can do anything with.
    std::unordered_set<std::uint64_t> known;
    known.reserve(instructions.size());
    for (const Instruction& insn : instructions) {
        known.insert(insn.address);
    }

    // Collect into a set first so the three rules can add the same address without
    // us having to worry about duplicates; we sort it into a plain vector at the end.
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

        // Rule 3: once a block ends, the next instruction begins a fresh one. That
        // covers the fall-through side of a conditional jump and the dead-drop
        // after an unconditional jump or a ret alike.
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

    // find_block_leaders already gives us every address that has to start a block,
    // including the instruction right after each jump/ret, so a leader is the only
    // place we ever need to make a cut. Drop them into a set for quick lookups.
    std::vector<std::uint64_t> leaders = find_block_leaders(instructions);
    std::unordered_set<std::uint64_t> is_leader(leaders.begin(), leaders.end());

    BasicBlock current;
    for (const Instruction& insn : instructions) {
        // Hitting a leader means the previous block is done. Push what we've got
        // and start collecting a new one from here. The very first instruction is
        // a leader too, but current is still empty then so there's nothing to push.
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
    // Every edge we add has to name the start of a real block, so collect the set
    // of block-start addresses up front and check each candidate target against it.
    // A jump that lands anywhere else (outside the function, mid-instruction) just
    // doesn't get an edge -- we've got nothing of ours to point it at.
    std::unordered_set<std::uint64_t> block_starts;
    block_starts.reserve(blocks.size());
    for (const BasicBlock& block : blocks) {
        block_starts.insert(block.start);
    }

    // Because the blocks are contiguous, a block's end address is exactly where the
    // next block begins, so block.end is the fall-through target whenever there is
    // one. The last block of the function ends past the final instruction and no
    // block starts there, which is how "falls off the end" comes out with no edge.
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
            // "jmp" is the only unconditional jump; everything else that's a jump
            // is a jcc, which also carries on to the next block when the condition
            // comes out false, so it picks up the fall-through edge as well.
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

        // No branch at the tail at all: this block was cut short only because the
        // instruction after it is a leader (something jumps there). Control runs
        // straight on into whatever block starts where this one ends.
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

    // The edges we have run forwards (each block lists where it goes), but the
    // dominator rule needs them the other way round, so flip them once up front.
    // Successor addresses always name a block start, so nothing here can miss.
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> predecessors;
    std::unordered_set<std::uint64_t> everything;
    everything.reserve(cfg.size());
    for (const BasicBlock& block : cfg.blocks) {
        everything.insert(block.start);
    }
    for (const BasicBlock& block : cfg.blocks) {
        for (std::uint64_t succ : block.successors) {
            predecessors[succ].push_back(block.start);
        }
    }

    // Start pessimistic: every block is dominated by every block. The entry is the
    // exception -- nothing comes before it, so only it dominates it, and that's the
    // fixed point the rest of the sets get whittled down from.
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

            // Intersect the predecessors' sets by starting from the first one and
            // dropping anything the rest don't also have.
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

}  // namespace minidec
