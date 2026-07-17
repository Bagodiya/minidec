#include "minidec/cfg.h"

#include <algorithm>
#include <cstdlib>
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

}  // namespace minidec
