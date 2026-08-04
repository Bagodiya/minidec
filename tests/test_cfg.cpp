#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_set>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"

// The CFG passes only read address, size, mnemonic, operand text and branch
// flags, so these build Instructions by hand instead of running bytes through
// capstone. Lets me draw the graph shape I want rather than hunt for an encoding
// that produces it.
//
// Addresses are contiguous because group_into_blocks treats a block's end as the
// next block's start. Sizes are plausible but nothing depends on them.

namespace {

using minidec::BasicBlock;
using minidec::CFG;
using minidec::Instruction;

// Operand text doesn't matter to the CFG; it's there so the shapes read like code.
Instruction plain(std::uint64_t address, std::uint16_t size, std::string mnemonic,
                  std::string operands) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = std::move(mnemonic);
    insn.op_str = std::move(operands);
    return insn;
}

// connect_blocks tells conditional from unconditional by the mnemonic and reads
// the target out of the operand text, so it has to be a bare hex address.
Instruction direct_jump(std::uint64_t address, std::uint16_t size, std::string mnemonic,
                        std::uint64_t target) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = std::move(mnemonic);

    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(target));
    insn.op_str = buffer;

    insn.is_jump = true;
    insn.is_relative = true;
    return insn;
}

// "jmp rax" and friends. Still a jump, but there's no address in the operand
// text to follow, so nothing downstream should try to make an edge out of it.
Instruction indirect_jump(std::uint64_t address, std::uint16_t size, std::string operands) {
    Instruction insn;
    insn.address = address;
    insn.size = size;
    insn.mnemonic = "jmp";
    insn.op_str = std::move(operands);
    insn.is_jump = true;
    return insn;
}

Instruction direct_call(std::uint64_t address, std::uint16_t size, std::uint64_t target) {
    Instruction insn = direct_jump(address, size, "call", target);
    insn.is_jump = false;
    insn.is_call = true;
    return insn;
}

Instruction ret_at(std::uint64_t address) {
    Instruction insn;
    insn.address = address;
    insn.size = 1;
    insn.mnemonic = "ret";
    insn.is_ret = true;
    return insn;
}

// The same three calls cmd_cfg makes to turn a decoded function into a graph.
CFG build_cfg(const std::vector<Instruction>& instructions) {
    CFG cfg;
    cfg.blocks = minidec::group_into_blocks(instructions);
    minidec::connect_blocks(cfg.blocks);
    if (!cfg.blocks.empty()) {
        cfg.entry = cfg.blocks.front().start;
    }
    return cfg;
}

// if (edi) eax = 1; else eax = 2; return;
//
//   0x1000  test edi, edi        block A, 0x1000 .. 0x1004
//   0x1002  je   0x100b            |
//   0x1004  mov  eax, 1          block B, 0x1004 .. 0x100b
//   0x1009  jmp  0x1010            |
//   0x100b  mov  eax, 2          block C, 0x100b .. 0x1010
//   0x1010  ret                  block D, 0x1010 .. 0x1011
//
// A branches to either B or C and both of them end up at D, which is the
// diamond an if/else eventually has to be recovered from.
std::vector<Instruction> diamond() {
    return {
        plain(0x1000, 2, "test", "edi, edi"),
        direct_jump(0x1002, 2, "je", 0x100b),
        plain(0x1004, 5, "mov", "eax, 1"),
        direct_jump(0x1009, 2, "jmp", 0x1010),
        plain(0x100b, 5, "mov", "eax, 2"),
        ret_at(0x1010),
    };
}

// while (ecx < 10) ecx++; return;
//
//   0x2000  mov  ecx, 0          block B0 (preheader), 0x2000 .. 0x2005
//   0x2005  cmp  ecx, 0xa        block B1 (header),    0x2005 .. 0x200a
//   0x2008  jge  0x2012            |
//   0x200a  add  ecx, 1          block B2 (latch),     0x200a .. 0x2012
//   0x200d  jmp  0x2005            |
//   0x2012  ret                  block B3 (exit),      0x2012 .. 0x2013
//
// B2 -> B1 is the back edge: B1 dominates B2, so jumping to it runs the body
// again. The 5-byte jmp is there to make the addresses land where I want them,
// a real one back that far would be 2 bytes.
std::vector<Instruction> counted_loop() {
    return {
        plain(0x2000, 5, "mov", "ecx, 0"),
        plain(0x2005, 3, "cmp", "ecx, 0xa"),
        direct_jump(0x2008, 2, "jge", 0x2012),
        plain(0x200a, 3, "add", "ecx, 1"),
        direct_jump(0x200d, 5, "jmp", 0x2005),
        ret_at(0x2012),
    };
}

}  // namespace

TEST_CASE("a function with no branches is one block", "[cfg]") {
    std::vector<Instruction> insns = {
        plain(0x1000, 3, "mov", "eax, edi"),
        plain(0x1003, 3, "add", "eax, esi"),
        ret_at(0x1006),
    };

    // Nothing jumps anywhere and the ret is the last instruction, so the only
    // leader is the one you get for free from rule 1.
    std::vector<std::uint64_t> leaders = minidec::find_block_leaders(insns);
    REQUIRE(leaders.size() == 1);
    CHECK(leaders[0] == 0x1000);

    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.size() == 1);
    CHECK(cfg.entry == 0x1000);
    CHECK(cfg.blocks[0].start == 0x1000);
    CHECK(cfg.blocks[0].end == 0x1007);
    CHECK(cfg.blocks[0].instructions.size() == 3);

    // A ret goes back to the caller, so there's no edge out of the function.
    CHECK(cfg.blocks[0].successors.empty());
}

TEST_CASE("a call in the middle of a block doesn't split it", "[cfg]") {
    std::vector<Instruction> insns = {
        plain(0x4000, 5, "mov", "edi, 1"),
        direct_call(0x4005, 5, 0x4100),
        ret_at(0x400a),
    };

    // A call comes back to the instruction after it, so as far as the flow
    // inside this function goes the block just keeps running.
    CHECK(minidec::find_block_leaders(insns).size() == 1);

    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.size() == 1);
    CHECK(cfg.blocks[0].instructions.size() == 3);
    CHECK(cfg.blocks[0].successors.empty());
}

TEST_CASE("leaders come out sorted with no duplicates", "[cfg]") {
    std::vector<Instruction> insns = diamond();

    // 0x1000 from rule 1; 0x100b and 0x1010 as jump targets; 0x1004 and 0x100b
    // as the instructions after a block-ending jump. 0x100b gets picked up
    // twice and should only be listed once.
    std::vector<std::uint64_t> leaders = minidec::find_block_leaders(insns);
    REQUIRE(leaders.size() == 4);
    CHECK(leaders == std::vector<std::uint64_t>{0x1000, 0x1004, 0x100b, 0x1010});
}

TEST_CASE("a jump target outside the function isn't a leader", "[cfg]") {
    std::vector<Instruction> insns = {
        plain(0x1000, 2, "test", "edi, edi"),
        direct_jump(0x1002, 2, "je", 0x9000),  // some other function entirely
        ret_at(0x1004),
    };

    // 0x9000 isn't one of ours so it can't split a block here, but the
    // fall-through after the je still starts one.
    std::vector<std::uint64_t> leaders = minidec::find_block_leaders(insns);
    REQUIRE(leaders.size() == 2);
    CHECK(leaders == std::vector<std::uint64_t>{0x1000, 0x1004});

    // And with nothing of ours to point the taken side at, that block ends up
    // with only its fall-through edge.
    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.size() == 2);
    REQUIRE(cfg.blocks[0].successors.size() == 1);
    CHECK(cfg.blocks[0].successors[0] == 0x1004);
}

TEST_CASE("an if/else builds four blocks with the right edges", "[cfg]") {
    CFG cfg = build_cfg(diamond());
    REQUIRE(cfg.size() == 4);
    CHECK(cfg.entry == 0x1000);

    // Blocks come back in address order, and each one runs from its leader up
    // to the next leader.
    CHECK(cfg.blocks[0].start == 0x1000);
    CHECK(cfg.blocks[0].end == 0x1004);
    CHECK(cfg.blocks[1].start == 0x1004);
    CHECK(cfg.blocks[1].end == 0x100b);
    CHECK(cfg.blocks[2].start == 0x100b);
    CHECK(cfg.blocks[2].end == 0x1010);
    CHECK(cfg.blocks[3].start == 0x1010);
    CHECK(cfg.blocks[3].end == 0x1011);

    // Every instruction has to land in exactly one block.
    CHECK(cfg.blocks[0].instructions.size() == 2);
    CHECK(cfg.blocks[1].instructions.size() == 2);
    CHECK(cfg.blocks[2].instructions.size() == 1);
    CHECK(cfg.blocks[3].instructions.size() == 1);

    // The conditional gets two edges, and connect_blocks pushes the branch
    // target before the fall-through.
    REQUIRE(cfg.blocks[0].successors.size() == 2);
    CHECK(cfg.blocks[0].successors[0] == 0x100b);
    CHECK(cfg.blocks[0].successors[1] == 0x1004);

    // The then-side ends on an unconditional jmp, so only the one edge.
    REQUIRE(cfg.blocks[1].successors.size() == 1);
    CHECK(cfg.blocks[1].successors[0] == 0x1010);

    // The else-side doesn't branch at all -- it was only cut short because the
    // join block is a leader -- so it falls straight through.
    REQUIRE(cfg.blocks[2].successors.size() == 1);
    CHECK(cfg.blocks[2].successors[0] == 0x1010);

    CHECK(cfg.blocks[3].successors.empty());
}

TEST_CASE("block_at finds blocks by their start address only", "[cfg]") {
    CFG cfg = build_cfg(diamond());

    const BasicBlock* join = cfg.block_at(0x1010);
    REQUIRE(join != nullptr);
    CHECK(join->start == 0x1010);
    CHECK(join->terminator().mnemonic == "ret");

    // 0x1009 is the jmp in the middle of a block, not the top of one, and
    // 0x1011 is just past the end of the function.
    CHECK(cfg.block_at(0x1009) == nullptr);
    CHECK(cfg.block_at(0x1011) == nullptr);
}

TEST_CASE("an indirect jump gets no edge", "[cfg]") {
    std::vector<Instruction> insns = {
        plain(0x1000, 3, "mov", "rax, rdi"),
        indirect_jump(0x1003, 2, "rax"),
        ret_at(0x1005),
    };

    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.size() == 2);

    // We can't tell statically where "jmp rax" lands, so there's nothing to
    // point at. It's still a block-ender, which is why the ret is its own block
    // rather than the fall-through of this one.
    CHECK(cfg.blocks[0].successors.empty());
    CHECK(cfg.blocks[1].start == 0x1005);
}

TEST_CASE("the entry dominates everything and every block dominates itself", "[cfg]") {
    CFG cfg = build_cfg(diamond());
    minidec::DominatorSets dominators = minidec::compute_dominators(cfg);
    REQUIRE(dominators.size() == 4);

    for (const BasicBlock& block : cfg.blocks) {
        CHECK(dominators.at(block.start).count(cfg.entry) == 1);
        CHECK(dominators.at(block.start).count(block.start) == 1);
    }

    // Nothing comes before the entry, so it's dominated by itself alone.
    CHECK(dominators.at(0x1000).size() == 1);
}

TEST_CASE("neither arm of an if dominates the join block", "[cfg]") {
    CFG cfg = build_cfg(diamond());
    minidec::DominatorSets dominators = minidec::compute_dominators(cfg);

    // You can reach the join through either arm, so neither one is on every
    // path to it. That leaves the entry and the join itself.
    const std::unordered_set<std::uint64_t>& join = dominators.at(0x1010);
    CHECK(join.size() == 2);
    CHECK(join.count(0x1000) == 1);
    CHECK(join.count(0x1010) == 1);
    CHECK(join.count(0x1004) == 0);
    CHECK(join.count(0x100b) == 0);

    // The arms themselves only hang off the entry.
    CHECK(dominators.at(0x1004) == std::unordered_set<std::uint64_t>{0x1000, 0x1004});
    CHECK(dominators.at(0x100b) == std::unordered_set<std::uint64_t>{0x1000, 0x100b});
}

TEST_CASE("a loop header dominates its body", "[cfg]") {
    CFG cfg = build_cfg(counted_loop());
    REQUIRE(cfg.size() == 4);
    minidec::DominatorSets dominators = minidec::compute_dominators(cfg);

    // The header has two predecessors, the preheader and the latch, but the
    // only way into the loop at all is through the preheader.
    CHECK(dominators.at(0x2005) == std::unordered_set<std::uint64_t>{0x2000, 0x2005});

    // The body is behind the header's conditional, so the header is on every
    // path to it.
    CHECK(dominators.at(0x200a) == std::unordered_set<std::uint64_t>{0x2000, 0x2005, 0x200a});

    // So is the exit, since the branch that leaves the loop lives in the header.
    CHECK(dominators.at(0x2012) == std::unordered_set<std::uint64_t>{0x2000, 0x2005, 0x2012});
}

TEST_CASE("a while loop shows up as one back edge", "[cfg]") {
    CFG cfg = build_cfg(counted_loop());

    // The latch jumps back to the header and the exit block is reached from the
    // header's conditional.
    REQUIRE(cfg.blocks[0].successors == std::vector<std::uint64_t>{0x2005});
    REQUIRE(cfg.blocks[1].successors == std::vector<std::uint64_t>{0x2012, 0x200a});
    REQUIRE(cfg.blocks[2].successors == std::vector<std::uint64_t>{0x2005});
    REQUIRE(cfg.blocks[3].successors.empty());

    std::vector<minidec::NaturalLoop> loops =
        minidec::find_natural_loops(cfg, minidec::compute_dominators(cfg));
    REQUIRE(loops.size() == 1);

    CHECK(loops[0].header == 0x2005);
    CHECK(loops[0].latch == 0x200a);

    // The body is the header and the latch. The preheader is above the loop and
    // the exit is below it, so neither belongs.
    CHECK(loops[0].size() == 2);
    CHECK(loops[0].contains(0x2005));
    CHECK(loops[0].contains(0x200a));
    CHECK_FALSE(loops[0].contains(0x2000));
    CHECK_FALSE(loops[0].contains(0x2012));
}

TEST_CASE("a block jumping to itself is a one block loop", "[cfg]") {
    // "jmp .", the tight infinite loop the compiler emits for while (1) {}.
    std::vector<Instruction> insns = {direct_jump(0x3000, 2, "jmp", 0x3000)};

    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.size() == 1);
    CHECK(cfg.blocks[0].successors == std::vector<std::uint64_t>{0x3000});

    // A block always dominates itself, so the edge counts as a back edge with
    // no special casing needed.
    std::vector<minidec::NaturalLoop> loops =
        minidec::find_natural_loops(cfg, minidec::compute_dominators(cfg));
    REQUIRE(loops.size() == 1);
    CHECK(loops[0].header == 0x3000);
    CHECK(loops[0].latch == 0x3000);
    CHECK(loops[0].size() == 1);
}

TEST_CASE("a straight line function has no loops", "[cfg]") {
    CFG cfg = build_cfg(diamond());
    CHECK(minidec::find_natural_loops(cfg, minidec::compute_dominators(cfg)).empty());
}

TEST_CASE("reverse postorder puts a block after its predecessors", "[cfg]") {
    CFG cfg = build_cfg(diamond());
    std::vector<std::uint64_t> order = minidec::compute_reverse_postorder(cfg);
    REQUIRE(order.size() == 4);

    // Successors are walked in the order they're stored, so the else-arm gets
    // finished first and the postorder comes out join, else, then, entry. That
    // reverses into the entry first and the join last, which is what a forward
    // dataflow pass wants: both arms are done before it looks at the join.
    CHECK(order == std::vector<std::uint64_t>{0x1000, 0x1004, 0x100b, 0x1010});
}

TEST_CASE("reverse postorder walks a loop body once", "[cfg]") {
    CFG cfg = build_cfg(counted_loop());
    std::vector<std::uint64_t> order = minidec::compute_reverse_postorder(cfg);

    // The back edge into the header doesn't send the walk round again, so every
    // block still shows up exactly once.
    REQUIRE(order.size() == 4);
    CHECK(order == std::vector<std::uint64_t>{0x2000, 0x2005, 0x200a, 0x2012});
}

TEST_CASE("an unreachable block is left out of the traversal", "[cfg]") {
    // The ret ends the first block and nothing jumps past it, so the tail below
    // is dead. Real binaries do this with padding between functions.
    std::vector<Instruction> insns = {
        ret_at(0x5000),
        plain(0x5001, 5, "mov", "eax, 1"),
        ret_at(0x5006),
    };

    CFG cfg = build_cfg(insns);
    REQUIRE(cfg.size() == 2);
    CHECK(cfg.blocks[1].start == 0x5001);

    // Reverse postorder is a walk from the entry, so the dead block never turns
    // up and the caller can read "not in here" as "don't bother with it".
    std::vector<std::uint64_t> order = minidec::compute_reverse_postorder(cfg);
    REQUIRE(order.size() == 1);
    CHECK(order[0] == 0x5000);

    // Intersecting an empty list of predecessors leaves it dominated by every
    // block, which is the usual convention and keeps it from pulling the real
    // answers around it down.
    minidec::DominatorSets dominators = minidec::compute_dominators(cfg);
    CHECK(dominators.at(0x5001).size() == 2);

    // That would make any edge out of it look like a back edge, so the loop
    // finder skips unreachable blocks outright.
    CHECK(minidec::find_natural_loops(cfg, dominators).empty());
}

TEST_CASE("an empty instruction list gives an empty graph", "[cfg]") {
    std::vector<Instruction> none;

    CHECK(minidec::find_block_leaders(none).empty());
    CHECK(minidec::group_into_blocks(none).empty());

    CFG cfg = build_cfg(none);
    CHECK(cfg.empty());
    CHECK(cfg.size() == 0);
    CHECK(cfg.block_at(0) == nullptr);
    CHECK(minidec::compute_dominators(cfg).empty());
    CHECK(minidec::find_natural_loops(cfg, minidec::DominatorSets{}).empty());
    CHECK(minidec::compute_reverse_postorder(cfg).empty());
}
