#include "minidec/ssa.h"

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "minidec/disasm.h"
#include "minidec/lift.h"

namespace minidec {

namespace {

bool is_register(const IrOperand& operand) {
    return operand.kind == OperandKind::reg;
}

// Every register the pass keys a version off is stored under this name.
std::string canonical(const std::string& name) {
    return std::string(whole_register(name));
}

// Everything the function mentions, canonical and sorted. Sorted because it
// decides the order clobbers are listed in, and a listing that reshuffles
// between runs is no use for comparing output.
std::vector<std::string> mentioned_registers(const std::vector<SsaBlock>& blocks) {
    std::unordered_set<std::string> seen;

    for (const SsaBlock& block : blocks) {
        for (const IrInst& inst : block.code) {
            if (is_register(inst.dst)) {
                seen.insert(canonical(inst.dst.reg));
            }
            for (const IrOperand& arg : inst.args) {
                if (is_register(arg)) {
                    seen.insert(canonical(arg.reg));
                }
            }
        }
    }

    std::vector<std::string> names(seen.begin(), seen.end());
    std::sort(names.begin(), names.end());
    return names;
}

// The registers an instruction leaves in a state we can't name. Nothing for
// almost everything: only a call and an unknown get here.
//
// Restricted to registers the function actually mentions, so a function that
// never touches r10 doesn't collect a version of it at every call.
std::vector<std::string> clobbered_by(const IrInst& inst,
                                      const std::vector<std::string>& mentioned) {
    if (inst.op != Opcode::call && inst.op != Opcode::unknown) {
        return {};
    }

    // A call writes rax itself, that being where the result comes back, so
    // clobbering it too would only produce a version nothing can read.
    std::string written;
    if (inst.writes_result() && is_register(inst.dst)) {
        written = canonical(inst.dst.reg);
    }

    // An unknown is an instruction we couldn't model, so the honest assumption
    // is that it wrote everything. A call has a convention behind it and only
    // gets the caller-saved half.
    std::vector<std::string> result;
    for (const std::string& reg : mentioned) {
        if (reg == written) {
            continue;
        }
        if (inst.op == Opcode::unknown) {
            result.push_back(reg);
            continue;
        }
        const std::vector<std::string>& saved = caller_saved_registers();
        if (std::find(saved.begin(), saved.end(), reg) != saved.end()) {
            result.push_back(reg);
        }
    }
    return result;
}

}  // namespace

const SsaBlock* SsaFunction::block_at(std::uint64_t address) const {
    for (const SsaBlock& block : blocks) {
        if (block.start == address) {
            return &block;
        }
    }
    return nullptr;
}

SsaFunction build_ssa(const CFG& cfg) {
    SsaFunction fn;
    if (cfg.empty() || cfg.block_at(cfg.entry) == nullptr) {
        return fn;
    }
    fn.entry = cfg.entry;

    // Reverse postorder is only being used for the set of blocks it covers, which
    // is the reachable ones. The order itself doesn't matter here: the renaming
    // walk follows the dominator tree instead.
    std::vector<std::uint64_t> reachable_order = compute_reverse_postorder(cfg);
    std::unordered_set<std::uint64_t> reachable(reachable_order.begin(), reachable_order.end());

    // One Lifter for the whole function, so no two blocks hand out the same
    // temporary number and the temporaries stay single-assignment across joins.
    Lifter lifter;
    for (const BasicBlock& block : cfg.blocks) {
        if (!reachable.count(block.start)) {
            continue;
        }

        SsaBlock out;
        out.start = block.start;
        for (std::uint64_t succ : block.successors) {
            if (reachable.count(succ)) {
                out.successors.push_back(succ);
            }
        }
        for (const Instruction& insn : block.instructions) {
            for (IrInst& ir : lifter.lift(insn)) {
                out.code.push_back(std::move(ir));
            }
        }
        fn.blocks.push_back(std::move(out));
    }
    fn.temp_count = lifter.temp_count();

    std::unordered_map<std::uint64_t, std::size_t> index;
    for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
        index[fn.blocks[i].start] = i;
    }

    // Reverse the edges. Blocks are in address order and appended in that order,
    // so each predecessor list comes out sorted without being sorted.
    for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
        for (std::uint64_t succ : fn.blocks[i].successors) {
            fn.blocks[index[succ]].predecessors.push_back(fn.blocks[i].start);
        }
    }

    DominatorSets dominators = compute_dominators(cfg);
    ImmediateDominators idom = compute_immediate_dominators(cfg, dominators);
    DominanceFrontiers frontiers = compute_dominance_frontiers(cfg, idom);

    std::vector<std::string> mentioned = mentioned_registers(fn.blocks);

    // Where each register is written. A clobber counts: the value after a call
    // is as much a new definition as an assignment would have been, and a join
    // below it needs a phi just the same.
    std::unordered_map<std::string, std::unordered_set<std::uint64_t>> def_sites;
    for (const SsaBlock& block : fn.blocks) {
        for (const IrInst& inst : block.code) {
            if (inst.writes_result() && is_register(inst.dst)) {
                def_sites[canonical(inst.dst.reg)].insert(block.start);
            }
            for (const std::string& reg : clobbered_by(inst, mentioned)) {
                def_sites[reg].insert(block.start);
            }
        }
    }

    // Phi placement, one register at a time. A phi is itself a write, so a block
    // that gets one goes back on the worklist unless it was already writing the
    // register on its own account.
    for (const std::string& reg : mentioned) {
        auto sites = def_sites.find(reg);
        if (sites == def_sites.end()) {
            continue;
        }
        std::optional<IrType> type = register_type(reg);
        if (!type) {
            continue;
        }

        std::unordered_set<std::uint64_t> placed;
        std::vector<std::uint64_t> worklist(sites->second.begin(), sites->second.end());

        while (!worklist.empty()) {
            std::uint64_t current = worklist.back();
            worklist.pop_back();

            auto frontier = frontiers.find(current);
            if (frontier == frontiers.end()) {
                continue;
            }

            for (std::uint64_t join : frontier->second) {
                if (!placed.insert(join).second) {
                    continue;
                }
                auto target = index.find(join);
                if (target == index.end()) {
                    continue;
                }

                SsaBlock& block = fn.blocks[target->second];
                SsaPhi phi;
                phi.dst = make_reg(reg, *type);
                phi.incoming.assign(block.predecessors.size(), make_reg(reg, *type));
                block.phis.push_back(std::move(phi));

                if (!sites->second.count(join)) {
                    worklist.push_back(join);
                }
            }
        }
    }

    // The worklist runs off an unordered set, so the phis landed in whatever
    // order it happened to hand blocks back. Sort them by register name to get
    // the same listing every run.
    for (SsaBlock& block : fn.blocks) {
        std::sort(block.phis.begin(), block.phis.end(),
                  [](const SsaPhi& a, const SsaPhi& b) { return a.reg() < b.reg(); });
    }

    // The dominator tree, read downwards. Sorted children again for a stable
    // walk, which is what makes version numbers repeatable.
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> children;
    for (const auto& entry : idom) {
        if (reachable.count(entry.first)) {
            children[entry.second].push_back(entry.first);
        }
    }
    for (auto& entry : children) {
        std::sort(entry.second.begin(), entry.second.end());
    }

    // Renaming state. counters hands out the next version of a register;
    // stacks holds the version live at the point of the walk we're at.
    std::unordered_map<std::string, unsigned> counters;
    std::unordered_map<std::string, std::vector<unsigned>> stacks;

    auto live_version = [&stacks](const std::string& reg) -> unsigned {
        auto it = stacks.find(reg);
        return it == stacks.end() || it->second.empty() ? 0u : it->second.back();
    };

    auto new_version = [&counters, &stacks](const std::string& reg) -> unsigned {
        unsigned version = ++counters[reg];
        stacks[reg].push_back(version);
        return version;
    };

    // A read that came back version 0 read something no write here produced, so
    // it arrived with the function. Worth recording once, at the first read.
    auto note_live_in = [&fn](const IrOperand& operand) {
        for (const IrOperand& value : fn.live_in) {
            if (whole_register(value.reg) == whole_register(operand.reg)) {
                return;
            }
        }
        fn.live_in.push_back(operand);
    };

    // Version one block, and fill in the phi slots it feeds in its successors.
    // `pushed` collects every register given a version here so the walk can undo
    // them on the way back out.
    auto rename = [&](SsaBlock& block, std::vector<std::string>& pushed) {
        for (SsaPhi& phi : block.phis) {
            std::string reg = canonical(phi.dst.reg);
            phi.dst.version = new_version(reg);
            pushed.push_back(reg);
        }

        block.clobbers.clear();
        for (std::size_t i = 0; i < block.code.size(); ++i) {
            IrInst& inst = block.code[i];

            // Reads before writes: an instruction that does both, like the
            // two-operand imul, reads the version from before its own.
            for (IrOperand& arg : inst.args) {
                if (!is_register(arg)) {
                    continue;
                }
                arg.version = live_version(canonical(arg.reg));
                if (arg.version == 0) {
                    note_live_in(arg);
                }
            }

            SsaClobber clobber;
            clobber.inst = i;
            for (const std::string& reg : clobbered_by(inst, mentioned)) {
                std::optional<IrType> type = register_type(reg);
                if (!type) {
                    continue;
                }
                IrOperand value = make_reg(reg, *type);
                value.version = new_version(reg);
                pushed.push_back(reg);
                clobber.values.push_back(std::move(value));
            }
            if (!clobber.values.empty()) {
                block.clobbers.push_back(std::move(clobber));
            }

            if (inst.writes_result() && is_register(inst.dst)) {
                std::string reg = canonical(inst.dst.reg);
                inst.dst.version = new_version(reg);
                pushed.push_back(reg);
            }
        }

        // Each successor's phi wants the version live at the end of this block,
        // in the slot standing for the edge from here.
        for (std::uint64_t succ : block.successors) {
            auto target = index.find(succ);
            if (target == index.end()) {
                continue;
            }
            SsaBlock& next = fn.blocks[target->second];

            auto slot = std::find(next.predecessors.begin(), next.predecessors.end(), block.start);
            if (slot == next.predecessors.end()) {
                continue;
            }
            std::size_t position = static_cast<std::size_t>(slot - next.predecessors.begin());

            for (SsaPhi& phi : next.phis) {
                IrOperand& incoming = phi.incoming[position];
                incoming.version = live_version(canonical(incoming.reg));
                if (incoming.version == 0) {
                    note_live_in(incoming);
                }
            }
        }
    };

    // Down the dominator tree, explicit stack rather than recursion. A frame is
    // pushed already renamed, and pops its own versions off on the way out so a
    // sibling doesn't see them.
    struct Frame {
        std::uint64_t block = 0;
        std::size_t next_child = 0;
        std::vector<std::string> pushed;
    };

    std::vector<Frame> stack;
    {
        Frame root;
        root.block = fn.entry;
        rename(fn.blocks[index[fn.entry]], root.pushed);
        stack.push_back(std::move(root));
    }

    while (!stack.empty()) {
        Frame& frame = stack.back();

        auto kids = children.find(frame.block);
        if (kids != children.end() && frame.next_child < kids->second.size()) {
            std::uint64_t child = kids->second[frame.next_child];
            ++frame.next_child;

            Frame next;
            next.block = child;
            auto target = index.find(child);
            if (target != index.end()) {
                rename(fn.blocks[target->second], next.pushed);
            }
            // Invalidates `frame`, so nothing below may touch it.
            stack.push_back(std::move(next));
            continue;
        }

        for (const std::string& reg : frame.pushed) {
            stacks[reg].pop_back();
        }
        stack.pop_back();
    }

    return fn;
}

}  // namespace minidec
