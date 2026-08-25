#include "minidec/regvar.h"

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "minidec/lift.h"

namespace minidec {

namespace {

// Stands in for "no such position" in the tables below.
constexpr std::size_t nowhere = static_cast<std::size_t>(-1);

std::string canonical(const std::string& reg) {
    return std::string(whole_register(reg));
}

// See the note on find_register_variables for why these three are out.
bool is_variable_register(const std::string& canon) {
    if (canon == "rsp" || canon == "rbp" || canon == "rip") {
        return false;
    }
    std::optional<IrType> type = register_type(canon);
    return type.has_value() && *type != IrType::i1;
}

bool tracked(const IrOperand& operand) {
    return operand.kind == OperandKind::reg && is_variable_register(canonical(operand.reg));
}

// A register version, before anything is merged.
struct Value {
    std::string reg;
    unsigned version = 0;
};

// What liveness needs to know about one block, all of it in merged ids.
struct BlockFacts {
    std::unordered_set<std::size_t> defined; // written somewhere in the block
    std::unordered_set<std::size_t> used;    // read before the block writes it
    std::unordered_set<std::size_t> phi_out; // wanted by a phi in a successor
    std::unordered_set<std::size_t> live_in;
    std::unordered_set<std::size_t> live_out;
};

// Where in a block a variable is first written and last read. Both are indices
// into SsaBlock::code, so a phi write is a case of its own -- it happens above
// instruction zero rather than at it.
struct Position {
    std::size_t first_def = nowhere;
    std::size_t last_use = nowhere;
    bool def_by_phi = false;
};

class RegScan {
public:
    explicit RegScan(const SsaFunction& fn) : fn_(fn) {
        facts_.resize(fn_.blocks.size());
        positions_.resize(fn_.blocks.size());
        for (std::size_t i = 0; i < fn_.blocks.size(); ++i) {
            index_.emplace(fn_.blocks[i].start, i);
        }
    }

    RegVars run();

private:
    // Value ids. intern() hands the same id back for the same register and
    // version, so the two halves of a phi meet on the same number.
    std::size_t intern(const IrOperand& operand);
    std::size_t root(std::size_t id);
    void unite(std::size_t a, std::size_t b);

    // Pull the versions a phi joins onto one id, which is what turns a pile of
    // versions into a variable. Has to finish before anything else asks for a
    // root, or the earlier answers go stale.
    void merge_phis();

    void scan_blocks();
    void solve_liveness();
    void build_spans();

    // The entry for a merged id, created on first mention.
    RegVar& variable(std::size_t id);
    void note_width(std::size_t id, IrType type);

    std::size_t block_index(std::uint64_t address) const;

    const SsaFunction& fn_;
    std::unordered_map<std::uint64_t, std::size_t> index_; // block address -> position

    std::vector<Value> values_;
    std::unordered_map<std::string, std::size_t> ids_; // "rax#2" -> value id
    std::vector<std::size_t> parent_;

    std::vector<BlockFacts> facts_;
    std::vector<std::unordered_map<std::size_t, Position>> positions_;

    std::unordered_map<std::size_t, RegVar> vars_; // keyed by merged id
};

std::size_t RegScan::intern(const IrOperand& operand) {
    Value value{canonical(operand.reg), operand.version};
    const std::string key = value.reg + "#" + std::to_string(value.version);

    auto found = ids_.find(key);
    if (found != ids_.end()) {
        return found->second;
    }

    const std::size_t id = values_.size();
    values_.push_back(std::move(value));
    parent_.push_back(id);
    ids_.emplace(key, id);
    return id;
}

std::size_t RegScan::root(std::size_t id) {
    while (parent_[id] != id) {
        parent_[id] = parent_[parent_[id]]; // halve the path on the way up
        id = parent_[id];
    }
    return id;
}

void RegScan::unite(std::size_t a, std::size_t b) {
    a = root(a);
    b = root(b);
    if (a == b) {
        return;
    }
    // Lower id wins, so the id a variable ends up under doesn't depend on the
    // order the phis were visited in.
    if (a < b) {
        parent_[b] = a;
    } else {
        parent_[a] = b;
    }
}

std::size_t RegScan::block_index(std::uint64_t address) const {
    auto found = index_.find(address);
    return found == index_.end() ? nowhere : found->second;
}

RegVar& RegScan::variable(std::size_t id) {
    auto found = vars_.find(id);
    if (found == vars_.end()) {
        RegVar var;
        var.reg = values_[id].reg;
        found = vars_.emplace(id, std::move(var)).first;
    }
    return found->second;
}

void RegScan::note_width(std::size_t id, IrType type) {
    RegVar& var = variable(id);
    var.width = std::max(var.width, type_bits(type));
}

void RegScan::merge_phis() {
    for (const SsaBlock& block : fn_.blocks) {
        for (const SsaPhi& phi : block.phis) {
            if (!tracked(phi.dst)) {
                continue;
            }
            const std::size_t dst = intern(phi.dst);
            for (const IrOperand& incoming : phi.incoming) {
                if (tracked(incoming)) {
                    unite(dst, intern(incoming));
                }
            }
        }
    }
}

void RegScan::scan_blocks() {
    for (std::size_t b = 0; b < fn_.blocks.size(); ++b) {
        const SsaBlock& block = fn_.blocks[b];
        BlockFacts& facts = facts_[b];
        auto& positions = positions_[b];

        // Phis write at the top, so a read anywhere below one sees it and the
        // block is not reading anything from above.
        for (const SsaPhi& phi : block.phis) {
            if (!tracked(phi.dst)) {
                continue;
            }
            const std::size_t id = root(intern(phi.dst));
            facts.defined.insert(id);

            Position& where = positions[id];
            if (where.first_def == nowhere) {
                where.first_def = 0;
                where.def_by_phi = true;
            }

            RegDef def;
            def.block = block.start;
            def.version = phi.dst.version;
            def.is_phi = true;
            variable(id).defs.push_back(def);
            note_width(id, phi.dst.type);
        }

        std::size_t next_clobber = 0;

        for (std::size_t i = 0; i < block.code.size(); ++i) {
            const IrInst& inst = block.code[i];

            for (std::size_t a = 0; a < inst.args.size(); ++a) {
                const IrOperand& arg = inst.args[a];
                if (!tracked(arg)) {
                    continue;
                }
                const std::size_t id = root(intern(arg));
                if (facts.defined.count(id) == 0) {
                    facts.used.insert(id);
                }
                positions[id].last_use = i;

                RegUse use;
                use.block = block.start;
                use.inst = i;
                use.arg = a;
                use.address = inst.address;
                use.version = arg.version;
                variable(id).uses.push_back(use);
                note_width(id, arg.type);
            }

            auto record_def = [&](const IrOperand& value, bool is_clobber) {
                const std::size_t id = root(intern(value));
                facts.defined.insert(id);

                Position& where = positions[id];
                if (where.first_def == nowhere) {
                    where.first_def = i;
                }

                RegDef def;
                def.block = block.start;
                def.inst = i;
                def.address = inst.address;
                def.version = value.version;
                def.is_clobber = is_clobber;
                variable(id).defs.push_back(def);
                note_width(id, value.type);
            };

            if (inst.writes_result() && tracked(inst.dst)) {
                record_def(inst.dst, false);
            }

            // Clobbers hang off the instruction rather than living in the code,
            // and there is at most one entry per index, so walking them with a
            // cursor keeps this linear.
            while (next_clobber < block.clobbers.size() && block.clobbers[next_clobber].inst < i) {
                ++next_clobber;
            }
            if (next_clobber < block.clobbers.size() && block.clobbers[next_clobber].inst == i) {
                for (const IrOperand& value : block.clobbers[next_clobber].values) {
                    if (tracked(value)) {
                        record_def(value, true);
                    }
                }
                ++next_clobber;
            }
        }
    }

    // A phi argument belongs to the edge it arrives on: it has to still be live
    // at the bottom of that one predecessor, and says nothing about the others.
    // Slot i of the phi pairs with predecessor i, which is what SsaBlock
    // promises.
    for (const SsaBlock& block : fn_.blocks) {
        for (const SsaPhi& phi : block.phis) {
            for (std::size_t i = 0; i < phi.incoming.size() && i < block.predecessors.size(); ++i) {
                if (!tracked(phi.incoming[i])) {
                    continue;
                }
                const std::size_t pred = block_index(block.predecessors[i]);
                if (pred != nowhere) {
                    facts_[pred].phi_out.insert(root(intern(phi.incoming[i])));
                }
            }
        }
    }
}

void RegScan::solve_liveness() {
    // Backwards to a fixed point. Liveness runs against the flow of control, so
    // sweeping the blocks in reverse address order carries most of the answer in
    // one pass and only a loop makes it take more than two.
    bool changed = true;
    while (changed) {
        changed = false;

        for (std::size_t i = fn_.blocks.size(); i-- > 0;) {
            const SsaBlock& block = fn_.blocks[i];
            BlockFacts& facts = facts_[i];

            std::unordered_set<std::size_t> out = facts.phi_out;
            for (std::uint64_t successor : block.successors) {
                const std::size_t next = block_index(successor);
                if (next == nowhere) {
                    continue;
                }
                out.insert(facts_[next].live_in.begin(), facts_[next].live_in.end());
            }

            std::unordered_set<std::size_t> in = facts.used;
            for (std::size_t id : out) {
                if (facts.defined.count(id) == 0) {
                    in.insert(id);
                }
            }

            if (out != facts.live_out || in != facts.live_in) {
                facts.live_out = std::move(out);
                facts.live_in = std::move(in);
                changed = true;
            }
        }
    }
}

void RegScan::build_spans() {
    for (std::size_t b = 0; b < fn_.blocks.size(); ++b) {
        const SsaBlock& block = fn_.blocks[b];
        const BlockFacts& facts = facts_[b];
        const auto& positions = positions_[b];

        // Everything the block has anything to do with: what flows through it as
        // well as what it writes itself.
        std::unordered_set<std::size_t> present = facts.live_in;
        present.insert(facts.live_out.begin(), facts.live_out.end());
        present.insert(facts.defined.begin(), facts.defined.end());

        // In id order, so a block's spans don't come out shuffled by the hash.
        std::vector<std::size_t> ordered(present.begin(), present.end());
        std::sort(ordered.begin(), ordered.end());

        for (std::size_t id : ordered) {
            const bool enters = facts.live_in.count(id) != 0;
            const bool leaves = facts.live_out.count(id) != 0;

            Position where;
            auto found = positions.find(id);
            if (found != positions.end()) {
                where = found->second;
            }

            std::size_t begin = 0;
            if (!enters) {
                if (where.first_def == nowhere) {
                    continue; // neither written here nor arriving; nothing to draw
                }
                begin = where.def_by_phi ? 0 : where.first_def;
            }

            std::size_t end = 0;
            if (leaves) {
                end = block.code.size();
            } else if (where.last_use != nowhere) {
                end = where.last_use + 1;
            } else {
                // Written and never read again. The span still covers the write
                // itself, which is what makes a dead one visible as a span of
                // exactly one instruction.
                end = std::min(begin + 1, block.code.size());
            }

            LiveSpan span;
            span.block = block.start;
            span.begin = begin;
            span.end = std::max(begin, end);
            span.enters = enters;
            span.leaves = leaves;

            RegVar& var = variable(id);

            // Live on both sides of a call, so whatever it holds had to survive
            // one. A value the call itself produced starts at the call and has
            // not crossed anything.
            for (std::size_t i = span.begin; i < span.end; ++i) {
                if (block.code[i].op != Opcode::call) {
                    continue;
                }
                const bool held_before = span.enters || span.begin < i;
                const bool held_after = span.leaves || span.end > i + 1;
                if (held_before && held_after) {
                    var.crosses_call = true;
                    break;
                }
            }

            var.live.push_back(span);
        }
    }
}

RegVars RegScan::run() {
    merge_phis();
    scan_blocks();
    solve_liveness();
    build_spans();

    for (std::size_t id = 0; id < values_.size(); ++id) {
        const std::size_t owner = root(id);
        auto found = vars_.find(owner);
        if (found != vars_.end()) {
            found->second.versions.push_back(values_[id].version);
        }
    }

    RegVars result;
    for (auto& entry : vars_) {
        RegVar& var = entry.second;
        if (var.uses.empty()) {
            continue; // written and never read: dead, not a variable
        }
        std::sort(var.versions.begin(), var.versions.end());
        result.vars.push_back(std::move(var));
    }

    std::sort(result.vars.begin(), result.vars.end(), [](const RegVar& a, const RegVar& b) {
        if (a.reg != b.reg) {
            return a.reg < b.reg;
        }
        return a.versions.front() < b.versions.front();
    });

    return result;
}

} // namespace

bool RegVar::from_caller() const {
    return !versions.empty() && versions.front() == 0;
}

const RegVar* RegVars::var_for(const std::string& reg, unsigned version) const {
    const std::string canon = canonical(reg);
    for (const RegVar& var : vars) {
        if (var.reg != canon) {
            continue;
        }
        if (std::find(var.versions.begin(), var.versions.end(), version) != var.versions.end()) {
            return &var;
        }
    }
    return nullptr;
}

RegVars find_register_variables(const SsaFunction& fn) {
    RegScan scan(fn);
    return scan.run();
}

} // namespace minidec
