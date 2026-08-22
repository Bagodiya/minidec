#include "minidec/stack.h"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "minidec/ir.h"
#include "minidec/lift.h"

namespace minidec {

namespace {

// A value that turned out to be an address in the frame: so many bytes from the
// value `base` held at version `version`.
struct FrameOffset {
    std::string base;
    unsigned version = 0;
    std::int64_t offset = 0;
};

std::string canonical(const std::string& reg) {
    return std::string(whole_register(reg));
}

// One name per value, so the two kinds can share a map. Temporaries are already
// unique for the whole function; registers need the version glued on, since that
// is the part that says which value we mean.
std::string value_key(const IrOperand& operand) {
    if (operand.kind == OperandKind::temp) {
        return "t" + std::to_string(operand.temp_id);
    }
    if (operand.kind == OperandKind::reg) {
        return canonical(operand.reg) + "#" + std::to_string(operand.version);
    }
    return std::string();
}

// The two registers a frame can be measured from. Anything else that ends up
// holding an address got it from one of these, so it will be resolved rather
// than treated as a base of its own.
bool is_base_register(const std::string& canon) {
    return canon == "rsp" || canon == "rbp";
}

// Displacements arrive as their two's complement -- "[rbp - 4]" lifts to an add
// of 0xfffffffffffffffc -- so reading the constant back as signed is what turns
// it into an offset again.
std::int64_t as_signed(std::uint64_t value) {
    return static_cast<std::int64_t>(value);
}

// Bytes an access of this width touches. Nothing narrower than a byte reaches
// memory, but i1 has a width of 1 bit and would otherwise round to zero.
unsigned access_size(IrType type) {
    unsigned bits = type_bits(type);
    return bits < 8 ? 1 : bits / 8;
}

// Addresses are 64-bit. Anything computed at a narrower width isn't one, however
// much the arithmetic looks the part.
bool is_address_width(IrType type) {
    return type_bits(type) == 64;
}

class FrameScan {
public:
    explicit FrameScan(const SsaFunction& fn) : fn_(fn) {}

    StackFrame run();

private:
    // Register versions some operation in the function writes. What's missing
    // from this is what a base has to be: a version nothing here computed, which
    // is either the value on entry or the leftovers of an instruction we can't
    // model.
    void collect_written();

    // The frame offset a value holds, if it holds one.
    bool resolve(const IrOperand& operand, FrameOffset& out) const;

    // What an operation leaves in its destination. Only the shapes that can move
    // an address around: a copy, and adding or subtracting a constant.
    bool evaluate(const IrInst& inst, FrameOffset& out) const;

    // One sweep of the function, learning what it can. True if it learned
    // anything, which is the caller's cue to sweep again.
    bool sweep();

    void record(const FrameOffset& where, std::uint64_t address, unsigned size, bool is_write);

    const SsaFunction& fn_;
    std::unordered_map<std::string, FrameOffset> known_;
    std::unordered_set<std::string> written_;

    std::vector<StackVar> vars_;
    std::unordered_map<std::string, std::size_t> slots_; // slot name -> index into vars_
    std::size_t untracked_ = 0;
};

void FrameScan::collect_written() {
    for (const SsaBlock& block : fn_.blocks) {
        for (const SsaPhi& phi : block.phis) {
            written_.insert(value_key(phi.dst));
        }
        for (const IrInst& inst : block.code) {
            if (inst.writes_result() && inst.dst.kind == OperandKind::reg) {
                written_.insert(value_key(inst.dst));
            }
        }
    }

    // Clobbers stay out on purpose. They are the versions a call or an unmodelled
    // instruction left behind, and treating those as bases is what makes the
    // ordinary prologue work: "push rbp" doesn't lift, so the rsp the frame is
    // built on is the version that push left.
}

bool FrameScan::resolve(const IrOperand& operand, FrameOffset& out) const {
    if (operand.kind != OperandKind::temp && operand.kind != OperandKind::reg) {
        return false;
    }

    const std::string key = value_key(operand);
    auto found = known_.find(key);
    if (found != known_.end()) {
        out = found->second;
        return true;
    }

    if (operand.kind != OperandKind::reg) {
        return false;
    }

    // A register version something here wrote but we couldn't explain. It may
    // still be an address -- loaded off the stack, say -- but we can't say where
    // from, so it isn't a base.
    if (written_.count(key) != 0) {
        return false;
    }

    const std::string canon = canonical(operand.reg);
    if (!is_base_register(canon)) {
        return false;
    }

    out = FrameOffset{canon, operand.version, 0};
    return true;
}

bool FrameScan::evaluate(const IrInst& inst, FrameOffset& out) const {
    if (!is_address_width(inst.type)) {
        return false;
    }

    if (inst.op == Opcode::assign && inst.args.size() == 1) {
        return resolve(inst.args[0], out);
    }

    if (inst.op == Opcode::add && inst.args.size() == 2) {
        // Either way round: the lifter puts the base first, but nothing promises
        // a hand-written instruction did.
        for (std::size_t i = 0; i < 2; ++i) {
            const IrOperand& other = inst.args[1 - i];
            if (other.is_const() && resolve(inst.args[i], out)) {
                out.offset += as_signed(other.imm);
                return true;
            }
        }
        return false;
    }

    if (inst.op == Opcode::sub && inst.args.size() == 2 && inst.args[1].is_const()) {
        if (resolve(inst.args[0], out)) {
            out.offset -= as_signed(inst.args[1].imm);
            return true;
        }
    }

    return false;
}

bool FrameScan::sweep() {
    bool learned = false;

    for (const SsaBlock& block : fn_.blocks) {
        // A phi only carries an address through if every edge brings the same
        // one. Two stack depths meeting is a real ambiguity, and picking one
        // would put the slots below it at the wrong offsets.
        for (const SsaPhi& phi : block.phis) {
            const std::string key = value_key(phi.dst);
            if (phi.incoming.empty() || known_.count(key) != 0) {
                continue;
            }

            FrameOffset first;
            bool agreed = resolve(phi.incoming.front(), first);
            for (std::size_t i = 1; agreed && i < phi.incoming.size(); ++i) {
                FrameOffset other;
                agreed = resolve(phi.incoming[i], other) && other.base == first.base &&
                         other.version == first.version && other.offset == first.offset;
            }

            if (agreed) {
                known_.emplace(key, first);
                learned = true;
            }
        }

        for (const IrInst& inst : block.code) {
            if (!inst.writes_result()) {
                continue;
            }

            const std::string key = value_key(inst.dst);
            if (key.empty() || known_.count(key) != 0) {
                continue;
            }

            FrameOffset where;
            if (evaluate(inst, where)) {
                known_.emplace(key, where);
                learned = true;
            }
        }
    }

    return learned;
}

void FrameScan::record(const FrameOffset& where, std::uint64_t address, unsigned size,
                       bool is_write) {
    const std::string slot =
        where.base + "#" + std::to_string(where.version) + ":" + std::to_string(where.offset);

    auto found = slots_.find(slot);
    if (found == slots_.end()) {
        StackVar var;
        var.base = where.base;
        var.base_version = where.version;
        var.offset = where.offset;

        found = slots_.emplace(slot, vars_.size()).first;
        vars_.push_back(std::move(var));
    }

    StackVar& var = vars_[found->second];
    var.size = std::max(var.size, size);
    var.accesses.push_back(StackAccess{address, size, is_write});
}

StackFrame FrameScan::run() {
    collect_written();

    // Sweeping until nothing new turns up rather than walking the blocks in a
    // careful order. Address arithmetic is emitted right where it's used, so one
    // sweep gets nearly all of it; the repeat is for the few values that cross a
    // block, like an rsp adjusted in the prologue and read in the body. The map
    // only ever grows, so it settles.
    while (sweep()) {
    }

    for (const SsaBlock& block : fn_.blocks) {
        for (const IrInst& inst : block.code) {
            if (inst.op != Opcode::load && inst.op != Opcode::store) {
                continue;
            }
            if (inst.args.empty()) {
                continue;
            }

            FrameOffset where;
            if (!resolve(inst.args[0], where)) {
                ++untracked_;
                continue;
            }

            record(where, inst.address, access_size(inst.type), inst.op == Opcode::store);
        }
    }

    StackFrame frame;
    frame.vars = std::move(vars_);
    frame.untracked = untracked_;

    for (StackVar& var : frame.vars) {
        std::sort(var.accesses.begin(), var.accesses.end(),
                  [](const StackAccess& a, const StackAccess& b) { return a.address < b.address; });
    }

    std::sort(frame.vars.begin(), frame.vars.end(), [](const StackVar& a, const StackVar& b) {
        if (a.base != b.base) {
            return a.base < b.base;
        }
        if (a.base_version != b.base_version) {
            return a.base_version < b.base_version;
        }
        return a.offset < b.offset;
    });

    return frame;
}

} // namespace

bool StackVar::is_read() const {
    for (const StackAccess& access : accesses) {
        if (!access.is_write) {
            return true;
        }
    }
    return false;
}

bool StackVar::is_written() const {
    for (const StackAccess& access : accesses) {
        if (access.is_write) {
            return true;
        }
    }
    return false;
}

const StackVar* StackFrame::var_at(std::int64_t offset) const {
    for (const StackVar& var : vars) {
        if (var.offset == offset) {
            return &var;
        }
    }
    return nullptr;
}

StackFrame find_stack_variables(const SsaFunction& fn) {
    FrameScan scan(fn);
    return scan.run();
}

} // namespace minidec
