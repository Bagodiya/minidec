#include "minidec/datatype.h"

#include <algorithm>
#include <string>
#include <unordered_map>

#include "minidec/lift.h"

namespace minidec {

namespace {

std::string canonical(const std::string& reg) {
    return std::string(whole_register(reg));
}

// One name per value, the same keying stack.cpp uses. Temporaries are unique for
// the whole function already; a register needs its version glued on, since that
// is the half that says which value is meant.
std::string value_key(const IrOperand& operand) {
    if (operand.kind == OperandKind::temp) {
        return "t" + std::to_string(operand.temp_id);
    }
    if (operand.kind == OperandKind::reg) {
        return canonical(operand.reg) + "#" + std::to_string(operand.version);
    }
    return std::string();
}

// Two pieces of evidence about the same value. Anything on top of unknown wins,
// and two different answers are a disagreement rather than a tie to break.
DataType join(DataType a, DataType b) {
    if (a == b) {
        return a;
    }
    if (a == DataType::unknown) {
        return b;
    }
    if (b == DataType::unknown) {
        return a;
    }
    return DataType::conflict;
}

// What the width alone settles, before anything is propagated.
DataType from_width(unsigned bits) {
    if (bits == 1) {
        return DataType::boolean;
    }
    if (bits >= 8 && bits < 64) {
        return DataType::integer;
    }
    return DataType::unknown;
}

// The two registers the frame is measured from. A function does arithmetic on
// them, but whatever else it does they hold an address the whole way through.
bool is_frame_register(const std::string& canon) {
    return canon == "rsp" || canon == "rbp";
}

class TypeScan {
public:
    explicit TypeScan(const SsaFunction& fn) : fn_(fn) {}

    TypeMap run();

private:
    // Every value the function mentions, with its width and whatever the width
    // and the frame registers already say about it.
    void collect();
    void see(const IrOperand& operand);

    // One pass of the rules over the whole function. True if anything was
    // learned, which is the caller's cue to go round again.
    bool sweep();
    void apply(const IrInst& inst);

    // Both operands of an add or a sub, and its result, read against each other.
    void arithmetic(const IrInst& inst);

    // Everything the operation touches is a number.
    void all_integer(const IrInst& inst);

    // Only what it produced is. See the note where it is used.
    void result_integer(const IrInst& inst);

    // Two spellings of the same value: whatever is known about either is known
    // about both.
    void unify(const IrOperand& a, const IrOperand& b);

    DataType lookup(const IrOperand& operand) const;
    void note(const IrOperand& operand, DataType type);

    const SsaFunction& fn_;
    std::unordered_map<std::string, ValueType> facts_;
    bool learned_ = false;
};

void TypeScan::see(const IrOperand& operand) {
    const std::string key = value_key(operand);
    if (key.empty()) {
        return;
    }

    auto found = facts_.find(key);
    if (found == facts_.end()) {
        ValueType value;
        value.kind = operand.kind;
        if (operand.kind == OperandKind::reg) {
            value.reg = canonical(operand.reg);
            value.version = operand.version;
        } else {
            value.temp_id = operand.temp_id;
        }
        found = facts_.emplace(key, std::move(value)).first;
    }

    ValueType& value = found->second;
    value.width = std::max(value.width, type_bits(operand.type));
    value.type = join(value.type, from_width(value.width));

    if (value.kind == OperandKind::reg && is_frame_register(value.reg)) {
        value.type = join(value.type, DataType::pointer);
    }
}

void TypeScan::collect() {
    for (const SsaBlock& block : fn_.blocks) {
        for (const SsaPhi& phi : block.phis) {
            see(phi.dst);
            for (const IrOperand& incoming : phi.incoming) {
                see(incoming);
            }
        }
        for (const IrInst& inst : block.code) {
            see(inst.dst);
            for (const IrOperand& arg : inst.args) {
                see(arg);
            }
        }
        // The versions a call left behind. Nothing wrote them on purpose, but a
        // read further down can still see one, so they are values like any other.
        for (const SsaClobber& clobber : block.clobbers) {
            for (const IrOperand& value : clobber.values) {
                see(value);
            }
        }
    }
}

DataType TypeScan::lookup(const IrOperand& operand) const {
    // A constant counts as a number here even though nothing tracks it, which is
    // what makes "pointer plus displacement" come out a pointer.
    if (operand.is_const()) {
        return DataType::integer;
    }

    auto found = facts_.find(value_key(operand));
    return found == facts_.end() ? DataType::unknown : found->second.type;
}

void TypeScan::note(const IrOperand& operand, DataType type) {
    auto found = facts_.find(value_key(operand));
    if (found == facts_.end()) {
        return;
    }

    // A single bit is a condition and stays one. The lifter spells "jne" as a
    // bit_not over zf, so the bitwise rule below would otherwise call half the
    // flags in the function numbers.
    if (found->second.width == 1 && type != DataType::boolean) {
        return;
    }

    const DataType merged = join(found->second.type, type);
    if (merged != found->second.type) {
        found->second.type = merged;
        learned_ = true;
    }
}

void TypeScan::unify(const IrOperand& a, const IrOperand& b) {
    note(a, lookup(b));
    note(b, lookup(a));
}

void TypeScan::all_integer(const IrInst& inst) {
    note(inst.dst, DataType::integer);
    for (const IrOperand& arg : inst.args) {
        note(arg, DataType::integer);
    }
}

void TypeScan::result_integer(const IrInst& inst) {
    note(inst.dst, DataType::integer);
}

void TypeScan::arithmetic(const IrInst& inst) {
    if (inst.args.size() != 2) {
        return;
    }

    const IrOperand& lhs = inst.args[0];
    const IrOperand& rhs = inst.args[1];

    const DataType a = lookup(lhs);
    const DataType b = lookup(rhs);
    const DataType result = lookup(inst.dst);

    if (inst.op == Opcode::add) {
        // An add moves an address along when exactly one side is one. Both sides
        // being addresses is not a shape that means anything, so it is left
        // alone rather than guessed at.
        if (a == DataType::pointer && b == DataType::integer) {
            note(inst.dst, DataType::pointer);
        } else if (a == DataType::integer && b == DataType::pointer) {
            note(inst.dst, DataType::pointer);
        } else if (a == DataType::integer && b == DataType::integer) {
            note(inst.dst, DataType::integer);
        }

        // Backwards: a sum that is an address had exactly one address in it, and
        // a sum that is a number had none.
        if (result == DataType::pointer) {
            if (a == DataType::integer) {
                note(rhs, DataType::pointer);
            }
            if (b == DataType::integer) {
                note(lhs, DataType::pointer);
            }
        } else if (result == DataType::integer) {
            note(lhs, DataType::integer);
            note(rhs, DataType::integer);
        }
        return;
    }

    // Subtract. Taking one address from another is how a distance is measured,
    // which is the one place a number comes out of two pointers.
    if (a == DataType::pointer && b == DataType::integer) {
        note(inst.dst, DataType::pointer);
    } else if (a == DataType::pointer && b == DataType::pointer) {
        note(inst.dst, DataType::integer);
    } else if (a == DataType::integer && b == DataType::integer) {
        note(inst.dst, DataType::integer);
    }

    if (result == DataType::pointer && b == DataType::integer) {
        note(lhs, DataType::pointer);
    }
    if (result == DataType::integer) {
        if (a == DataType::pointer) {
            note(rhs, DataType::pointer);
        }
        if (a == DataType::integer) {
            note(rhs, DataType::integer);
        }
    }
}

void TypeScan::apply(const IrInst& inst) {
    switch (inst.op) {
    case Opcode::load:
    case Opcode::store:
        // The one operation that says outright what its operand is for.
        if (!inst.args.empty()) {
            note(inst.args[0], DataType::pointer);
        }
        break;

    case Opcode::assign:
        if (inst.args.size() == 1) {
            unify(inst.dst, inst.args[0]);
        }
        break;

    case Opcode::add:
    case Opcode::sub:
        arithmetic(inst);
        break;

    case Opcode::mul:
    case Opcode::div_u:
    case Opcode::div_s:
    case Opcode::rem_u:
    case Opcode::rem_s:
    case Opcode::neg:
    case Opcode::shl:
    case Opcode::shr_u:
    case Opcode::shr_s:
    case Opcode::sext:
    case Opcode::trunc:
        all_integer(inst);
        break;

    case Opcode::bit_or:
    case Opcode::bit_xor:
    case Opcode::bit_not:
        // The result of one of these is a number, but its operands are let
        // alone: the lifter builds the overflow flag out of xors and ands over
        // whatever the instruction was adding, and a pointer walked along by an
        // "add rax, 8" would come back a number through that chain.
        result_integer(inst);
        break;

    case Opcode::bit_and:
        // Same, except that an and against a constant is a mask, and masking an
        // address leaves an address -- rounding rsp down to an alignment is the
        // usual case -- so there the result is whatever went in.
        if (inst.args.size() == 2 && (inst.args[0].is_const() || inst.args[1].is_const())) {
            unify(inst.dst, inst.args[0].is_const() ? inst.args[1] : inst.args[0]);
        } else {
            result_integer(inst);
        }
        break;

    default:
        // The comparisons are deliberately absent. A signed compare against zero
        // looks like it is saying its operand is a number, but nearly every one
        // in a function is the lifter working out the sign flag of an addition,
        // and the operand it reads is that addition's result. zext is out too:
        // it leaves a narrow value in a wide register and either answer is still
        // open. So are call and ret, since a convention says where an argument
        // sits and not what it is.
        break;
    }
}

bool TypeScan::sweep() {
    learned_ = false;

    for (const SsaBlock& block : fn_.blocks) {
        // A phi is the same variable arriving down different edges, so every
        // version it joins has to agree.
        for (const SsaPhi& phi : block.phis) {
            for (const IrOperand& incoming : phi.incoming) {
                unify(phi.dst, incoming);
            }
        }
        for (const IrInst& inst : block.code) {
            apply(inst);
        }
    }

    return learned_;
}

TypeMap TypeScan::run() {
    collect();

    // Round and round until nothing new turns up. Evidence only ever narrows a
    // value from unknown or widens it to a conflict, and neither goes back, so
    // the sweeps settle.
    while (sweep()) {
    }

    TypeMap map;
    map.values.reserve(facts_.size());
    for (auto& entry : facts_) {
        map.values.push_back(std::move(entry.second));
    }

    std::sort(map.values.begin(), map.values.end(), [](const ValueType& a, const ValueType& b) {
        if (a.kind != b.kind) {
            return a.kind == OperandKind::reg; // registers first, then temporaries
        }
        if (a.kind == OperandKind::temp) {
            return a.temp_id < b.temp_id;
        }
        if (a.reg != b.reg) {
            return a.reg < b.reg;
        }
        return a.version < b.version;
    });

    return map;
}

} // namespace

const char* data_type_name(DataType type) {
    switch (type) {
    case DataType::unknown:
        return "unknown";
    case DataType::boolean:
        return "bool";
    case DataType::integer:
        return "int";
    case DataType::pointer:
        return "ptr";
    case DataType::conflict:
        return "conflict";
    }
    return "?";
}

DataType TypeMap::type_of(const IrOperand& operand) const {
    if (operand.kind == OperandKind::temp) {
        return type_of_temp(operand.temp_id);
    }
    if (operand.kind == OperandKind::reg) {
        return type_of(operand.reg, operand.version);
    }
    return DataType::unknown;
}

DataType TypeMap::type_of(const std::string& reg, unsigned version) const {
    const std::string canon = canonical(reg);
    for (const ValueType& value : values) {
        if (value.kind == OperandKind::reg && value.version == version && value.reg == canon) {
            return value.type;
        }
    }
    return DataType::unknown;
}

DataType TypeMap::type_of_temp(unsigned id) const {
    for (const ValueType& value : values) {
        if (value.kind == OperandKind::temp && value.temp_id == id) {
            return value.type;
        }
    }
    return DataType::unknown;
}

std::size_t TypeMap::conflicts() const {
    std::size_t count = 0;
    for (const ValueType& value : values) {
        count += value.type == DataType::conflict ? 1 : 0;
    }
    return count;
}

TypeMap infer_data_types(const SsaFunction& fn) {
    TypeScan scan(fn);
    return scan.run();
}

} // namespace minidec
