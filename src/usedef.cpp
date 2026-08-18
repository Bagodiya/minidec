#include "minidec/usedef.h"

#include <string>
#include <string_view>
#include <unordered_map>

#include "minidec/lift.h"

namespace minidec {

namespace {

// Only registers and temporaries flow from one operation to another. A constant
// carries its own value and an empty slot isn't read at all.
bool is_value(const IrOperand& operand) {
    return operand.kind == OperandKind::reg || operand.kind == OperandKind::temp;
}

bool same_value(const IrOperand& a, const IrOperand& b) {
    if (a.kind != b.kind) {
        return false;
    }
    if (a.kind == OperandKind::reg) {
        return whole_register(a.reg) == whole_register(b.reg);
    }
    return a.temp_id == b.temp_id;
}

}  // namespace

const Def* UseDefChains::reaching_def(std::size_t inst, std::size_t arg) const {
    if (inst >= reaching.size() || arg >= reaching[inst].size()) {
        return nullptr;
    }
    std::size_t index = reaching[inst][arg];
    return index == none ? nullptr : &defs[index];
}

const Def* UseDefChains::def_written_by(std::size_t inst) const {
    if (inst >= written.size()) {
        return nullptr;
    }
    std::size_t index = written[inst];
    return index == none ? nullptr : &defs[index];
}

UseDefChains compute_use_def(const std::vector<IrInst>& code) {
    UseDefChains chains;
    chains.reaching.resize(code.size());
    chains.written.assign(code.size(), UseDefChains::none);

    // What each value currently holds, as an index into chains.defs. Registers
    // and temporaries are kept apart because a call and an unknown wipe out the
    // registers on their own -- nothing outside the lifter can name a temporary,
    // so those survive both.
    std::unordered_map<std::string, std::size_t> registers;
    std::unordered_map<unsigned, std::size_t> temporaries;

    for (std::size_t i = 0; i < code.size(); ++i) {
        const IrInst& inst = code[i];
        chains.reaching[i].assign(inst.args.size(), UseDefChains::none);

        // Reads first, then the write. Most operations the lifter emits don't
        // do both, but the two-operand imul reads and writes eax in one go, and
        // what it reads is the value from before.
        for (std::size_t a = 0; a < inst.args.size(); ++a) {
            const IrOperand& arg = inst.args[a];
            if (!is_value(arg)) {
                continue;
            }

            std::size_t def = UseDefChains::none;
            if (arg.kind == OperandKind::reg) {
                auto it = registers.find(std::string(whole_register(arg.reg)));
                if (it != registers.end()) {
                    def = it->second;
                }
            } else {
                auto it = temporaries.find(arg.temp_id);
                if (it != temporaries.end()) {
                    def = it->second;
                }
            }

            if (def == UseDefChains::none) {
                // Nothing here wrote it, so it came in from outside. Only worth
                // recording the first read: the ones after it say the same.
                bool known = false;
                for (const IrOperand& value : chains.live_in) {
                    if (same_value(value, arg)) {
                        known = true;
                        break;
                    }
                }
                if (!known) {
                    chains.live_in.push_back(arg);
                }
                continue;
            }

            chains.reaching[i][a] = def;
            chains.defs[def].uses.push_back(Use{i, a});
        }

        // An unknown is an instruction the lifter couldn't model, so there's no
        // saying which registers it left alone. Ending every chain here costs a
        // few missed links; carrying them on would hand out values that may
        // already have been overwritten.
        if (inst.op == Opcode::unknown) {
            registers.clear();
        } else if (inst.op == Opcode::call) {
            // Same reasoning, but the convention says exactly how much of the
            // damage to expect. rax is wiped along with the rest and then
            // written again below, since that's where the result comes back.
            for (const std::string& reg : caller_saved_registers()) {
                registers.erase(reg);
            }
        }

        if (!inst.writes_result() || !is_value(inst.dst)) {
            continue;
        }

        Def def;
        def.inst = i;
        def.value = inst.dst;
        chains.defs.push_back(std::move(def));

        std::size_t index = chains.defs.size() - 1;
        chains.written[i] = index;
        if (inst.dst.kind == OperandKind::reg) {
            registers[std::string(whole_register(inst.dst.reg))] = index;
        } else {
            temporaries[inst.dst.temp_id] = index;
        }
    }

    return chains;
}

}  // namespace minidec
