#include "minidec/usedef.h"

#include <string>
#include <string_view>
#include <unordered_map>

namespace minidec {

namespace {

// al, ax and eax are three views of rax, so a write through any of them has to
// end the chain the others were reading. Fold every spelling onto the 64-bit
// name; anything missing from the table -- the flags, rip -- is already a whole
// register and comes back unchanged.
//
// Exact for the 32-bit forms, which zero the top half anyway. For the 8- and
// 16-bit ones it's an approximation: writing al leaves the rest of rax alone,
// but the chain will say the whole register came from that write. Compilers
// hardly ever read a wider register straight after a narrow write, so it's a
// cheap price for keeping one entry per register.
std::string_view whole_register(std::string_view name) {
    static const std::unordered_map<std::string_view, std::string_view> parts = {
        {"eax", "rax"}, {"ebx", "rbx"}, {"ecx", "rcx"}, {"edx", "rdx"},
        {"esi", "rsi"}, {"edi", "rdi"}, {"ebp", "rbp"}, {"esp", "rsp"},

        {"ax", "rax"},  {"bx", "rbx"},  {"cx", "rcx"},  {"dx", "rdx"},
        {"si", "rsi"},  {"di", "rdi"},  {"bp", "rbp"},  {"sp", "rsp"},

        {"al", "rax"},  {"bl", "rbx"},  {"cl", "rcx"},  {"dl", "rdx"},
        {"ah", "rax"},  {"bh", "rbx"},  {"ch", "rcx"},  {"dh", "rdx"},
        {"sil", "rsi"}, {"dil", "rdi"}, {"bpl", "rbp"}, {"spl", "rsp"},
    };

    auto it = parts.find(name);
    if (it != parts.end()) {
        return it->second;
    }

    // r8 through r15 spell their width as a suffix, so one rule covers the
    // twenty-four names the table would otherwise have to list.
    if (name.size() < 3 || name.front() != 'r') {
        return name;
    }
    char suffix = name.back();
    if (suffix != 'd' && suffix != 'w' && suffix != 'b') {
        return name;
    }
    for (char c : name.substr(1, name.size() - 2)) {
        if (c < '0' || c > '9') {
            return name;
        }
    }
    return name.substr(0, name.size() - 1);
}

// What the System V convention lets a call leave changed. The callee has to put
// rbx, rbp, rsp and r12-r15 back before it returns, so those chains carry on
// across the call; every other register, flags included, has to stop there.
const std::vector<std::string>& caller_saved() {
    static const std::vector<std::string> registers = {
        "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
        "cf",  "pf",  "af",  "zf",  "sf",  "of",
    };
    return registers;
}

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
            for (const std::string& reg : caller_saved()) {
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
