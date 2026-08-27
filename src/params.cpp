#include "minidec/params.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include "minidec/lift.h"

namespace minidec {

namespace {

// System V hands the integer arguments over in these, in this order. The order
// is the only reason a skipped argument can be spotted at all, so it matters
// more here than the names do. lift.cpp keeps the same list for the calling
// side; the two have to agree, since one is reading back what the other wrote.
const char* const argument_registers[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

constexpr std::size_t argument_count = sizeof(argument_registers) / sizeof(argument_registers[0]);

std::string canonical(const std::string& reg) {
    return std::string(whole_register(reg));
}

// Where in the fill order a register sits, or -1 if arguments never arrive in
// it.
int argument_index(const std::string& canon) {
    for (std::size_t i = 0; i < argument_count; ++i) {
        if (canon == argument_registers[i]) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

class ParamScan {
public:
    explicit ParamScan(const SsaFunction& fn) : fn_(fn) {}

    ParamList run();

private:
    void scan();

    // A read that counts. `where` arrives filled in except for the width, which
    // only the operand knows.
    void note(const IrOperand& operand, const ParamRead& where);

    // A read that doesn't: an argument slot of a call the lifter filled in
    // blind.
    void note_forward(const IrOperand& operand);

    const SsaFunction& fn_;

    std::array<std::vector<ParamRead>, argument_count> reads_;
    std::array<bool, argument_count> forwarded_{};
};

void ParamScan::note(const IrOperand& operand, const ParamRead& where) {
    if (operand.kind != OperandKind::reg || operand.version != 0) {
        return;
    }

    const int index = argument_index(canonical(operand.reg));
    if (index < 0) {
        return;
    }

    ParamRead read = where;
    read.width = type_bits(operand.type);
    reads_[static_cast<std::size_t>(index)].push_back(read);
}

void ParamScan::note_forward(const IrOperand& operand) {
    if (operand.kind != OperandKind::reg || operand.version != 0) {
        return;
    }

    const int index = argument_index(canonical(operand.reg));
    if (index >= 0) {
        forwarded_[static_cast<std::size_t>(index)] = true;
    }
}

void ParamScan::scan() {
    for (const SsaBlock& block : fn_.blocks) {
        // A phi argument is a read like any other: the entry value got as far as
        // a join still holding something worth merging. There is no instruction
        // behind it, so `inst` counts phis rather than code.
        for (std::size_t p = 0; p < block.phis.size(); ++p) {
            const SsaPhi& phi = block.phis[p];
            for (std::size_t a = 0; a < phi.incoming.size(); ++a) {
                ParamRead read;
                read.block = block.start;
                read.inst = p;
                read.arg = a;
                read.is_phi = true;
                note(phi.incoming[a], read);
            }
        }

        for (std::size_t i = 0; i < block.code.size(); ++i) {
            const IrInst& inst = block.code[i];

            for (std::size_t a = 0; a < inst.args.size(); ++a) {
                // Argument 0 of a call is the target, which is a real read --
                // "call rdi" is this function calling a function pointer it was
                // handed. Everything after it is the lifter's guess at what the
                // callee wants and says nothing about what we were given.
                if (inst.op == Opcode::call && a > 0) {
                    note_forward(inst.args[a]);
                    continue;
                }

                ParamRead read;
                read.block = block.start;
                read.inst = i;
                read.arg = a;
                read.address = inst.address;
                note(inst.args[a], read);
            }
        }
    }
}

ParamList ParamScan::run() {
    scan();

    ParamList result;

    // Before anything moves out of reads_, since a register can be both read for
    // real and passed on to a callee, and that one is not forwarded-only.
    for (std::size_t i = 0; i < argument_count; ++i) {
        if (forwarded_[i] && reads_[i].empty()) {
            result.forwarded.push_back(argument_registers[i]);
        }
    }

    // The last register anything reads fixes the count. Everything below it was
    // passed too, whether or not the function ever looks at it.
    int last = -1;
    for (std::size_t i = 0; i < argument_count; ++i) {
        if (!reads_[i].empty()) {
            last = static_cast<int>(i);
        }
    }

    for (int i = 0; i <= last; ++i) {
        const std::size_t slot = static_cast<std::size_t>(i);

        Parameter param;
        param.index = static_cast<unsigned>(i);
        param.reg = argument_registers[slot];
        param.reads = std::move(reads_[slot]);

        for (const ParamRead& read : param.reads) {
            param.width = std::max(param.width, read.width);
        }

        result.params.push_back(std::move(param));
    }

    return result;
}

} // namespace

const Parameter* ParamList::at(unsigned index) const {
    if (index >= params.size()) {
        return nullptr;
    }
    return &params[index];
}

const Parameter* ParamList::find(const std::string& reg) const {
    const std::string canon = canonical(reg);
    for (const Parameter& param : params) {
        if (param.reg == canon) {
            return &param;
        }
    }
    return nullptr;
}

ParamList recover_parameters(const SsaFunction& fn) {
    return ParamScan(fn).run();
}

} // namespace minidec
