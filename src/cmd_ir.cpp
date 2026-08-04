#include "minidec/commands.h"

#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "minidec/disasm.h"
#include "minidec/ir.h"
#include "minidec/lift.h"
#include "minidec/loader.h"

namespace minidec {

namespace {

// Same 16-hex-digit addresses the disasm and cfg listings print.
std::string format_addr(std::uint64_t addr) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(addr));
    return std::string(buf);
}

// Find the code section. ELF calls it ".text", Mach-O "__TEXT,__text".
const Section* find_text_section(const Binary& bin) {
    for (const Section& sec : bin.sections) {
        if (sec.name == ".text" || sec.name.find("__text") != std::string::npos) {
            return &sec;
        }
    }
    return nullptr;
}

// Temporaries print as t0, t1; inside the IR they're just an id.
std::string format_operand(const IrOperand& operand) {
    switch (operand.kind) {
    case OperandKind::none:
        return "";
    case OperandKind::reg:
        return operand.reg;
    case OperandKind::temp:
        return "t" + std::to_string(operand.temp_id);
    case OperandKind::imm: {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(operand.imm));
        return std::string(buf);
    }
    }
    return "?";
}

// Written the way an assignment reads. The width goes on the opcode rather than
// each operand: it's the operation's anyway, and where the two disagree -- a cmp,
// a trunc -- the operation's is the one that says what happened.
std::string format_inst(const IrInst& inst) {
    std::string line;

    if (inst.writes_result()) {
        line += format_operand(inst.dst);
        line += " = ";
    }

    line += opcode_name(inst.op);
    line += ".";
    line += type_name(inst.type);

    for (std::size_t i = 0; i < inst.args.size(); ++i) {
        line += i == 0 ? " " : ", ";
        line += format_operand(inst.args[i]);
    }

    return line;
}

}  // namespace

int cmd_ir(const ParsedArgs& args) {
    if (args.positionals.empty()) {
        std::cerr << "ir: no input file given\n";
        std::cerr << "usage: minidec ir <file> --func <name>\n";
        return 1;
    }

    std::string func = args.option("func");
    if (func.empty()) {
        std::cerr << "ir: no function given (pass --func <name>)\n";
        return 1;
    }

    const std::string& path = args.positionals.front();
    std::optional<Binary> bin = load_binary(path);
    if (!bin) {
        std::cerr << "ir: could not load '" << path << "'\n";
        return 1;
    }

    const Symbol* sym = bin->symbol_by_name(func);
    if (!sym) {
        std::cerr << "ir: no symbol named '" << func << "'\n";
        return 1;
    }
    if (sym->size == 0) {
        std::cerr << "ir: '" << func << "' has no size, can't tell where it ends\n";
        return 1;
    }

    const Section* sec = find_text_section(*bin);
    if (!sec) {
        std::cerr << "ir: no text section to read code from\n";
        return 1;
    }
    if (!sec->contains(sym->address)) {
        std::cerr << "ir: '" << func << "' doesn't land in the text section\n";
        return 1;
    }

    std::uint64_t offset = sym->address - sec->address;
    std::uint64_t end = offset + sym->size;
    if (offset >= sec->bytes.size() || end > sec->bytes.size()) {
        std::cerr << "ir: '" << func << "' runs past the bytes in section " << sec->name << "\n";
        return 1;
    }

    // Intel: that's the spelling the lifter parses.
    Disassembler dis(Syntax::intel);
    if (!dis.is_open()) {
        std::cerr << "ir: couldn't start the disassembler\n";
        return 1;
    }

    std::vector<Instruction> insns =
        dis.disassemble(sec->bytes.data() + offset, sym->size, sym->address);
    if (insns.empty()) {
        std::cerr << "ir: nothing decoded for '" << func << "'\n";
        return 1;
    }

    std::cout << func << ":\n";

    // One Lifter per function, so temp numbering runs straight through.
    Lifter lifter;
    std::size_t unknowns = 0;

    for (const Instruction& insn : insns) {
        std::cout << "\n" << format_addr(insn.address) << "  " << insn.mnemonic;
        if (!insn.op_str.empty()) {
            std::cout << " " << insn.op_str;
        }
        std::cout << "\n";

        for (const IrInst& ir : lifter.lift(insn)) {
            if (ir.op == Opcode::unknown) {
                ++unknowns;
            }
            std::cout << "    " << format_inst(ir) << "\n";
        }
    }

    // A function with many unknowns hasn't really been lifted, and the listing
    // would mislead without saying so.
    std::cout << "\n" << insns.size() << " instructions, " << lifter.temp_count()
              << " temporaries, " << unknowns << " not modelled\n";

    return 0;
}

}  // namespace minidec
