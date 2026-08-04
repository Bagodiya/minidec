#include "minidec/commands.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>

#include "minidec/disasm.h"
#include "minidec/loader.h"

namespace minidec {

namespace {

// Same format the symbols listing uses.
std::string format_addr(std::uint64_t addr) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(addr));
    return std::string(buf);
}

// "48 89 e5" style hex, the way objdump prints it.
std::string format_bytes(const std::vector<std::uint8_t>& bytes) {
    std::string out;
    out.reserve(bytes.size() * 3);
    char pair[3];
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        std::snprintf(pair, sizeof(pair), "%02x", bytes[i]);
        out += pair;
    }
    return out;
}

// ELF calls it ".text", Mach-O "__TEXT,__text".
//
// Going straight for the code section rather than looking up whichever section
// covers the address: in a relocatable .o every section still starts at 0, so an
// address lookup would happily return .strtab.
const Section* find_text_section(const Binary& bin) {
    for (const Section& sec : bin.sections) {
        if (sec.name == ".text" || sec.name.find("__text") != std::string::npos) {
            return &sec;
        }
    }
    return nullptr;
}

// A colour per control-flow kind, or empty for the plain ones. Returned as a
// string so the caller can check .empty() before printing a reset.
std::string flow_color(const Instruction& insn) {
    if (insn.is_call) {
        return "\033[32m";  // green
    }
    if (insn.is_ret) {
        return "\033[31m";  // red
    }
    if (insn.is_jump) {
        return "\033[33m";  // yellow
    }
    return "";
}

// Match a direct branch's target against the symbol table so the listing can
// print "call 0x1140 <puts>". Empty when it isn't direct or nothing matches.
std::string resolve_target(const Binary& bin, const Instruction& insn) {
    // Indirect branches have a register or memory operand, nothing to resolve.
    if (!insn.is_relative || !(insn.is_call || insn.is_jump)) {
        return "";
    }

    // strtoull so a weird operand can't throw. Partial consumption means it wasn't
    // a bare address.
    const char* start = insn.op_str.c_str();
    char* stop = nullptr;
    std::uint64_t target = std::strtoull(start, &stop, 0);
    if (stop == start || *stop != '\0') {
        return "";
    }

    for (const Symbol& sym : bin.symbols) {
        if (sym.address == target) {
            return sym.name;
        }
    }
    return "";
}

}  // namespace

int cmd_disasm(const ParsedArgs& args) {
    if (args.positionals.empty()) {
        std::cerr << "disasm: no input file given\n";
        std::cerr << "usage: minidec disasm <file> --func <name>\n";
        return 1;
    }


    std::string func = args.option("func");
    if (func.empty()) {
        std::cerr << "disasm: no function given (pass --func <name>)\n";
        return 1;
    }

    const std::string& path = args.positionals.front();
    std::optional<Binary> bin = load_binary(path);
    if (!bin) {
        std::cerr << "disasm: could not load '" << path << "'\n";
        return 1;
    }

    const Symbol* sym = bin->symbol_by_name(func);
    if (!sym) {
        std::cerr << "disasm: no symbol named '" << func << "'\n";
        return 1;
    }

    // No size means no byte range to hand capstone. Bail rather than guess.
    if (sym->size == 0) {
        std::cerr << "disasm: '" << func << "' has no size, can't tell where it ends\n";
        return 1;
    }

    // Check the syntax before loading anything so a typo fails fast.
    Syntax syntax = Syntax::intel;
    if (args.has_option("syntax")) {
        std::string choice = args.option("syntax");
        if (choice == "att") {
            syntax = Syntax::att;
        } else if (choice == "intel") {
            syntax = Syntax::intel;
        } else {
            std::cerr << "disasm: unknown --syntax '" << choice << "' (use att or intel)\n";
            return 1;
        }
    }

    const Section* sec = find_text_section(*bin);
    if (!sec) {
        std::cerr << "disasm: no text section to read code from\n";
        return 1;
    }
    if (!sec->contains(sym->address)) {
        std::cerr << "disasm: '" << func << "' doesn't land in the text section\n";
        return 1;
    }

    // The section's virtual address maps to bytes[0], so subtracting gives the
    // offset. Guard the end: a bogus size would otherwise read past the buffer.
    std::uint64_t offset = sym->address - sec->address;
    std::uint64_t end = offset + sym->size;
    if (offset >= sec->bytes.size() || end > sec->bytes.size()) {
        std::cerr << "disasm: '" << func << "' runs past the bytes in section "
                  << sec->name << "\n";
        return 1;
    }

    Disassembler dis(syntax);
    if (!dis.is_open()) {
        std::cerr << "disasm: couldn't start the disassembler\n";
        return 1;
    }

    std::vector<Instruction> insns =
        dis.disassemble(sec->bytes.data() + offset, sym->size, sym->address);
    if (insns.empty()) {
        std::cerr << "disasm: nothing decoded for '" << func << "'\n";
        return 1;
    }

    // The byte and mnemonic columns vary per function, so measure first and pad to
    // the widest. Operands go last and need no padding.
    std::vector<std::string> byte_cols;
    byte_cols.reserve(insns.size());
    std::size_t byte_w = 0;
    std::size_t mnem_w = 0;
    for (const Instruction& insn : insns) {
        byte_cols.push_back(format_bytes(insn.bytes));
        byte_w = std::max(byte_w, byte_cols.back().size());
        mnem_w = std::max(mnem_w, insn.mnemonic.size());
    }

    // Off when redirected, or the escape codes end up as junk in the output.
    bool use_color = !args.has_option("no-color") && isatty(STDOUT_FILENO);

    std::cout << func << ":\n";
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const Instruction& insn = insns[i];
        std::cout << format_addr(insn.address) << ":  " << std::left
                  << std::setw(static_cast<int>(byte_w)) << byte_cols[i] << "  ";

        // setw counts the escape characters, so pad by hand to the real width.
        std::string color = use_color ? flow_color(insn) : "";
        std::cout << color << insn.mnemonic;
        if (!color.empty()) {
            std::cout << "\033[0m";
        }
        if (insn.mnemonic.size() < mnem_w) {
            std::cout << std::string(mnem_w - insn.mnemonic.size(), ' ');
        }

        if (!insn.op_str.empty()) {
            std::cout << "  " << insn.op_str;


            std::string target = resolve_target(*bin, insn);
            if (!target.empty()) {
                std::cout << " <" << target << ">";
            }
        }
        std::cout << "\n";
    }

    return 0;
}

}  // namespace minidec
