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

// Same 16-hex-digit address format the symbols listing uses, kept here so the
// two commands print addresses the same way.
std::string format_addr(std::uint64_t addr) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(addr));
    return std::string(buf);
}

// Turn the raw instruction bytes into "48 89 e5" style hex, one space between
// bytes. objdump prints them this way and it's handy when you want to eyeball
// the encoding, so we do the same.
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

// Find the code section. ELF calls it ".text", Mach-O names it "__TEXT,__text",
// so match either. Returns nullptr if there's no text section.
//
// We go straight for .text instead of hunting for whichever section covers the
// address because in a relocatable .o every section still sits at address 0, so
// an address lookup would happily grab .strtab or .data instead. Functions live
// in the code section anyway, and a symbol's address there is just its offset
// into it, which is exactly what we need to slice the bytes.
const Section* find_text_section(const Binary& bin) {
    for (const Section& sec : bin.sections) {
        if (sec.name == ".text" || sec.name.find("__text") != std::string::npos) {
            return &sec;
        }
    }
    return nullptr;
}

// ANSI color for a control-flow instruction, or an empty string for the plain
// ones. calls, jumps and returns each get their own color so they pop out when
// you're scanning a listing. Returns a std::string so the caller can just check
// .empty() and not worry about whether to print a reset afterwards.
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

// For a direct call/jmp, capstone hands us the target as a plain address in the
// operand string (e.g. "0x1140"). Try to match that address to a symbol so we
// can print its name next to the operand, the way objdump does. Returns the
// name, or "" when this isn't a direct branch or nothing in the table sits on
// that address.
std::string resolve_target(const Binary& bin, const Instruction& insn) {
    // Only direct branches carry an address we can resolve. Indirect ones (call
    // rax, jmp [rip+..]) have a register or memory operand instead, so skip them.
    if (!insn.is_relative || !(insn.is_call || insn.is_jump)) {
        return "";
    }

    // strtoull instead of stoull so a weird operand can't throw at us. If it
    // doesn't consume the whole string it wasn't a bare address, so don't trust
    // the result.
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

    // --func is required; without a function name we don't know what to decode.
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

    // A size of zero means the symbol table never recorded how long the function
    // is, so we've got no byte range to hand to capstone. Bail rather than guess.
    if (sym->size == 0) {
        std::cerr << "disasm: '" << func << "' has no size, can't tell where it ends\n";
        return 1;
    }

    // Work out the syntax before we touch the binary so a typo fails fast. No
    // --syntax means Intel; anything other than the two we know about is a user
    // mistake worth pointing out rather than silently ignoring.
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

    // Work out where the function sits inside the section's bytes. The section's
    // virtual address maps to bytes[0], so subtract to get the offset. Guard the
    // end against the bytes we actually have -- a stripped or bogus size could
    // run past what we copied, and slicing past the buffer would read garbage.
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

    // The address is a fixed 16 digits, but the byte column and the mnemonic both
    // vary in width from one function to the next, so measure them first and pad
    // every row to the widest one. Same trick the symbols listing uses. Operands
    // go last so they don't need padding.
    std::vector<std::string> byte_cols;
    byte_cols.reserve(insns.size());
    std::size_t byte_w = 0;
    std::size_t mnem_w = 0;
    for (const Instruction& insn : insns) {
        byte_cols.push_back(format_bytes(insn.bytes));
        byte_w = std::max(byte_w, byte_cols.back().size());
        mnem_w = std::max(mnem_w, insn.mnemonic.size());
    }

    // Color is on by default but we skip it when --no-color is passed or when
    // stdout isn't a terminal (piped to a file or another program), otherwise the
    // escape codes end up as junk in the redirected output.
    bool use_color = !args.has_option("no-color") && isatty(STDOUT_FILENO);

    std::cout << func << ":\n";
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const Instruction& insn = insns[i];
        std::cout << format_addr(insn.address) << ":  " << std::left
                  << std::setw(static_cast<int>(byte_w)) << byte_cols[i] << "  ";

        // Can't hand the colored mnemonic to std::setw: it counts the escape
        // characters too and the padding comes out wrong. So print the color,
        // the mnemonic, the reset, then pad by hand to the real text width.
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

            // Tack on the symbol name for a direct call/jmp so you can read
            // "call 0x1140 <puts>" instead of chasing the bare address.
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
