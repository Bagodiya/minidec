#include "minidec/commands.h"

#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

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

    Disassembler dis;
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

    // Plain one-line-per-instruction dump for now. Making it line up in neat
    // columns (and showing the raw bytes) is the next step's job.
    std::cout << func << ":\n";
    for (const Instruction& insn : insns) {
        std::cout << format_addr(insn.address) << ": " << insn.mnemonic;
        if (!insn.op_str.empty()) {
            std::cout << " " << insn.op_str;
        }
        std::cout << "\n";
    }

    return 0;
}

}  // namespace minidec
