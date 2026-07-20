#include "minidec/commands.h"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "minidec/cfg.h"
#include "minidec/disasm.h"
#include "minidec/loader.h"

namespace minidec {

namespace {

// Same 16-hex-digit addresses the disasm and symbols listings print, so a block
// header lines up with the instructions underneath it.
std::string format_addr(std::uint64_t addr) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(addr));
    return std::string(buf);
}

// Find the code section. ELF calls it ".text", Mach-O "__TEXT,__text". Same
// reasoning as in cmd_disasm: go straight for the code section rather than
// looking up whichever section covers the symbol's address, because in a
// relocatable .o every section still starts at address 0.
const Section* find_text_section(const Binary& bin) {
    for (const Section& sec : bin.sections) {
        if (sec.name == ".text" || sec.name.find("__text") != std::string::npos) {
            return &sec;
        }
    }
    return nullptr;
}

}  // namespace

int cmd_cfg(const ParsedArgs& args) {
    if (args.positionals.empty()) {
        std::cerr << "cfg: no input file given\n";
        std::cerr << "usage: minidec cfg <file> --func <name>\n";
        return 1;
    }

    std::string func = args.option("func");
    if (func.empty()) {
        std::cerr << "cfg: no function given (pass --func <name>)\n";
        return 1;
    }

    const std::string& path = args.positionals.front();
    std::optional<Binary> bin = load_binary(path);
    if (!bin) {
        std::cerr << "cfg: could not load '" << path << "'\n";
        return 1;
    }

    const Symbol* sym = bin->symbol_by_name(func);
    if (!sym) {
        std::cerr << "cfg: no symbol named '" << func << "'\n";
        return 1;
    }
    if (sym->size == 0) {
        std::cerr << "cfg: '" << func << "' has no size, can't tell where it ends\n";
        return 1;
    }

    const Section* sec = find_text_section(*bin);
    if (!sec) {
        std::cerr << "cfg: no text section to read code from\n";
        return 1;
    }
    if (!sec->contains(sym->address)) {
        std::cerr << "cfg: '" << func << "' doesn't land in the text section\n";
        return 1;
    }

    // The section's virtual address maps to bytes[0], so subtracting gives the
    // offset of the function inside the copy we hold. Check the end against the
    // bytes we really have -- a bogus symbol size would otherwise read past them.
    std::uint64_t offset = sym->address - sec->address;
    std::uint64_t end = offset + sym->size;
    if (offset >= sec->bytes.size() || end > sec->bytes.size()) {
        std::cerr << "cfg: '" << func << "' runs past the bytes in section " << sec->name << "\n";
        return 1;
    }

    // Intel syntax only here. The CFG doesn't care which dialect the operands are
    // printed in, and jump_target() in cfg.cpp reads the target off the operand
    // text, which capstone writes as a bare address either way.
    Disassembler dis(Syntax::intel);
    if (!dis.is_open()) {
        std::cerr << "cfg: couldn't start the disassembler\n";
        return 1;
    }

    std::vector<Instruction> insns =
        dis.disassemble(sec->bytes.data() + offset, sym->size, sym->address);
    if (insns.empty()) {
        std::cerr << "cfg: nothing decoded for '" << func << "'\n";
        return 1;
    }

    CFG cfg;
    cfg.blocks = group_into_blocks(insns);
    connect_blocks(cfg.blocks);
    if (cfg.empty()) {
        std::cerr << "cfg: no basic blocks built for '" << func << "'\n";
        return 1;
    }
    cfg.entry = cfg.blocks.front().start;

    // Blocks get printed as b0, b1, ... in address order, which reads a lot better
    // than a bare address in the successor lists. Successors are stored as
    // addresses, so keep a map from start address back to the number we gave it.
    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(cfg.blocks.size());
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        block_index[cfg.blocks[i].start] = i;
    }

    // Pad the mnemonics to the widest one in the whole function so the operand
    // column stays put across blocks instead of jumping around per block.
    std::size_t mnem_w = 0;
    for (const Instruction& insn : insns) {
        mnem_w = std::max(mnem_w, insn.mnemonic.size());
    }

    std::cout << func << ": " << cfg.size() << (cfg.size() == 1 ? " block\n" : " blocks\n");

    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        const BasicBlock& block = cfg.blocks[i];

        std::cout << "\nb" << i << " [" << format_addr(block.start) << " - "
                  << format_addr(block.end) << ")";
        if (block.start == cfg.entry) {
            std::cout << "  entry";
        }
        std::cout << "\n";

        for (const Instruction& insn : block.instructions) {
            std::cout << "  " << format_addr(insn.address) << ":  " << std::left
                      << std::setw(static_cast<int>(mnem_w)) << insn.mnemonic;
            if (!insn.op_str.empty()) {
                std::cout << "  " << insn.op_str;
            }
            std::cout << "\n";
        }

        // No successors means the block ends the function, either on a ret or on a
        // branch we couldn't follow. Say so rather than printing an empty list.
        if (block.successors.empty()) {
            std::cout << "  -> (none)\n";
            continue;
        }

        std::cout << "  ->";
        for (std::uint64_t succ : block.successors) {
            auto it = block_index.find(succ);
            if (it == block_index.end()) {
                // connect_blocks only ever points at a block start, so this
                // shouldn't happen -- print the address rather than pretend.
                std::cout << " " << format_addr(succ);
            } else {
                std::cout << " b" << it->second;
            }
        }
        std::cout << "\n";
    }

    return 0;
}

}  // namespace minidec
