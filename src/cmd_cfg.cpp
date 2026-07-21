#include "minidec/commands.h"

#include <algorithm>
#include <cstdio>
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

// One instruction as a single line of text, mnemonic padded out to `mnem_w` so
// the operands line up under each other. Both output formats want the same line,
// the text one prints it directly and the dot one packs it into a node label.
std::string format_insn(const Instruction& insn, std::size_t mnem_w) {
    std::string line = insn.mnemonic;
    if (!insn.op_str.empty()) {
        if (line.size() < mnem_w) {
            line += std::string(mnem_w - line.size(), ' ');
        }
        line += "  ";
        line += insn.op_str;
    }
    return line;
}

// Graphviz reads a quoted label until the closing quote, so a backslash or a
// quote inside one has to be escaped or the file won't parse. Operand text is
// nearly always plain, but AT&T-style operands and the .byte placeholders we
// emit for undecodable bytes can carry either, so don't assume.
std::string escape_label(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    return out;
}

// The textual listing: every block with its instructions and where it goes next.
void emit_text(const CFG& cfg, const std::string& func,
               const std::unordered_map<std::uint64_t, std::size_t>& block_index,
               std::size_t mnem_w) {
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
            std::cout << "  " << format_addr(insn.address) << ":  " << format_insn(insn, mnem_w)
                      << "\n";
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
}

// The same graph as a Graphviz file, so you can run it through
// `dot -Tpng` and actually look at the shape of a function.
//
// Blocks come out as left-aligned boxes in a fixed-width font: "\l" is graphviz's
// line break that also left-aligns the line it ends, which a plain "\n" doesn't
// do, and without it every instruction ends up centered and unreadable.
void emit_dot(const CFG& cfg, const std::string& func,
              const std::unordered_map<std::uint64_t, std::size_t>& block_index,
              std::size_t mnem_w) {
    std::cout << "digraph \"" << escape_label(func) << "\" {\n";
    std::cout << "  graph [label=\"" << escape_label(func) << "\", labelloc=t];\n";
    std::cout << "  node [shape=box, fontname=\"monospace\"];\n\n";

    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        const BasicBlock& block = cfg.blocks[i];

        std::cout << "  b" << i << " [label=\"b" << i << " (" << format_addr(block.start) << ")\\l";
        for (const Instruction& insn : block.instructions) {
            std::cout << escape_label(format_insn(insn, mnem_w)) << "\\l";
        }
        std::cout << "\"";

        // The entry block gets a heavier border so it's obvious where to start
        // reading; dot lays blocks out top-down but that ordering isn't a promise.
        if (block.start == cfg.entry) {
            std::cout << ", penwidth=2";
        }
        std::cout << "];\n";
    }

    std::cout << "\n";
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        const BasicBlock& block = cfg.blocks[i];

        // connect_blocks pushes the branch target first and the fall-through
        // second, so a block with two edges is a conditional and we can label the
        // two sides without having to look at the terminator again.
        bool conditional = block.successors.size() == 2;

        for (std::size_t s = 0; s < block.successors.size(); ++s) {
            auto it = block_index.find(block.successors[s]);
            if (it == block_index.end()) {
                continue;
            }
            std::cout << "  b" << i << " -> b" << it->second;
            if (conditional) {
                std::cout << " [label=\"" << (s == 0 ? "taken" : "fall") << "\"]";
            }
            std::cout << ";\n";
        }
    }

    std::cout << "}\n";
}

}  // namespace

int cmd_cfg(const ParsedArgs& args) {
    if (args.positionals.empty()) {
        std::cerr << "cfg: no input file given\n";
        std::cerr << "usage: minidec cfg <file> --func <name> [--format text|dot]\n";
        return 1;
    }

    std::string func = args.option("func");
    if (func.empty()) {
        std::cerr << "cfg: no function given (pass --func <name>)\n";
        return 1;
    }

    // Check the format before loading anything so a typo fails straight away
    // instead of after we've parsed a binary. No --format means the text listing.
    bool as_dot = false;
    if (args.has_option("format")) {
        std::string choice = args.option("format");
        if (choice == "dot") {
            as_dot = true;
        } else if (choice != "text") {
            std::cerr << "cfg: unknown --format '" << choice << "' (use text or dot)\n";
            return 1;
        }
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

    if (as_dot) {
        emit_dot(cfg, func, block_index, mnem_w);
    } else {
        emit_text(cfg, func, block_index, mnem_w);
    }

    return 0;
}

}  // namespace minidec
