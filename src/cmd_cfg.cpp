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

// Same addresses the disasm listing prints, so headers line up with instructions.
std::string format_addr(std::uint64_t addr) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(addr));
    return std::string(buf);
}

// ELF calls it ".text", Mach-O "__TEXT,__text". Same reasoning as cmd_disasm.
const Section* find_text_section(const Binary& bin) {
    for (const Section& sec : bin.sections) {
        if (sec.name == ".text" || sec.name.find("__text") != std::string::npos) {
            return &sec;
        }
    }
    return nullptr;
}

// One instruction, mnemonic padded to `mnem_w`. Both output formats use this.
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

// Graphviz reads a quoted label to the closing quote, so backslashes and quotes
// inside need escaping. AT&T operands and .byte placeholders can carry both.
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

        // A ret, or a branch we couldn't follow. Say so rather than print nothing.
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

// Block addresses to sorted b-numbers. The sets are unordered, so without this
// the same function prints its dominators differently each run.
std::vector<std::size_t> numbered(const std::unordered_set<std::uint64_t>& addresses,
                                  const std::unordered_map<std::uint64_t, std::size_t>& index) {
    std::vector<std::size_t> out;
    out.reserve(addresses.size());
    for (std::uint64_t address : addresses) {
        auto it = index.find(address);
        if (it != index.end()) {
            out.push_back(it->second);
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

void print_blocks(const std::vector<std::size_t>& blocks) {
    for (std::size_t b : blocks) {
        std::cout << " b" << b;
    }
}

// Which blocks dominate each block. Reads as "you cannot reach b3 without going
// through b0 and b1 first".
void emit_dominators(const CFG& cfg,
                     const std::unordered_map<std::uint64_t, std::size_t>& block_index) {
    DominatorSets dominators = compute_dominators(cfg);

    std::cout << "\ndominators:\n";
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        auto found = dominators.find(cfg.blocks[i].start);
        std::cout << "  b" << i << " <-";
        if (found == dominators.end()) {
            std::cout << " (none)";
        } else {
            print_blocks(numbered(found->second, block_index));
        }
        std::cout << "\n";
    }
}

// Every natural loop, i.e. every back edge and the blocks it wraps around.
void emit_loops(const CFG& cfg,
                const std::unordered_map<std::uint64_t, std::size_t>& block_index) {
    DominatorSets dominators = compute_dominators(cfg);
    std::vector<NaturalLoop> loops = find_natural_loops(cfg, dominators);

    std::cout << "\nloops: " << loops.size() << "\n";
    for (const NaturalLoop& loop : loops) {
        auto header = block_index.find(loop.header);
        auto latch = block_index.find(loop.latch);
        if (header == block_index.end() || latch == block_index.end()) {
            continue;
        }

        std::cout << "  header b" << header->second << ", latch b" << latch->second << ", body";
        print_blocks(numbered(loop.body, block_index));
        std::cout << "\n";
    }
}

// The order a forward dataflow pass should walk the blocks in.
void emit_reverse_postorder(const CFG& cfg,
                            const std::unordered_map<std::uint64_t, std::size_t>& block_index) {
    std::vector<std::uint64_t> order = compute_reverse_postorder(cfg);

    std::cout << "\nreverse postorder:";
    for (std::uint64_t address : order) {
        auto it = block_index.find(address);
        if (it != block_index.end()) {
            std::cout << " b" << it->second;
        }
    }
    std::cout << "\n";
}

// The graph as Graphviz, for `dot -Tpng`.
//
// "\l" is the line break that also left-aligns; a plain "\n" centres every
// instruction and the result is unreadable.
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

        // Heavier border on the entry: dot's top-down layout isn't a promise.
        if (block.start == cfg.entry) {
            std::cout << ", penwidth=2";
        }
        std::cout << "];\n";
    }

    std::cout << "\n";
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        const BasicBlock& block = cfg.blocks[i];

        // connect_blocks pushes target then fall-through, so two edges means a
        // conditional and the sides can be labelled without re-reading the terminator.
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
        std::cerr << "       [--dominators] [--loops] [--rpo] [--all]\n";
        return 1;
    }

    std::string func = args.option("func");
    if (func.empty()) {
        std::cerr << "cfg: no function given (pass --func <name>)\n";
        return 1;
    }

    // Checked before loading, so a typo fails straight away.
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

    // Virtual address maps to bytes[0]. Guard the end against a bogus size.
    std::uint64_t offset = sym->address - sec->address;
    std::uint64_t end = offset + sym->size;
    if (offset >= sec->bytes.size() || end > sec->bytes.size()) {
        std::cerr << "cfg: '" << func << "' runs past the bytes in section " << sec->name << "\n";
        return 1;
    }

    // Intel only: the CFG doesn't care about dialect, and jump_target() reads a
    // bare address either way.
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

    // Successors are stored as addresses, so map them back to the b-numbers.
    std::unordered_map<std::uint64_t, std::size_t> block_index;
    block_index.reserve(cfg.blocks.size());
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        block_index[cfg.blocks[i].start] = i;
    }

    // Widest mnemonic in the function, so the operand column doesn't jump per block.
    std::size_t mnem_w = 0;
    for (const Instruction& insn : insns) {
        mnem_w = std::max(mnem_w, insn.mnemonic.size());
    }

    if (as_dot) {
        emit_dot(cfg, func, block_index, mnem_w);
        return 0;
    }

    emit_text(cfg, func, block_index, mnem_w);

    // Opt-in: the dominator listing outgrows the graph it describes fast.
    bool all = args.has_option("all");
    if (all || args.has_option("dominators")) {
        emit_dominators(cfg, block_index);
    }
    if (all || args.has_option("loops")) {
        emit_loops(cfg, block_index);
    }
    if (all || args.has_option("rpo")) {
        emit_reverse_postorder(cfg, block_index);
    }

    return 0;
}

}  // namespace minidec
