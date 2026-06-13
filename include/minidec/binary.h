#ifndef MINIDEC_BINARY_H
#define MINIDEC_BINARY_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace minidec {

// Which executable format a Binary was loaded from. We figure this out from the
// file's magic bytes when it's opened (phase 2).
enum class Format {
    Unknown,
    Elf,
    MachO,
};

// Rough bucket for a symbol. Mostly we just need to tell code (Function) apart
// from data (Object); everything we can't classify ends up in Other.
enum class SymbolKind {
    Function,
    Object,
    Other,
};

// A named region of the binary, e.g. ".text" or "__TEXT,__text". The addresses
// here are the virtual addresses the loader would map the section to at runtime.
struct Section {
    std::string name;
    std::uint64_t address = 0;      // virtual address of the first byte
    std::uint64_t size = 0;         // size of the section in bytes
    std::uint64_t file_offset = 0;  // where the bytes sit inside the file
    std::vector<std::uint8_t> bytes;  // raw contents, filled in when we have them

    // True if addr falls inside [address, address + size).
    bool contains(std::uint64_t addr) const {
        return addr >= address && addr < address + size;
    }
};

// One entry of the symbol table: a name pinned to an address, plus its size and
// a guess at whether it points at code or data.
struct Symbol {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    SymbolKind kind = SymbolKind::Other;
};

// Everything we managed to pull out of a binary file. Owns its sections and
// symbols. This is the hand-off point between the loaders and the analysis
// passes that come later.
struct Binary {
    Format format = Format::Unknown;
    std::string path;  // path the binary was loaded from
    std::uint64_t entry_point = 0;
    std::uint64_t file_size = 0;  // size of the file on disk, in bytes
    std::string arch;             // target architecture, e.g. "x86_64"; empty if unknown
    std::vector<Section> sections;
    std::vector<Symbol> symbols;

    // Find a section by exact name (e.g. ".text"). Returns nullptr if there's
    // no such section.
    const Section* section_by_name(std::string_view name) const {
        for (const auto& sec : sections) {
            if (sec.name == name) {
                return &sec;
            }
        }
        return nullptr;
    }

    // Look up a symbol by exact name. The disasm/cfg commands lean on this to
    // resolve a --func argument to an address range.
    const Symbol* symbol_by_name(std::string_view name) const {
        for (const auto& sym : symbols) {
            if (sym.name == name) {
                return &sym;
            }
        }
        return nullptr;
    }
};

}  // namespace minidec

#endif  // MINIDEC_BINARY_H
