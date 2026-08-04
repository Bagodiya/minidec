#ifndef MINIDEC_BINARY_H
#define MINIDEC_BINARY_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace minidec {

// Which executable format a Binary was loaded from. We figure this out from the
// file's magic bytes when it's opened.
enum class Format {
    Unknown,
    Elf,
    MachO,
};

// Code (Function) against data (Object); anything else lands in Other.
enum class SymbolKind {
    Function,
    Object,
    Other,
};

// A named region, e.g. ".text" or "__TEXT,__text". Addresses are the virtual
// ones the loader would map to.
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

// A name pinned to an address, with its size and a guess at code or data.
struct Symbol {
    std::string name;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    SymbolKind kind = SymbolKind::Other;
};

// A loaded binary, owning its sections and symbols. The hand-off point between
// the loaders and everything after them.
struct Binary {
    Format format = Format::Unknown;
    std::string path;  // path the binary was loaded from
    std::uint64_t entry_point = 0;
    std::uint64_t file_size = 0;  // size of the file on disk, in bytes
    std::string arch;             // target architecture, e.g. "x86_64"; empty if unknown
    std::vector<Section> sections;
    std::vector<Symbol> symbols;

    // Exact name match, e.g. ".text".
    const Section* section_by_name(std::string_view name) const {
        for (const auto& sec : sections) {
            if (sec.name == name) {
                return &sec;
            }
        }
        return nullptr;
    }

    // How --func gets resolved to an address range.
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
