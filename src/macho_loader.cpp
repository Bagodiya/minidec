#include "minidec/loader.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <memory>
#include <set>
#include <utility>

#include <LIEF/Abstract/Header.hpp>
#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/Section.hpp>
#include <LIEF/MachO/Symbol.hpp>

namespace minidec {

namespace {

// Same short-name table as the ELF loader uses. Kept as its own copy here so the
// two loaders don't have to share a translation unit just for this.
std::string arch_name(LIEF::Header::ARCHITECTURES arch) {
    switch (arch) {
        case LIEF::Header::ARCHITECTURES::X86_64:
            return "x86_64";
        case LIEF::Header::ARCHITECTURES::X86:
            return "x86";
        case LIEF::Header::ARCHITECTURES::ARM64:
            return "arm64";
        case LIEF::Header::ARCHITECTURES::ARM:
            return "arm";
        default:
            return "";
    }
}

std::uint64_t file_size_on_disk(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        return 0;
    }
    return static_cast<std::uint64_t>(in.tellg());
}

// The same short name can appear under more than one segment, so join them as
// "__SEGMENT,__section" the way the toolchain does.
std::vector<Section> read_sections(const LIEF::MachO::Binary& macho) {
    std::vector<Section> out;
    for (const LIEF::MachO::Section& sec : macho.sections()) {
        Section s;
        s.name = sec.segment_name() + "," + sec.name();
        s.address = sec.virtual_address();
        s.size = sec.size();
        s.file_offset = sec.offset();

        auto content = sec.content();
        s.bytes.assign(content.begin(), content.end());

        out.push_back(std::move(s));
    }
    return out;
}

// Mach-O has no code/data symbol type, so go by where the address lands.
SymbolKind classify(const LIEF::MachO::Symbol& sym, const std::vector<Section>& sections) {
    if (sym.type() == LIEF::MachO::Symbol::TYPE::UNDEFINED) {
        return SymbolKind::Other;
    }
    for (const Section& sec : sections) {
        if (sec.contains(sym.value())) {
            // The only code section we emit lives in the __TEXT segment.
            if (sec.name.find("__text") != std::string::npos) {
                return SymbolKind::Function;
            }
            return SymbolKind::Object;
        }
    }
    return SymbolKind::Other;
}

// The section a symbol's address falls in, or nullptr if it's outside all of
// them (an import, or the nameless zero-address entries).
const Section* section_holding(const std::vector<Section>& sections, std::uint64_t address) {
    for (const Section& sec : sections) {
        if (sec.contains(address)) {
            return &sec;
        }
    }
    return nullptr;
}

// An nlist entry has no size field, so LIEF reports zero for every Mach-O symbol
// and there's nothing to copy across. Without a size, disasm and cfg have no end
// address to stop at.
//
// So measure each symbol against the next one along: symbols in a section sit
// back to back, and the last runs to the end of the section. A function followed
// by alignment padding over-measures, but padding is nops, so the disassembly
// picks up a few extra instructions rather than going wrong.
void infer_symbol_sizes(std::vector<Symbol>& symbols, const std::vector<Section>& sections) {
    // Only symbols inside a section can be measured, and they need address order.
    // Sort pointers so the caller's order survives.
    std::vector<Symbol*> placed;
    placed.reserve(symbols.size());
    for (Symbol& sym : symbols) {
        if (section_holding(sections, sym.address) != nullptr) {
            placed.push_back(&sym);
        }
    }

    std::sort(placed.begin(), placed.end(),
              [](const Symbol* a, const Symbol* b) { return a->address < b->address; });

    for (std::size_t i = 0; i < placed.size(); ++i) {
        Symbol& sym = *placed[i];
        if (sym.size != 0) {
            continue;  // something already knew, don't second-guess it
        }

        const Section* sec = section_holding(sections, sym.address);
        std::uint64_t end = sec->address + sec->size;

        // Skip anything sharing this address, or two names for one function measure
        // each other as zero bytes.
        for (std::size_t j = i + 1; j < placed.size(); ++j) {
            if (placed[j]->address <= sym.address) {
                continue;
            }
            if (placed[j]->address < end) {
                end = placed[j]->address;
            }
            break;
        }

        sym.size = end - sym.address;
    }
}

std::vector<Symbol> read_symbols(const LIEF::MachO::Binary& macho,
                                 const std::vector<Section>& sections) {
    std::vector<Symbol> out;

    // A defined-and-exported symbol appears in both the symbol table and the
    // export trie, and LIEF returns both. The duplicate makes `symbols` print the
    // function twice and gives symbol_by_name two identical entries.
    std::set<std::pair<std::string, std::uint64_t>> seen;

    for (const LIEF::MachO::Symbol& sym : macho.symbols()) {
        if (sym.name().empty()) {
            continue;
        }
        if (!seen.emplace(sym.name(), sym.value()).second) {
            continue;
        }

        Symbol s;
        s.name = sym.name();
        s.address = sym.value();
        s.size = sym.size();
        s.kind = classify(sym, sections);
        out.push_back(std::move(s));
    }

    infer_symbol_sizes(out, sections);
    return out;
}

// Out of a fat binary, grab the x86_64 slice if it's present, otherwise just the
// first one. Returns nullptr only when there are no slices at all.
const LIEF::MachO::Binary* pick_slice(const LIEF::MachO::FatBinary& fat) {
    const LIEF::MachO::Binary* first = nullptr;
    for (std::size_t i = 0; i < fat.size(); ++i) {
        const LIEF::MachO::Binary* slice = fat.at(i);
        if (slice == nullptr) {
            continue;
        }
        if (first == nullptr) {
            first = slice;
        }
        if (arch_name(LIEF::Header::from(*slice).architecture()) == "x86_64") {
            return slice;
        }
    }
    return first;
}

}  // namespace

std::optional<Binary> load_macho(const std::string& path) {
    std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(path);
    if (!fat) {
        return std::nullopt;  // not a Mach-O, or the file couldn't be opened
    }

    const LIEF::MachO::Binary* macho = pick_slice(*fat);
    if (macho == nullptr) {
        return std::nullopt;
    }

    Binary bin;
    bin.format = Format::MachO;
    bin.path = path;
    bin.entry_point = macho->entrypoint();
    bin.file_size = file_size_on_disk(path);
    bin.arch = arch_name(LIEF::Header::from(*macho).architecture());

    bin.sections = read_sections(*macho);
    bin.symbols = read_symbols(*macho, bin.sections);

    return bin;
}

std::optional<Binary> load_binary(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }

    // Match the first four bytes against the magic numbers we know.
    std::array<unsigned char, 4> magic{};
    in.read(reinterpret_cast<char*>(magic.data()), magic.size());
    if (in.gcount() < static_cast<std::streamsize>(magic.size())) {
        return std::nullopt;  // too short to be either format
    }

    static const unsigned char elf_magic[4] = {0x7f, 'E', 'L', 'F'};
    if (std::memcmp(magic.data(), elf_magic, sizeof(elf_magic)) == 0) {
        return load_elf(path);
    }

    // Thin Mach-O plus the fat wrappers. LIEF handles endianness and the fat
    // container, so we only need to spot the leading word.
    std::uint32_t word = static_cast<std::uint32_t>(magic[0]) << 24 |
                         static_cast<std::uint32_t>(magic[1]) << 16 |
                         static_cast<std::uint32_t>(magic[2]) << 8 |
                         static_cast<std::uint32_t>(magic[3]);
    switch (word) {
        case 0xfeedface:  // 32-bit, big endian
        case 0xfeedfacf:  // 64-bit, big endian
        case 0xcefaedfe:  // 32-bit, little endian
        case 0xcffaedfe:  // 64-bit, little endian
        case 0xcafebabe:  // fat
        case 0xbebafeca:  // fat, byte swapped
            return load_macho(path);
        default:
            return std::nullopt;
    }
}

}  // namespace minidec
