#include "minidec/loader.h"

#include <array>
#include <cstring>
#include <fstream>
#include <memory>

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

// Mach-O names a section by both its segment and the section itself, so the same
// short name (e.g. "__text") can show up under more than one segment. We glue
// them together as "__SEGMENT,__section" which is how the toolchain spells it.
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

// Mach-O symbols don't carry a "this is code / this is data" type the way ELF
// ones do, so we work it out from where the symbol lands: an address inside an
// executable section means a function, anything else inside a section is data,
// and an undefined symbol (an import, no real address) goes in Other.
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

std::vector<Symbol> read_symbols(const LIEF::MachO::Binary& macho,
                                 const std::vector<Section>& sections) {
    std::vector<Symbol> out;
    for (const LIEF::MachO::Symbol& sym : macho.symbols()) {
        if (sym.name().empty()) {
            continue;
        }
        Symbol s;
        s.name = sym.name();
        s.address = sym.value();
        s.size = sym.size();
        s.kind = classify(sym, sections);
        out.push_back(std::move(s));
    }
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

    // Read the first four bytes and match them against the magic numbers we know.
    std::array<unsigned char, 4> magic{};
    in.read(reinterpret_cast<char*>(magic.data()), magic.size());
    if (in.gcount() < static_cast<std::streamsize>(magic.size())) {
        return std::nullopt;  // too short to be either format
    }

    static const unsigned char elf_magic[4] = {0x7f, 'E', 'L', 'F'};
    if (std::memcmp(magic.data(), elf_magic, sizeof(elf_magic)) == 0) {
        return load_elf(path);
    }

    // Thin Mach-O (0xfeedface / 0xfeedfacf) plus the fat/universal wrappers
    // (0xcafebabe and its byte-swapped form). LIEF sorts out the endianness and
    // the fat container for us, so we just need to spot the leading word.
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
