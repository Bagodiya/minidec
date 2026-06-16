#include "minidec/loader.h"

#include <fstream>
#include <memory>

#include <LIEF/Abstract/Header.hpp>
#include <LIEF/ELF/Binary.hpp>
#include <LIEF/ELF/Parser.hpp>
#include <LIEF/ELF/Section.hpp>
#include <LIEF/ELF/Symbol.hpp>

namespace minidec {

namespace {

// Map LIEF's architecture enum onto the short names we use elsewhere. Only the
// ones we actually expect to deal with are spelled out; anything else returns
// an empty string so the caller can tell "didn't recognize it" apart from a
// real answer.
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

// Size of the file on disk in bytes. Open at the end and read back the offset.
// Returns 0 if the file won't open, which lines up with the default in Binary.
std::uint64_t file_size_on_disk(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        return 0;
    }
    return static_cast<std::uint64_t>(in.tellg());
}

// Pull every section out of the parsed ELF and turn it into our own Section
// type. We copy the bytes across so the rest of the program doesn't have to
// keep the LIEF object alive. Sections like .bss carry no data on disk, so
// content() comes back empty there and bytes just stays empty too.
std::vector<Section> read_sections(const LIEF::ELF::Binary& elf) {
    std::vector<Section> out;
    for (const LIEF::ELF::Section& sec : elf.sections()) {
        Section s;
        s.name = sec.name();
        s.address = sec.virtual_address();
        s.size = sec.size();
        s.file_offset = sec.file_offset();

        auto content = sec.content();
        s.bytes.assign(content.begin(), content.end());

        out.push_back(std::move(s));
    }
    return out;
}

// Boil LIEF's symbol type down to the three buckets we care about. The ELF spec
// has more (sections, files, TLS, ...) but for decompilation we only really need
// to know "is this code or is this data", so the rest lands in Other.
SymbolKind classify(LIEF::ELF::Symbol::TYPE type) {
    switch (type) {
        case LIEF::ELF::Symbol::TYPE::FUNC:
        case LIEF::ELF::Symbol::TYPE::GNU_IFUNC:
            return SymbolKind::Function;
        case LIEF::ELF::Symbol::TYPE::OBJECT:
            return SymbolKind::Object;
        default:
            return SymbolKind::Other;
    }
}

// Walk the symbol table and copy out the entries that are useful to us.
// symbols() covers both the static (.symtab) and dynamic (.dynsym) tables.
// We drop the nameless ones up front -- things like section and file symbols
// show up with no name and there's nothing the later passes can do with them,
// plus symbol_by_name would never match them anyway.
std::vector<Symbol> read_symbols(const LIEF::ELF::Binary& elf) {
    std::vector<Symbol> out;
    for (const LIEF::ELF::Symbol& sym : elf.symbols()) {
        if (sym.name().empty()) {
            continue;
        }
        Symbol s;
        s.name = sym.name();
        s.address = sym.value();
        s.size = sym.size();
        s.kind = classify(sym.type());
        out.push_back(std::move(s));
    }
    return out;
}

}  // namespace

std::optional<Binary> load_elf(const std::string& path) {
    std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(path);
    if (!elf) {
        return std::nullopt;  // not an ELF, or the file couldn't be opened
    }

    Binary bin;
    bin.format = Format::Elf;
    bin.path = path;
    bin.entry_point = elf->entrypoint();
    bin.file_size = file_size_on_disk(path);

    // header() on an ELF::Binary hands back the ELF-specific header, so go
    // through the abstract one to get the architecture in a format-agnostic way.
    LIEF::Header header = LIEF::Header::from(*elf);
    bin.arch = arch_name(header.architecture());

    bin.sections = read_sections(*elf);
    bin.symbols = read_symbols(*elf);

    return bin;
}

}  // namespace minidec
