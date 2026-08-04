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

// Empty string for anything unrecognised, so the caller can tell that apart from
// a real answer.
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

// Open at the end and read back the offset. 0 if the file won't open, matching
// Binary's default.
std::uint64_t file_size_on_disk(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        return 0;
    }
    return static_cast<std::uint64_t>(in.tellg());
}

// Bytes are copied so nothing downstream has to keep the LIEF object alive.
// .bss and friends carry no data on disk, so their bytes stay empty.
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

// The ELF spec has more types than this, but code against data is what matters.
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

// symbols() covers both .symtab and .dynsym. Nameless entries -- section and file
// symbols -- are dropped, since symbol_by_name would never match them anyway.
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

    // header() gives the ELF-specific one, so go through the abstract header.
    LIEF::Header header = LIEF::Header::from(*elf);
    bin.arch = arch_name(header.architecture());

    bin.sections = read_sections(*elf);
    bin.symbols = read_symbols(*elf);

    return bin;
}

}  // namespace minidec
