#include "minidec/loader.h"

#include <fstream>
#include <memory>

#include <LIEF/Abstract/Header.hpp>
#include <LIEF/ELF/Binary.hpp>
#include <LIEF/ELF/Parser.hpp>

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

    return bin;
}

}  // namespace minidec
