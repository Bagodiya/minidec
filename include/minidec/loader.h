#ifndef MINIDEC_LOADER_H
#define MINIDEC_LOADER_H

#include <optional>
#include <string>

#include "minidec/binary.h"

namespace minidec {

// Open an ELF file and pull out the headline metadata: entry point, file size,
// target architecture, the section table, and the named symbols. Returns nullopt
// when the file can't be read or LIEF decides it isn't a valid ELF.
std::optional<Binary> load_elf(const std::string& path);

// Same idea as load_elf but for Mach-O. Fat (universal) binaries hold more than
// one slice; we pick the x86_64 one when it's there and otherwise fall back to
// the first slice. Returns nullopt if the file isn't a Mach-O or won't open.
std::optional<Binary> load_macho(const std::string& path);

// Peek at the file's magic bytes and hand off to whichever loader fits. This is
// the entry point the subcommands should use so they don't have to care about
// the format. Returns nullopt for anything we don't recognize.
std::optional<Binary> load_binary(const std::string& path);

}  // namespace minidec

#endif  // MINIDEC_LOADER_H
