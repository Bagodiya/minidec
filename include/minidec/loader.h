#ifndef MINIDEC_LOADER_H
#define MINIDEC_LOADER_H

#include <optional>
#include <string>

#include "minidec/binary.h"

namespace minidec {

// Entry point, file size, architecture, sections and named symbols. nullopt if
// the file won't read or isn't a valid ELF.
std::optional<Binary> load_elf(const std::string& path);

// Same for Mach-O. Fat binaries give up their x86_64 slice, or the first one if
// there isn't one.
std::optional<Binary> load_macho(const std::string& path);

// Dispatch on the magic bytes. What the subcommands should call.
std::optional<Binary> load_binary(const std::string& path);

}  // namespace minidec

#endif  // MINIDEC_LOADER_H
