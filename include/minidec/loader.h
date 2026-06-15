#ifndef MINIDEC_LOADER_H
#define MINIDEC_LOADER_H

#include <optional>
#include <string>

#include "minidec/binary.h"

namespace minidec {

// Open an ELF file and pull out the headline metadata: entry point, file size,
// target architecture, and the section table. Symbols are still left empty for
// now; a later step fills those in. Returns nullopt when the file can't be read
// or LIEF decides it isn't a valid ELF.
std::optional<Binary> load_elf(const std::string& path);

}  // namespace minidec

#endif  // MINIDEC_LOADER_H
