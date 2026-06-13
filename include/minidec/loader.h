#ifndef MINIDEC_LOADER_H
#define MINIDEC_LOADER_H

#include <optional>
#include <string>

#include "minidec/binary.h"

namespace minidec {

// Open an ELF file and pull out the headline metadata: entry point, file size,
// and target architecture. Sections and symbols are left empty for now; the
// later steps fill those in. Returns nullopt when the file can't be read or
// LIEF decides it isn't a valid ELF.
std::optional<Binary> load_elf(const std::string& path);

}  // namespace minidec

#endif  // MINIDEC_LOADER_H
