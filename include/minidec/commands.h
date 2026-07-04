#ifndef MINIDEC_COMMANDS_H
#define MINIDEC_COMMANDS_H

#include "minidec/cli.h"

namespace minidec {

// Entry point for `minidec symbols <file>`. Loads the binary named in the first
// positional argument and lists every symbol we pulled out of it. Returns the
// process exit code (0 on success).
int cmd_symbols(const ParsedArgs& args);

// Entry point for `minidec disasm <file> --func <name>`. Loads the binary, finds
// the named function, and disassembles the bytes that belong to it. Returns the
// process exit code (0 on success).
int cmd_disasm(const ParsedArgs& args);

}  // namespace minidec

#endif  // MINIDEC_COMMANDS_H
