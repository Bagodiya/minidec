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

// Entry point for `minidec cfg <file> --func <name>`. Disassembles the named
// function, splits it into basic blocks, and prints each block with its
// instructions and the blocks control can reach from it. Returns the process
// exit code (0 on success).
int cmd_cfg(const ParsedArgs& args);

}  // namespace minidec

#endif  // MINIDEC_COMMANDS_H
