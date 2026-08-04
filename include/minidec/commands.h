#ifndef MINIDEC_COMMANDS_H
#define MINIDEC_COMMANDS_H

#include "minidec/cli.h"

namespace minidec {

// `minidec symbols <file>` -- list the symbols in a binary. Returns the exit code.
int cmd_symbols(const ParsedArgs& args);

// `minidec disasm <file> --func <name>` -- disassemble one function.
int cmd_disasm(const ParsedArgs& args);

// `minidec cfg <file> --func <name>` -- basic blocks and the edges between them.
int cmd_cfg(const ParsedArgs& args);

// `minidec ir <file> --func <name>` -- the IR each instruction lifts to.
int cmd_ir(const ParsedArgs& args);

}  // namespace minidec

#endif  // MINIDEC_COMMANDS_H
