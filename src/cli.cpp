#include "minidec/cli.h"

#include <iostream>

#include "minidec/commands.h"

namespace minidec {

std::string version_string() {
    return "minidec 0.0.1";
}

std::string help_text() {
    // Keep this in sync with the subcommands as they get added. For now only the
    // skeleton exists, so we just advertise what's planned.
    std::string out;
    out += "usage: minidec <command> [options]\n";
    out += "\n";
    out += "commands:\n";
    out += "  symbols     list the symbols in a binary\n";
    out += "  disasm      disassemble a function\n";
    out += "  cfg         show a function's control-flow graph\n";
    out += "  decompile   emit C-like pseudocode for a function\n";
    out += "\n";
    out += "options:\n";
    out += "  --version   print the version and exit\n";
    out += "  --help      print this help and exit\n";
    return out;
}

bool ParsedArgs::has_option(const std::string& name) const {
    return options.find(name) != options.end();
}

std::string ParsedArgs::option(const std::string& name, const std::string& fallback) const {
    auto it = options.find(name);
    if (it == options.end()) {
        return fallback;
    }
    return it->second;
}

static bool is_flag(const std::string& token) {
    return token.rfind("--", 0) == 0;
}

ParsedArgs parse_args(int argc, char* argv[]) {
    ParsedArgs result;

    for (int i = 1; i < argc; ++i) {
        std::string token = argv[i];

        if (is_flag(token)) {
            std::string name = token.substr(2);  // drop the leading "--"

            // grab the next token as the value if there is one and it isn't
            // another flag, otherwise treat this as a bare on/off flag
            if (i + 1 < argc && !is_flag(argv[i + 1])) {
                result.options[name] = argv[i + 1];
                ++i;
            } else {
                result.options[name] = "";
            }
        } else if (result.command.empty()) {
            result.command = token;  // first plain token is the subcommand
        } else {
            result.positionals.push_back(token);
        }
    }

    return result;
}

int run(const ParsedArgs& args) {
    if (args.command == "symbols") {
        return cmd_symbols(args);
    }

    std::cerr << "unknown command: " << args.command << "\n";
    std::cerr << "run 'minidec --help' to see the available commands\n";
    return 1;
}

}  // namespace minidec
