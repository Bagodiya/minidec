#include "minidec/cli.h"

#include <iostream>

int main(int argc, char* argv[]) {
    minidec::ParsedArgs args = minidec::parse_args(argc, argv);

    if (args.has_option("version")) {
        std::cout << minidec::version_string() << std::endl;
        return 0;
    }

    // --help, or nothing at all, both print the usage text.
    if (args.has_option("help") || args.command.empty()) {
        std::cout << minidec::help_text();
        return 0;
    }

    // For now just echo back what we parsed. Real subcommands come later.
    std::cout << "command: " << args.command << std::endl;
    for (const auto& pos : args.positionals) {
        std::cout << "  arg: " << pos << std::endl;
    }
    for (const auto& opt : args.options) {
        std::cout << "  --" << opt.first << " = " << opt.second << std::endl;
    }

    return 0;
}
