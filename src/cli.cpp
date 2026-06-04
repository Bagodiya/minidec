#include "minidec/cli.h"

namespace minidec {

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

}  // namespace minidec
