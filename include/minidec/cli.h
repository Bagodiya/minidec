#ifndef MINIDEC_CLI_H
#define MINIDEC_CLI_H

#include <map>
#include <string>
#include <vector>

namespace minidec {

// Holds the result of parsing the command line: the subcommand the user picked,
// any leftover positional arguments, and the --flag value pairs.
struct ParsedArgs {
    std::string command;                         // e.g. "symbols"; empty if none was given
    std::vector<std::string> positionals;        // non-flag tokens after the command
    std::map<std::string, std::string> options;  // --flag -> value (value is "" for bare flags)

    bool has_option(const std::string& name) const;
    std::string option(const std::string& name, const std::string& fallback = "") const;
};

// Walk argv and pull out the subcommand, positionals, and options. argv[0] (the
// program name) is skipped. A token starting with "--" is a flag; the token
// right after it becomes its value unless that token is itself a flag, in which
// case the flag is recorded with an empty value.
ParsedArgs parse_args(int argc, char* argv[]);

// "minidec <version>" — what --version prints.
std::string version_string();

// The text printed for --help (and when no command is given): a usage line plus
// the list of available subcommands.
std::string help_text();

// Hand a parsed command line off to the matching subcommand and return its exit
// code. The caller deals with --version, --help, and the no-command case before
// getting here; an unrecognized command prints an error and returns non-zero.
int run(const ParsedArgs& args);

}  // namespace minidec

#endif  // MINIDEC_CLI_H
