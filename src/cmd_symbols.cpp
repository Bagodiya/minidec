#include "minidec/commands.h"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>

#include "minidec/loader.h"

namespace minidec {

namespace {

// Short label for the symbol bucket so the listing reads at a glance.
const char* kind_label(SymbolKind kind) {
    switch (kind) {
        case SymbolKind::Function:
            return "func";
        case SymbolKind::Object:
            return "object";
        default:
            return "other";
    }
}

// Addresses are always printed as 16 hex digits, so build that string once.
std::string format_addr(std::uint64_t addr) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(addr));
    return std::string(buf);
}

}  // namespace

int cmd_symbols(const ParsedArgs& args) {
    if (args.positionals.empty()) {
        std::cerr << "symbols: no input file given\n";
        std::cerr << "usage: minidec symbols <file>\n";
        return 1;
    }

    const std::string& path = args.positionals.front();
    std::optional<Binary> bin = load_binary(path);
    if (!bin) {
        std::cerr << "symbols: could not load '" << path << "'\n";
        return 1;
    }

    if (bin->symbols.empty()) {
        std::cout << "no symbols found\n";
        return 0;
    }

    // The address column is a fixed width, but size and type vary depending on
    // the binary, so walk the symbols once and remember the widest value in each
    // column before we print anything. Name goes last so it doesn't need padding.
    std::size_t addr_w = std::string("ADDRESS").size();
    std::size_t size_w = std::string("SIZE").size();
    std::size_t type_w = std::string("TYPE").size();
    for (const Symbol& sym : bin->symbols) {
        addr_w = std::max(addr_w, format_addr(sym.address).size());
        size_w = std::max(size_w, std::to_string(sym.size).size());
        type_w = std::max(type_w, std::string(kind_label(sym.kind)).size());
    }

    std::cout << std::left << std::setw(static_cast<int>(addr_w)) << "ADDRESS" << "  "
              << std::right << std::setw(static_cast<int>(size_w)) << "SIZE" << "  "
              << std::left << std::setw(static_cast<int>(type_w)) << "TYPE" << "  "
              << "NAME" << "\n";

    for (const Symbol& sym : bin->symbols) {
        std::cout << std::left << std::setw(static_cast<int>(addr_w)) << format_addr(sym.address)
                  << "  " << std::right << std::setw(static_cast<int>(size_w)) << sym.size << "  "
                  << std::left << std::setw(static_cast<int>(type_w)) << kind_label(sym.kind)
                  << "  " << sym.name << "\n";
    }

    return 0;
}

}  // namespace minidec
