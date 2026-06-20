#include "minidec/commands.h"

#include <cstdio>
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

    for (const Symbol& sym : bin->symbols) {
        // Fixed-width hex address, then the kind and the name. Lining the
        // columns up properly comes in the next step; two spaces is enough to
        // keep it readable for now.
        char addr[17];
        std::snprintf(addr, sizeof(addr), "%016llx",
                      static_cast<unsigned long long>(sym.address));
        std::cout << addr << "  " << kind_label(sym.kind) << "  " << sym.name << "\n";
    }

    return 0;
}

}  // namespace minidec
