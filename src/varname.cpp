#include "minidec/varname.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "minidec/lift.h"

namespace minidec {

namespace {

std::string canonical(const std::string& reg) {
    return std::string(whole_register(reg));
}

std::string make_name(const char* prefix, unsigned index) {
    return std::string(prefix) + std::to_string(index);
}

// A stack slot's size is in bytes and everything else is in bits, so one of them
// has to give. Bits, since that is what a width means everywhere else.
unsigned bits_from_bytes(unsigned bytes) {
    return bytes * 8;
}

void add_versions(NamedVar& var, const std::vector<unsigned>& versions) {
    for (unsigned version : versions) {
        if (std::find(var.versions.begin(), var.versions.end(), version) == var.versions.end()) {
            var.versions.push_back(version);
        }
    }
    std::sort(var.versions.begin(), var.versions.end());
}

// The parameter a register variable is really the arrival of, or nullptr. Both
// halves matter: a callee-saved register read before it is written also has a
// version 0, and that is not an argument.
NamedVar* parameter_for(std::vector<NamedVar>& named, const ParamList& params, const RegVar& var) {
    if (!var.from_caller()) {
        return nullptr;
    }

    const Parameter* param = params.find(var.reg);
    if (param == nullptr) {
        return nullptr;
    }

    for (NamedVar& candidate : named) {
        if (candidate.kind == VarKind::parameter && candidate.index == param->index) {
            return &candidate;
        }
    }
    return nullptr;
}

} // namespace

const char* var_kind_name(VarKind kind) {
    switch (kind) {
    case VarKind::parameter:
        return "parameter";
    case VarKind::stack:
        return "stack";
    case VarKind::reg:
        return "register";
    }
    return "?";
}

const NamedVar* NameTable::find(const std::string& name) const {
    for (const NamedVar& var : vars) {
        if (var.name == name) {
            return &var;
        }
    }
    return nullptr;
}

const NamedVar* NameTable::stack_slot(const std::string& base, unsigned base_version,
                                      std::int64_t offset) const {
    const std::string canon = canonical(base);
    for (const NamedVar& var : vars) {
        if (var.kind != VarKind::stack) {
            continue;
        }
        if (var.base == canon && var.base_version == base_version && var.offset == offset) {
            return &var;
        }
    }
    return nullptr;
}

const NamedVar* NameTable::value(const std::string& reg, unsigned version) const {
    const std::string canon = canonical(reg);
    for (const NamedVar& var : vars) {
        if (var.reg != canon) {
            continue;
        }
        if (std::find(var.versions.begin(), var.versions.end(), version) != var.versions.end()) {
            return &var;
        }
    }
    return nullptr;
}

NameTable name_variables(const ParamList& params, const StackFrame& frame, const RegVars& regs) {
    NameTable table;

    for (const Parameter& param : params.params) {
        NamedVar named;
        named.name = make_name("arg_", param.index);
        named.kind = VarKind::parameter;
        named.index = param.index;
        named.width = param.width;
        named.reg = canonical(param.reg);
        named.versions.push_back(0);
        table.vars.push_back(std::move(named));
    }

    // One counter for both kinds of local, running on from wherever the stack
    // slots leave it.
    unsigned next = 0;

    for (const StackVar& var : frame.vars) {
        NamedVar named;
        named.name = make_name("var_", next);
        named.kind = VarKind::stack;
        named.index = next;
        named.width = bits_from_bytes(var.size);
        named.offset = var.offset;
        named.base = canonical(var.base);
        named.base_version = var.base_version;
        table.vars.push_back(std::move(named));
        ++next;
    }

    for (const RegVar& var : regs.vars) {
        if (NamedVar* param = parameter_for(table.vars, params, var)) {
            // The argument again, further down the function. Same variable, so
            // the extra versions go on the name it already has.
            add_versions(*param, var.versions);
            param->width = std::max(param->width, var.width);
            continue;
        }

        NamedVar named;
        named.name = make_name("var_", next);
        named.kind = VarKind::reg;
        named.index = next;
        named.width = var.width;
        named.reg = canonical(var.reg);
        named.versions = var.versions;
        table.vars.push_back(std::move(named));
        ++next;
    }

    return table;
}

} // namespace minidec
