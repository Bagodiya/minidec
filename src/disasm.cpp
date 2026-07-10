#include "minidec/disasm.h"

#include <utility>

#include <capstone/capstone.h>

namespace minidec {

Disassembler::Disassembler(Syntax syntax) {
    csh handle = 0;
    // x86-64 only for now. cs_open returns CS_ERR_OK and fills in the handle on
    // success; on failure we just leave opened_ false and let callers notice via
    // is_open() instead of throwing.
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
        // Turn on detail mode so each decoded instruction carries its group
        // membership (call, jump, ret, ...). Without this cs_insn_group has
        // nothing to read and every instruction looks like a plain one.
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        // Pick the operand dialect. Capstone already prints Intel by default, so
        // we only really need to flip it for att, but setting both explicitly
        // keeps the mapping obvious.
        cs_option(handle, CS_OPT_SYNTAX,
                  syntax == Syntax::att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
        handle_ = static_cast<std::size_t>(handle);
        opened_ = true;
    }
}

Disassembler::~Disassembler() {
    if (opened_) {
        csh handle = static_cast<csh>(handle_);
        cs_close(&handle);
    }
}

Disassembler::Disassembler(Disassembler&& other) noexcept
    : handle_(other.handle_), opened_(other.opened_) {
    // Null out the source so its destructor doesn't close a handle we now own.
    other.handle_ = 0;
    other.opened_ = false;
}

Disassembler& Disassembler::operator=(Disassembler&& other) noexcept {
    if (this != &other) {
        // Drop whatever we're currently holding before taking the other's handle.
        if (opened_) {
            csh handle = static_cast<csh>(handle_);
            cs_close(&handle);
        }
        handle_ = other.handle_;
        opened_ = other.opened_;
        other.handle_ = 0;
        other.opened_ = false;
    }
    return *this;
}

std::vector<Instruction> Disassembler::disassemble(const std::uint8_t* code, std::size_t size,
                                                   std::uint64_t address) const {
    std::vector<Instruction> out;
    if (!opened_ || code == nullptr || size == 0) {
        return out;
    }

    csh handle = static_cast<csh>(handle_);
    cs_insn* insn = nullptr;

    // Passing 0 as the count tells capstone to decode until it runs out of bytes
    // or hits something it can't decode. It allocates the insn array itself and
    // hands back how many it filled; we hand that block back with cs_free.
    std::size_t count = cs_disasm(handle, code, size, address, 0, &insn);
    out.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        const cs_insn& in = insn[i];
        Instruction decoded;
        decoded.address = in.address;
        decoded.size = in.size;
        decoded.bytes.assign(in.bytes, in.bytes + in.size);
        decoded.mnemonic = in.mnemonic;
        decoded.op_str = in.op_str;

        // cs_insn_group only works when detail is on, which we set in the ctor.
        // CS_GRP_JUMP covers both jmp and the conditional jcc family, and
        // CS_GRP_BRANCH_RELATIVE tells us the target is a relative offset baked
        // into the encoding (i.e. a direct branch we can resolve to a symbol).
        decoded.is_call = cs_insn_group(handle, &in, CS_GRP_CALL);
        decoded.is_jump = cs_insn_group(handle, &in, CS_GRP_JUMP);
        decoded.is_ret = cs_insn_group(handle, &in, CS_GRP_RET);
        decoded.is_relative = cs_insn_group(handle, &in, CS_GRP_BRANCH_RELATIVE);

        out.push_back(std::move(decoded));
    }

    if (insn != nullptr) {
        cs_free(insn, count);
    }
    return out;
}

}  // namespace minidec
