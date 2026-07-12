#include "minidec/disasm.h"

#include <cstdio>
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

    // cs_disasm_iter decodes one instruction at a time out of a buffer we own,
    // instead of cs_disasm which stops dead at the first byte it can't read. We
    // go one at a time so that when it does choke we can drop a placeholder for
    // the bad byte and keep walking, rather than losing the rest of the function.
    cs_insn* insn = cs_malloc(handle);
    if (insn == nullptr) {
        return out;
    }

    const std::uint8_t* ptr = code;
    std::size_t left = size;
    std::uint64_t addr = address;

    while (left > 0) {
        // On success iter advances ptr/left/addr past the instruction for us, so
        // the next loop pass picks up right where this one ended.
        if (cs_disasm_iter(handle, &ptr, &left, &addr, insn)) {
            Instruction decoded;
            decoded.address = insn->address;
            decoded.size = insn->size;
            decoded.bytes.assign(insn->bytes, insn->bytes + insn->size);
            decoded.mnemonic = insn->mnemonic;
            decoded.op_str = insn->op_str;

            // cs_insn_group only works when detail is on, which we set in the
            // ctor. CS_GRP_JUMP covers both jmp and the conditional jcc family,
            // and CS_GRP_BRANCH_RELATIVE tells us the target is a relative offset
            // baked into the encoding (i.e. a direct branch we can resolve).
            decoded.is_call = cs_insn_group(handle, insn, CS_GRP_CALL);
            decoded.is_jump = cs_insn_group(handle, insn, CS_GRP_JUMP);
            decoded.is_ret = cs_insn_group(handle, insn, CS_GRP_RET);
            decoded.is_relative = cs_insn_group(handle, insn, CS_GRP_BRANCH_RELATIVE);

            out.push_back(std::move(decoded));
        } else {
            // capstone couldn't make an instruction out of the byte at ptr. This
            // is normal: jump tables, string literals and alignment padding all
            // end up sitting in the middle of .text. Emit the single byte as a
            // ".byte 0xNN" line the way objdump does, then step over it by hand
            // (iter didn't move ptr since it failed) and try the next one.
            Instruction raw;
            raw.address = addr;
            raw.size = 1;
            raw.bytes.assign(ptr, ptr + 1);
            raw.mnemonic = ".byte";

            char buf[8];
            std::snprintf(buf, sizeof(buf), "0x%02x", *ptr);
            raw.op_str = buf;

            out.push_back(std::move(raw));

            ptr += 1;
            addr += 1;
            left -= 1;
        }
    }

    cs_free(insn, 1);
    return out;
}

}  // namespace minidec
