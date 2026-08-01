#include "minidec/lift.h"

#include <cstdlib>
#include <string>
#include <unordered_map>
#include <utility>

namespace minidec {

namespace {

// The legacy register names, which have to be a table because there's no rule
// behind them -- "al" and "ax" and "eax" and "rax" are the same register at four
// widths but none of the spellings follow from the others. The flag bits are in
// here too: as far as the IR is concerned zf and friends are just registers that
// happen to be one bit wide, which is what lets an arithmetic instruction's flag
// writes be ordinary assignments later on.
const std::unordered_map<std::string_view, IrType>& legacy_registers() {
    static const std::unordered_map<std::string_view, IrType> table = {
        {"rax", IrType::i64}, {"rbx", IrType::i64}, {"rcx", IrType::i64},
        {"rdx", IrType::i64}, {"rsi", IrType::i64}, {"rdi", IrType::i64},
        {"rbp", IrType::i64}, {"rsp", IrType::i64}, {"rip", IrType::i64},

        {"eax", IrType::i32}, {"ebx", IrType::i32}, {"ecx", IrType::i32},
        {"edx", IrType::i32}, {"esi", IrType::i32}, {"edi", IrType::i32},
        {"ebp", IrType::i32}, {"esp", IrType::i32},

        {"ax", IrType::i16},  {"bx", IrType::i16},  {"cx", IrType::i16},
        {"dx", IrType::i16},  {"si", IrType::i16},  {"di", IrType::i16},
        {"bp", IrType::i16},  {"sp", IrType::i16},

        {"al", IrType::i8},   {"bl", IrType::i8},   {"cl", IrType::i8},
        {"dl", IrType::i8},   {"ah", IrType::i8},   {"bh", IrType::i8},
        {"ch", IrType::i8},   {"dh", IrType::i8},   {"sil", IrType::i8},
        {"dil", IrType::i8},  {"bpl", IrType::i8},  {"spl", IrType::i8},

        {"cf", IrType::i1},   {"pf", IrType::i1},   {"af", IrType::i1},
        {"zf", IrType::i1},   {"sf", IrType::i1},   {"of", IrType::i1},
        {"df", IrType::i1},
    };
    return table;
}

// r8 through r15, which unlike the names above are completely regular: the
// number picks the register and the suffix picks the width. That's worth a few
// lines of parsing instead of another thirty-two table entries.
std::optional<IrType> numbered_register_type(std::string_view name) {
    if (name.empty() || name[0] != 'r') {
        return std::nullopt;
    }

    std::size_t pos = 1;
    unsigned number = 0;
    while (pos < name.size() && name[pos] >= '0' && name[pos] <= '9') {
        number = number * 10 + static_cast<unsigned>(name[pos] - '0');
        ++pos;
    }

    // pos == 1 means there were no digits at all, so this was "rax" or similar
    // and belongs to the table instead.
    if (pos == 1 || number < 8 || number > 15) {
        return std::nullopt;
    }

    std::string_view suffix = name.substr(pos);
    if (suffix.empty()) {
        return IrType::i64;
    }
    if (suffix == "d") {
        return IrType::i32;
    }
    if (suffix == "w") {
        return IrType::i16;
    }
    if (suffix == "b") {
        return IrType::i8;
    }
    return std::nullopt;
}

// Drop the spaces capstone leaves around operands once they're split apart.
std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

// Cut the operand text into its individual operands. A plain split on commas is
// enough because capstone never writes one inside an operand -- even a full
// address like "[rbp + rax*8 - 4]" only uses + - and *.
std::vector<std::string_view> split_operands(std::string_view op_str) {
    std::vector<std::string_view> parts;
    if (trim(op_str).empty()) {
        return parts;
    }

    std::size_t start = 0;
    while (true) {
        std::size_t comma = op_str.find(',', start);
        if (comma == std::string_view::npos) {
            parts.push_back(trim(op_str.substr(start)));
            break;
        }
        parts.push_back(trim(op_str.substr(start, comma - start)));
        start = comma + 1;
    }
    return parts;
}

// Read a constant operand. Capstone prints these as bare numbers, usually hex
// with an 0x on the front and occasionally negative, so strtoull with base 0
// covers it. Same rule as the jump target parsing in cfg.cpp: if it didn't eat
// the whole string then it wasn't a number and we don't guess at what it was.
std::optional<std::uint64_t> parse_immediate(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }

    std::string owned(text);
    const char* begin = owned.c_str();
    char* stop = nullptr;

    // A negative immediate has to go through the signed parser and then get
    // reinterpreted, because strtoull would happily wrap it round the other way
    // without telling us it saw a minus sign.
    std::uint64_t value = 0;
    if (owned.front() == '-') {
        long long signed_value = std::strtoll(begin, &stop, 0);
        value = static_cast<std::uint64_t>(signed_value);
    } else {
        value = std::strtoull(begin, &stop, 0);
    }

    if (stop == begin || *stop != '\0') {
        return std::nullopt;
    }
    return value;
}

// Cut a constant down to the width it's actually being used at. Capstone prints
// a small negative immediate as a signed number, and reading that back gives a
// value with ones sitting above the operand's real width -- "mov al, -1" would
// end up carrying 0xffffffffffffffff in an eight-bit operand. Everything in the
// IR is a fixed-width bit pattern, so trim it to the width it says it is.
std::uint64_t mask_to_width(std::uint64_t value, IrType type) {
    unsigned bits = type_bits(type);
    // Nothing to do at 64 bits, and shifting by the full width would be
    // undefined anyway. Width 0 is the none type, which shouldn't reach here.
    if (bits == 0 || bits >= 64) {
        return value;
    }
    return value & ((std::uint64_t{1} << bits) - 1);
}

// One operand's worth of text into an IR operand. Registers carry their own
// width so they ignore the hint; a constant has no width of its own in the text,
// so it takes whatever the instruction is working at.
//
// Anything else -- a memory reference, an xmm register, a segment override --
// comes back as nothing, and the caller turns the whole instruction into an
// unknown rather than lifting half of it.
std::optional<IrOperand> parse_operand(std::string_view text, IrType width_hint) {
    text = trim(text);
    if (text.empty()) {
        return std::nullopt;
    }

    if (std::optional<IrType> type = register_type(text)) {
        return make_reg(std::string(text), *type);
    }

    if (width_hint != IrType::none) {
        if (std::optional<std::uint64_t> value = parse_immediate(text)) {
            return make_imm(mask_to_width(*value, width_hint), width_hint);
        }
    }

    return std::nullopt;
}

// Build one operation in a single expression. The arithmetic below emits runs of
// eight and nine operations at a time, and filling in five fields by hand each
// time buried what the sequence was actually doing.
IrInst make_inst(Opcode op, IrType type, IrOperand dst, std::vector<IrOperand> args,
                 std::uint64_t address) {
    IrInst inst;
    inst.op = op;
    inst.type = type;
    inst.dst = std::move(dst);
    inst.args = std::move(args);
    inst.address = address;
    return inst;
}

// The register pair div and idiv work on, which changes name with the width.
// The 8-bit form is missing on purpose: it divides ax rather than a pair and
// leaves the remainder in ah, so it doesn't fit the shape the others share and
// isn't worth a special case for how rarely compilers emit it.
struct DivisionRegisters {
    const char* accumulator;  // holds the dividend going in, the quotient coming out
    const char* remainder;
};

std::optional<DivisionRegisters> division_registers(IrType type) {
    switch (type) {
    case IrType::i16:
        return DivisionRegisters{"ax", "dx"};
    case IrType::i32:
        return DivisionRegisters{"eax", "edx"};
    case IrType::i64:
        return DivisionRegisters{"rax", "rdx"};
    default:
        return std::nullopt;
    }
}

// The placeholder for an instruction we can't model yet. It writes nothing and
// reads nothing, which is a lie, but it's a lie in the right place: a pass that
// walks the IR sees an operation it has to treat as opaque instead of quietly
// missing an instruction that was there.
IrInst make_unknown(std::uint64_t address) {
    IrInst inst;
    inst.op = Opcode::unknown;
    inst.type = IrType::none;
    inst.address = address;
    return inst;
}

// mov and movabs, in the forms where both operands are registers or the source
// is a constant. Either way it's a straight copy, so one assign covers it.
// A mov with a memory operand on either side is a load or a store and needs the
// address worked out first, which is step 42, so it isn't handled here.
//
// Returns false without touching `out` when the operands aren't a shape we
// understand, so the caller can fall back to an unknown.
bool lift_mov(const Instruction& insn, std::vector<IrInst>& out) {
    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 2) {
        return false;
    }

    std::optional<IrOperand> dst = parse_operand(operands[0], IrType::none);
    if (!dst || dst->kind != OperandKind::reg) {
        return false;
    }

    std::optional<IrOperand> src = parse_operand(operands[1], dst->type);
    if (!src) {
        return false;
    }

    // Both sides of a mov are the same width in any encoding that assembles, so
    // a mismatch here means we misread one of them. Bail out rather than emit an
    // assign that silently changes width.
    if (src->kind == OperandKind::reg && src->type != dst->type) {
        return false;
    }

    IrInst assign;
    assign.op = Opcode::assign;
    assign.type = dst->type;
    assign.dst = *dst;
    assign.args.push_back(*src);
    assign.address = insn.address;
    out.push_back(std::move(assign));
    return true;
}

}  // namespace

std::optional<IrType> register_type(std::string_view name) {
    const auto& table = legacy_registers();
    auto found = table.find(name);
    if (found != table.end()) {
        return found->second;
    }
    return numbered_register_type(name);
}

IrOperand Lifter::new_temp(IrType type) {
    return make_temp(next_temp_++, type);
}

// x86 updates six flags after an add or a sub and we write four of them. zf and
// sf fall straight out of the result; cf and of cost a few extra operations
// each, but every conditional jump in step 43 reads one of the four, so they
// have to be here and they have to be right.
//
// pf and af are the two left out. af only matters to the BCD instructions, which
// nothing has emitted in decades, and pf is the parity of the low byte, which
// would need a popcount the IR has no opcode for. Neither is left holding a
// wrong answer -- they just keep whatever they had before the instruction, which
// a later pass can at least see is stale.
void Lifter::emit_arith_flags(const IrOperand& lhs, const IrOperand& rhs, const IrOperand& result,
                              bool subtract, std::uint64_t address, std::vector<IrInst>& out) {
    IrType width = result.type;
    IrOperand zero = make_imm(0, width);

    out.push_back(
        make_inst(Opcode::cmp_eq, IrType::i1, make_reg("zf", IrType::i1), {result, zero}, address));
    out.push_back(make_inst(Opcode::cmp_lt_s, IrType::i1, make_reg("sf", IrType::i1),
                            {result, zero}, address));

    // The carry out of the top bit. A sub carries when it had to borrow, which
    // is exactly when the left side was the smaller of the two read as unsigned.
    // An add carries when it wrapped round, and a wrapped sum always lands below
    // the operand it started from, so one compare catches it either way.
    if (subtract) {
        out.push_back(make_inst(Opcode::cmp_lt_u, IrType::i1, make_reg("cf", IrType::i1),
                                {lhs, rhs}, address));
    } else {
        out.push_back(make_inst(Opcode::cmp_lt_u, IrType::i1, make_reg("cf", IrType::i1),
                                {result, lhs}, address));
    }

    // Signed overflow, by the usual sign-bit trick. An add overflows when both
    // operands shared a sign and the result came back with the other one; a sub
    // overflows when the operands' signs differed and the result took the
    // right-hand one's. Both come out as "these two xors agree in the sign bit",
    // so it's the same three operations with different inputs, and testing a
    // sign bit is just a signed compare against zero.
    IrOperand first = new_temp(width);
    IrOperand second = new_temp(width);
    IrOperand both = new_temp(width);
    if (subtract) {
        out.push_back(make_inst(Opcode::bit_xor, width, first, {lhs, rhs}, address));
        out.push_back(make_inst(Opcode::bit_xor, width, second, {lhs, result}, address));
    } else {
        out.push_back(make_inst(Opcode::bit_xor, width, first, {result, lhs}, address));
        out.push_back(make_inst(Opcode::bit_xor, width, second, {result, rhs}, address));
    }
    out.push_back(make_inst(Opcode::bit_and, width, both, {first, second}, address));
    out.push_back(make_inst(Opcode::cmp_lt_s, IrType::i1, make_reg("of", IrType::i1), {both, zero},
                            address));
}

// add and sub between two registers, or a register and a constant. Both have the
// same shape -- the destination doubles as the left-hand operand -- so the only
// thing that changes between them is which opcode comes out and how the flags
// are worked out, and `subtract` picks that.
//
// A memory operand on either side needs an address computing first, which is
// step 42, so parse_operand rejecting it here is what we want.
bool Lifter::lift_add_sub(const Instruction& insn, bool subtract, std::vector<IrInst>& out) {
    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 2) {
        return false;
    }

    std::optional<IrOperand> dst = parse_operand(operands[0], IrType::none);
    if (!dst || dst->kind != OperandKind::reg) {
        return false;
    }

    std::optional<IrOperand> src = parse_operand(operands[1], dst->type);
    if (!src) {
        return false;
    }
    // Same reasoning as in lift_mov: an encoding that assembles has both sides
    // at one width, so a mismatch means we misread an operand.
    if (src->kind == OperandKind::reg && src->type != dst->type) {
        return false;
    }

    // The result goes into a temporary and only reaches the register on the last
    // line. Since the destination is also the left-hand operand, writing it any
    // earlier would leave the flag operations reading the value the instruction
    // just produced instead of the one it started with.
    IrOperand result = new_temp(dst->type);
    out.push_back(make_inst(subtract ? Opcode::sub : Opcode::add, dst->type, result, {*dst, *src},
                            insn.address));
    emit_arith_flags(*dst, *src, result, subtract, insn.address, out);
    out.push_back(make_inst(Opcode::assign, dst->type, *dst, {result}, insn.address));
    return true;
}

// imul in the two forms that keep the product at the operand's own width: two
// operands, where the destination is also the left factor, and three, where both
// factors are written out. The one-operand form is the odd one -- it multiplies
// rax and spreads a result twice as wide across rdx:rax, and there's no IR type
// big enough to hold that, so it falls through to an unknown.
//
// mul, the unsigned one, only exists in that one-operand form, so it never
// reaches here either. Which leaves nothing signed about this: the low half of a
// product is the same bit pattern whichever way the operands are read, and that
// is exactly why the compiler reaches for imul on unsigned code too.
bool Lifter::lift_imul(const Instruction& insn, std::vector<IrInst>& out) {
    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 2 && operands.size() != 3) {
        return false;
    }

    std::optional<IrOperand> dst = parse_operand(operands[0], IrType::none);
    if (!dst || dst->kind != OperandKind::reg) {
        return false;
    }

    // With two operands the destination stands in as the left factor; with three
    // it is only a destination and the left factor is the second operand.
    IrOperand lhs = *dst;
    std::string_view rhs_text = operands[1];
    if (operands.size() == 3) {
        std::optional<IrOperand> named = parse_operand(operands[1], IrType::none);
        if (!named || named->kind != OperandKind::reg || named->type != dst->type) {
            return false;
        }
        lhs = *named;
        rhs_text = operands[2];
    }

    std::optional<IrOperand> rhs = parse_operand(rhs_text, dst->type);
    if (!rhs) {
        return false;
    }
    if (rhs->kind == OperandKind::reg && rhs->type != dst->type) {
        return false;
    }

    // No flag operations. imul sets cf and of when the full product needed more
    // room than the destination had, which we'd have to multiply at double width
    // to find out, and it leaves zf, sf, pf and af undefined -- so there's
    // nothing here that could be written correctly.
    out.push_back(make_inst(Opcode::mul, dst->type, *dst, {lhs, *rhs}, insn.address));
    return true;
}

// div and idiv, which take one operand, divide the pair rdx:rax by it, and leave
// the quotient in rax and the remainder in rdx.
//
// The dividend being twice as wide as everything else is the awkward part, and
// again there's no IR type for it. What rescues us is that compilers never use
// the extra width: an unsigned divide is always set up by something that clears
// rdx ("xor edx, edx") and a signed one by cdq or cqo, which fills rdx with
// copies of rax's sign bit. Either way the real dividend is just rax widened, so
// dividing rax at its own width gives the same answer.
//
// Hand-written or obfuscated code that puts a genuine value in rdx does get
// lifted wrong by this. It's the first place we produce an answer instead of an
// unknown without being able to show it's right, and it deserves another look
// once step 45 can trace back what actually wrote rdx.
bool Lifter::lift_div(const Instruction& insn, bool is_signed, std::vector<IrInst>& out) {
    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 1) {
        return false;
    }

    // There is no immediate form of div, so a constant here means we misread the
    // operand rather than that the instruction divides by a literal.
    std::optional<IrOperand> divisor = parse_operand(operands[0], IrType::none);
    if (!divisor || divisor->kind != OperandKind::reg) {
        return false;
    }

    std::optional<DivisionRegisters> regs = division_registers(divisor->type);
    if (!regs) {
        return false;
    }

    IrType width = divisor->type;
    IrOperand accumulator = make_reg(regs->accumulator, width);
    IrOperand quotient = new_temp(width);
    IrOperand remainder = new_temp(width);

    // Both halves are computed before either register is written, for the same
    // reason as in lift_add_sub: the remainder still needs the old accumulator,
    // and the quotient would have overwritten it.
    out.push_back(make_inst(is_signed ? Opcode::div_s : Opcode::div_u, width, quotient,
                            {accumulator, *divisor}, insn.address));
    out.push_back(make_inst(is_signed ? Opcode::rem_s : Opcode::rem_u, width, remainder,
                            {accumulator, *divisor}, insn.address));
    out.push_back(make_inst(Opcode::assign, width, accumulator, {quotient}, insn.address));
    out.push_back(make_inst(Opcode::assign, width, make_reg(regs->remainder, width), {remainder},
                            insn.address));

    // div and idiv leave every flag undefined, so there is nothing to emit.
    return true;
}

std::vector<IrInst> Lifter::lift(const Instruction& insn) {
    std::vector<IrInst> out;

    if (insn.mnemonic == "nop") {
        // Capstone writes the wide padding forms with operands attached
        // ("nop word ptr [rax + rax]"), but they're still doing nothing, so the
        // operand text doesn't need reading.
        IrInst nop;
        nop.op = Opcode::nop;
        nop.address = insn.address;
        out.push_back(std::move(nop));
        return out;
    }

    if (insn.mnemonic == "mov" || insn.mnemonic == "movabs") {
        if (lift_mov(insn, out)) {
            return out;
        }
        out.clear();
    }

    if (insn.mnemonic == "add" || insn.mnemonic == "sub") {
        if (lift_add_sub(insn, insn.mnemonic == "sub", out)) {
            return out;
        }
        out.clear();
    }

    if (insn.mnemonic == "imul") {
        if (lift_imul(insn, out)) {
            return out;
        }
        out.clear();
    }

    if (insn.mnemonic == "div" || insn.mnemonic == "idiv") {
        if (lift_div(insn, insn.mnemonic == "idiv", out)) {
            return out;
        }
        out.clear();
    }

    out.push_back(make_unknown(insn.address));
    return out;
}

}  // namespace minidec
