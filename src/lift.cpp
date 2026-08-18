#include "minidec/lift.h"

#include <cstdlib>
#include <iterator>
#include <string>
#include <unordered_map>
#include <utility>

namespace minidec {

// base + index*scale + disp, any part optional. Taken apart into adds and a
// multiply here so no later pass has to know addressing modes exist.
//
// `width` is the access size from the "qword ptr" prefix. It belongs to the
// access rather than the address, but it parses out of the same operand.
struct MemoryOperand {
    IrType width = IrType::none;
    std::string base;         // empty when the address has no base register
    std::string index;        // empty when there's no index
    std::uint64_t scale = 1;  // 1, 2, 4 or 8; only meaningful with an index
    std::uint64_t disp = 0;   // already wrapped to 64 bits, so a negative
                              // displacement is its two's complement
};

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
// Anything else -- an xmm register, a memory reference the caller hasn't already
// pulled out with parse_memory -- comes back as nothing, and the caller turns the
// whole instruction into an unknown rather than lifting half of it.
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

// Build an operation in one expression, so the runs of eight and nine below read
// as a sequence instead of as five field assignments each.
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

// Where a direct branch goes. Capstone works the arithmetic out for us and
// prints the destination of a pc-relative jump as a plain absolute address, so
// there's nothing to add to anything here -- read the number back and that's the
// target. An indirect jump has a register or a memory reference in the operand
// instead, and no address we could know before the program runs, so it comes
// back as nothing and the caller deals with it.
std::optional<std::uint64_t> branch_target(const Instruction& insn) {
    if (!insn.is_relative) {
        return std::nullopt;
    }
    return parse_immediate(trim(insn.op_str));
}

// The System V integer argument registers, in fill order. Stack arguments and
// floats aren't here: the former are ordinary stores already emitted, the latter
// need xmm registers the IR doesn't have.
//
// A call names all six because nothing in the instruction says how many it reads.
// Over-stating is the safe direction -- a use-def pass that thinks a register
// might be read leaves its producer alone, where the reverse would delete the
// argument setup of every call it couldn't see through.
const char* const argument_registers[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

// What a conditional jump is actually asking about. x86 has thirty-odd of them
// but only eight distinct questions, because each one comes in a pair: ja is jbe
// with the answer turned round, jne is je turned round, and so on. So the
// mnemonic table below maps onto one of these plus a flag saying which half of
// the pair it is, and the emitter only has to build eight things.
enum class FlagTest {
    overflow,     // of
    carry,        // cf                -- unsigned <
    zero,         // zf
    below_equal,  // cf | zf           -- unsigned <=
    sign,         // sf
    parity,       // pf
    less,         // sf != of          -- signed <
    less_equal,   // zf | (sf != of)   -- signed <=
};

struct ConditionCode {
    FlagTest test;
    bool negate;  // the jn... spelling, taken when the test comes out false
};

// Every conditional jump mnemonic. Capstone settles on one spelling per
// condition, but the aliases cost a line each and stop this breaking quietly if
// a version prints one of them.
//
// jcxz, jrcxz and loop test rcx rather than a flag, so they don't fit and become
// unknowns.
std::optional<ConditionCode> condition_code(std::string_view mnemonic) {
    static const std::unordered_map<std::string_view, ConditionCode> table = {
        {"jo", {FlagTest::overflow, false}},     {"jno", {FlagTest::overflow, true}},

        {"jb", {FlagTest::carry, false}},        {"jc", {FlagTest::carry, false}},
        {"jnae", {FlagTest::carry, false}},      {"jae", {FlagTest::carry, true}},
        {"jnb", {FlagTest::carry, true}},        {"jnc", {FlagTest::carry, true}},

        {"je", {FlagTest::zero, false}},         {"jz", {FlagTest::zero, false}},
        {"jne", {FlagTest::zero, true}},         {"jnz", {FlagTest::zero, true}},

        {"jbe", {FlagTest::below_equal, false}}, {"jna", {FlagTest::below_equal, false}},
        {"ja", {FlagTest::below_equal, true}},   {"jnbe", {FlagTest::below_equal, true}},

        {"js", {FlagTest::sign, false}},         {"jns", {FlagTest::sign, true}},

        {"jp", {FlagTest::parity, false}},       {"jpe", {FlagTest::parity, false}},
        {"jnp", {FlagTest::parity, true}},       {"jpo", {FlagTest::parity, true}},

        {"jl", {FlagTest::less, false}},         {"jnge", {FlagTest::less, false}},
        {"jge", {FlagTest::less, true}},         {"jnl", {FlagTest::less, true}},

        {"jle", {FlagTest::less_equal, false}},  {"jng", {FlagTest::less_equal, false}},
        {"jg", {FlagTest::less_equal, true}},    {"jnle", {FlagTest::less_equal, true}},
    };

    auto found = table.find(mnemonic);
    if (found == table.end()) {
        return std::nullopt;
    }
    return found->second;
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

// Brackets are the only thing capstone puts round a memory operand. Whether we
// can model it is parse_memory's problem.
bool is_memory_text(std::string_view text) {
    return text.find('[') != std::string_view::npos;
}

// The size keyword capstone puts in front of the brackets. The ones missing are
// the widths the IR has no type for -- tbyte is the 80-bit x87 format, and
// xmmword and up are the vector registers -- so an access at one of those has to
// become an unknown.
std::optional<IrType> memory_width(std::string_view keyword) {
    if (keyword == "byte") {
        return IrType::i8;
    }
    if (keyword == "word") {
        return IrType::i16;
    }
    if (keyword == "dword") {
        return IrType::i32;
    }
    if (keyword == "qword") {
        return IrType::i64;
    }
    return std::nullopt;
}

// Fold one term of an address -- a register, a scaled index, or a number -- into
// the operand being built. `negate` says the term came after a minus sign.
bool apply_address_term(MemoryOperand& mem, std::string_view term, bool negate) {
    std::size_t star = term.find('*');
    if (star != std::string_view::npos) {
        // A scaled index, and there's only ever one of them per address.
        if (negate || !mem.index.empty()) {
            return false;
        }

        std::string_view name = trim(term.substr(0, star));
        std::optional<IrType> type = register_type(name);
        if (!type || *type != IrType::i64) {
            return false;
        }

        std::optional<std::uint64_t> scale = parse_immediate(trim(term.substr(star + 1)));
        if (!scale || (*scale != 1 && *scale != 2 && *scale != 4 && *scale != 8)) {
            return false;
        }

        mem.index = std::string(name);
        mem.scale = *scale;
        return true;
    }

    if (std::optional<IrType> type = register_type(term)) {
        // Registers are only ever added, and only at the full 64 bits: a 32-bit
        // base means the instruction carried an address-size prefix, which
        // truncates the address in a way plain arithmetic on i64 wouldn't show.
        if (negate || *type != IrType::i64) {
            return false;
        }

        if (mem.base.empty()) {
            mem.base = std::string(term);
        } else if (mem.index.empty()) {
            // "[rax + rbx]" -- the second register is the index, scaled by one.
            mem.index = std::string(term);
            mem.scale = 1;
        } else {
            return false;
        }
        return true;
    }

    std::optional<std::uint64_t> value = parse_immediate(term);
    if (!value) {
        return false;
    }
    // Adding rather than assigning so that an address written with more than one
    // constant in it still comes out right. Unsigned arithmetic wraps, which is
    // what we want for the minus case -- the result is the displacement's two's
    // complement, and adding that is the same as subtracting.
    mem.disp = negate ? mem.disp - *value : mem.disp + *value;
    return true;
}

// Pick apart something like "qword ptr [rbp + rax*8 - 0x10]". Anything we can't
// model comes back as nothing and the instruction ends up an unknown, so this
// stays strict: it's better to lose a mov than to invent an address.
std::optional<MemoryOperand> parse_memory(std::string_view text) {
    text = trim(text);
    std::size_t open = text.find('[');
    std::size_t close = text.find(']');
    if (open == std::string_view::npos || close != text.size() - 1 || close < open) {
        return std::nullopt;
    }

    MemoryOperand mem;

    std::string_view prefix = trim(text.substr(0, open));
    if (!prefix.empty()) {
        // A segment override, "qword ptr fs:[0x28]" and friends. The segment base
        // isn't in the instruction or in any register we can read, so there's no
        // honest address to compute -- this is where the stack cookie lives, and
        // it stops here.
        if (prefix.find(':') != std::string_view::npos) {
            return std::nullopt;
        }

        std::size_t space = prefix.find(' ');
        if (space == std::string_view::npos || trim(prefix.substr(space)) != "ptr") {
            return std::nullopt;
        }

        std::optional<IrType> width = memory_width(trim(prefix.substr(0, space)));
        if (!width) {
            return std::nullopt;
        }
        mem.width = *width;
    }

    // The terms between the brackets, split on the + and - that separate them.
    // Neither sign can turn up inside a term: a register name has no punctuation
    // and capstone prints a negative displacement by writing the minus out as the
    // separator instead of attaching it to the number.
    std::string_view inner = text.substr(open + 1, close - open - 1);
    bool negate = false;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= inner.size(); ++i) {
        bool at_end = i == inner.size();
        if (!at_end && inner[i] != '+' && inner[i] != '-') {
            continue;
        }

        std::string_view term = trim(inner.substr(start, i - start));
        if (term.empty() || !apply_address_term(mem, term, negate)) {
            return std::nullopt;
        }

        if (!at_end) {
            negate = inner[i] == '-';
            start = i + 1;
        }
    }

    return mem;
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

std::string_view whole_register(std::string_view name) {
    static const std::unordered_map<std::string_view, std::string_view> parts = {
        {"eax", "rax"}, {"ebx", "rbx"}, {"ecx", "rcx"}, {"edx", "rdx"},
        {"esi", "rsi"}, {"edi", "rdi"}, {"ebp", "rbp"}, {"esp", "rsp"},

        {"ax", "rax"},  {"bx", "rbx"},  {"cx", "rcx"},  {"dx", "rdx"},
        {"si", "rsi"},  {"di", "rdi"},  {"bp", "rbp"},  {"sp", "rsp"},

        {"al", "rax"},  {"bl", "rbx"},  {"cl", "rcx"},  {"dl", "rdx"},
        {"ah", "rax"},  {"bh", "rbx"},  {"ch", "rcx"},  {"dh", "rdx"},
        {"sil", "rsi"}, {"dil", "rdi"}, {"bpl", "rbp"}, {"spl", "rsp"},
    };

    auto it = parts.find(name);
    if (it != parts.end()) {
        return it->second;
    }

    // r8 through r15 spell their width as a suffix, so one rule covers the
    // twenty-four names the table would otherwise have to list.
    if (name.size() < 3 || name.front() != 'r') {
        return name;
    }
    char suffix = name.back();
    if (suffix != 'd' && suffix != 'w' && suffix != 'b') {
        return name;
    }
    for (char c : name.substr(1, name.size() - 2)) {
        if (c < '0' || c > '9') {
            return name;
        }
    }
    return name.substr(0, name.size() - 1);
}

const std::vector<std::string>& caller_saved_registers() {
    static const std::vector<std::string> registers = {
        "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
        "cf",  "pf",  "af",  "zf",  "sf",  "of",
    };
    return registers;
}

IrOperand Lifter::new_temp(IrType type) {
    return make_temp(next_temp_++, type);
}

// base + index*scale + disp, spelled out as the multiply and adds it actually
// is. Rule 2 of the IR says a load or a store is handed a value, not an address
// expression, and this is what pays for that: the addressing mode is unpicked
// here, once, and after this an address is just another i64 like any other.
//
// Every part is optional, so most addresses cost far less than the full form --
// "[rbp - 8]" is one add, and "[rax]" doesn't emit anything at all.
IrOperand Lifter::emit_address(const MemoryOperand& mem, const Instruction& insn,
                               std::vector<IrInst>& out) {
    const IrType width = IrType::i64;
    std::uint64_t disp = mem.disp;
    bool has_base = !mem.base.empty();

    // rip isn't a register we can read the way the others are read: it holds the
    // address of the *next* instruction while this one runs, and that's a number
    // we already know here. So it folds into the displacement and disappears,
    // which is what turns a rip-relative access into a plain absolute one.
    if (mem.base == "rip") {
        disp += insn.address + insn.size;
        has_base = false;
    }

    std::optional<IrOperand> address;
    if (has_base) {
        address = make_reg(mem.base, width);
    }

    if (!mem.index.empty()) {
        IrOperand index = make_reg(mem.index, width);
        if (mem.scale != 1) {
            IrOperand scaled = new_temp(width);
            out.push_back(make_inst(Opcode::mul, width, scaled,
                                    {index, make_imm(mem.scale, width)}, insn.address));
            index = scaled;
        }

        if (address) {
            IrOperand sum = new_temp(width);
            out.push_back(make_inst(Opcode::add, width, sum, {*address, index}, insn.address));
            address = sum;
        } else {
            address = index;
        }
    }

    // No registers at all, so the address was known when the program was linked
    // and it's just a constant.
    if (!address) {
        return make_imm(disp, width);
    }

    if (disp == 0) {
        return *address;
    }

    // A negative displacement is already stored as its two's complement, so this
    // one add covers both directions.
    IrOperand sum = new_temp(width);
    out.push_back(
        make_inst(Opcode::add, width, sum, {*address, make_imm(disp, width)}, insn.address));
    return sum;
}

// A mov reading memory into a register.
bool Lifter::lift_load(const Instruction& insn, std::string_view reg_text, const MemoryOperand& mem,
                       std::vector<IrInst>& out) {
    std::optional<IrOperand> dst = parse_operand(reg_text, IrType::none);
    if (!dst || dst->kind != OperandKind::reg) {
        return false;
    }

    // The size keyword and the register have to agree. They always do in an
    // encoding that assembles, so if they don't we misread one of them and
    // guessing which would mean reading the wrong number of bytes.
    if (mem.width != IrType::none && mem.width != dst->type) {
        return false;
    }

    IrOperand address = emit_address(mem, insn, out);
    out.push_back(make_inst(Opcode::load, dst->type, *dst, {address}, insn.address));
    return true;
}

// A mov writing a register or a constant out to memory.
bool Lifter::lift_store(const Instruction& insn, const MemoryOperand& mem,
                        std::string_view value_text, std::vector<IrInst>& out) {
    // Only the size keyword says how wide the write is here. A register source
    // would say the same thing, but "mov dword ptr [rbp - 4], 5" has nothing else
    // to go on, so we need the keyword either way.
    if (mem.width == IrType::none) {
        return false;
    }

    std::optional<IrOperand> value = parse_operand(value_text, mem.width);
    if (!value || (value->kind == OperandKind::reg && value->type != mem.width)) {
        return false;
    }

    IrOperand address = emit_address(mem, insn, out);
    out.push_back(
        make_inst(Opcode::store, mem.width, IrOperand{}, {address, *value}, insn.address));
    return true;
}

// mov and movabs. Between registers, or from a constant, it's a straight copy
// and one assign covers it; with memory on one side it becomes an address
// calculation and a load or a store.
//
// Returns false without touching `out` when the operands aren't a shape we
// understand, so the caller can fall back to an unknown.
bool Lifter::lift_mov(const Instruction& insn, std::vector<IrInst>& out) {
    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 2) {
        return false;
    }

    bool dst_in_memory = is_memory_text(operands[0]);
    bool src_in_memory = is_memory_text(operands[1]);

    // x86 has no memory-to-memory mov, so seeing brackets on both sides means we
    // read the operand text wrong rather than that such an instruction exists.
    if (dst_in_memory && src_in_memory) {
        return false;
    }

    if (src_in_memory) {
        std::optional<MemoryOperand> mem = parse_memory(operands[1]);
        return mem && lift_load(insn, operands[0], *mem, out);
    }

    if (dst_in_memory) {
        std::optional<MemoryOperand> mem = parse_memory(operands[0]);
        return mem && lift_store(insn, *mem, operands[1], out);
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

    out.push_back(make_inst(Opcode::assign, dst->type, *dst, {*src}, insn.address));
    return true;
}

// Four of the six flags an add or sub writes. Every conditional jump reads one
// of these four, so they have to be right.
//
// pf and af are left out: af only matters to the BCD instructions, and pf needs
// a popcount the IR has no opcode for. Both keep their previous value, which a
// later pass can at least see is stale.
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

// and, or, xor and test clear cf and of outright -- a bit operation has no carry
// or overflow. zf and sf still come from the result.
//
// Clearing them explicitly matters: "xor eax, eax" is how a compiler writes zero,
// and a pass that saw cf untouched here would trace it back to whatever
// arithmetic ran last and get an answer from the wrong instruction.
void Lifter::emit_logic_flags(const IrOperand& result, std::uint64_t address,
                              std::vector<IrInst>& out) {
    const IrType bit = IrType::i1;
    IrOperand zero = make_imm(0, result.type);

    out.push_back(make_inst(Opcode::cmp_eq, bit, make_reg("zf", bit), {result, zero}, address));
    out.push_back(make_inst(Opcode::cmp_lt_s, bit, make_reg("sf", bit), {result, zero}, address));
    out.push_back(
        make_inst(Opcode::assign, bit, make_reg("cf", bit), {make_imm(0, bit)}, address));
    out.push_back(
        make_inst(Opcode::assign, bit, make_reg("of", bit), {make_imm(0, bit)}, address));
}

// The two operands shared by the arithmetic, bitwise and compare instructions,
// destination doubling as the left-hand side.
//
// The right-hand side may sit in memory ("add eax, dword ptr [rbp - 8]"). The
// load is emitted here and `src` names the temporary it landed in, so the caller
// only ever sees an ordinary register-to-register operation.
//
// Emits into `out` before knowing the instruction will lift, which is safe --
// lift() discards the whole run and starts an unknown on any later failure.
//
// The reverse form, "add dword ptr [rbp - 8], eax", reads-operates-writes back
// and isn't handled; it becomes an unknown.
bool Lifter::read_binary_operands(const Instruction& insn, std::optional<IrOperand>& dst,
                                  std::optional<IrOperand>& src, std::vector<IrInst>& out) {
    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 2) {
        return false;
    }
    if (is_memory_text(operands[0])) {
        return false;
    }

    dst = parse_operand(operands[0], IrType::none);
    if (!dst || dst->kind != OperandKind::reg) {
        return false;
    }

    if (is_memory_text(operands[1])) {
        std::optional<MemoryOperand> mem = parse_memory(operands[1]);
        if (!mem) {
            return false;
        }
        // The size keyword and the register have to agree, same as in a load.
        if (mem->width != IrType::none && mem->width != dst->type) {
            return false;
        }

        IrOperand address = emit_address(*mem, insn, out);
        IrOperand loaded = new_temp(dst->type);
        out.push_back(make_inst(Opcode::load, dst->type, loaded, {address}, insn.address));
        src = loaded;
        return true;
    }

    src = parse_operand(operands[1], dst->type);
    if (!src) {
        return false;
    }
    if (src->kind == OperandKind::reg && src->type != dst->type) {
        return false;
    }
    return true;
}

// cmp, which is a sub that throws the result away and keeps only the flags. It's
// the instruction the whole conditional-jump path depends on: a compiler emits
// cmp and then a jcc that reads what it wrote, so without this the branches
// lifted above are reading flags left over from whatever arithmetic ran last.
//
// test is the same idea over bit_and, and the two live together here because the
// only thing separating them is which operation runs and which flag set follows.
bool Lifter::lift_cmp_test(const Instruction& insn, bool logical, std::vector<IrInst>& out) {
    std::optional<IrOperand> dst;
    std::optional<IrOperand> src;
    if (!read_binary_operands(insn, dst, src, out)) {
        return false;
    }

    // The result goes to a temporary and stays there. That's the whole difference
    // from sub and and: neither operand is written back.
    IrOperand result = new_temp(dst->type);
    out.push_back(make_inst(logical ? Opcode::bit_and : Opcode::sub, dst->type, result,
                            {*dst, *src}, insn.address));

    if (logical) {
        emit_logic_flags(result, insn.address, out);
    } else {
        emit_arith_flags(*dst, *src, result, true, insn.address, out);
    }
    return true;
}

// and, or and xor between two registers, or a register and a constant. Same
// shape as add and sub -- destination doubles as the left operand -- with the
// bitwise flag set instead of the arithmetic one.
bool Lifter::lift_bitwise(const Instruction& insn, Opcode op, std::vector<IrInst>& out) {
    std::optional<IrOperand> dst;
    std::optional<IrOperand> src;
    if (!read_binary_operands(insn, dst, src, out)) {
        return false;
    }

    // Same ordering rule as lift_add_sub: compute into a temporary so the flag
    // operations still see the operand the instruction started with.
    IrOperand result = new_temp(dst->type);
    out.push_back(make_inst(op, dst->type, result, {*dst, *src}, insn.address));
    emit_logic_flags(result, insn.address, out);
    out.push_back(make_inst(Opcode::assign, dst->type, *dst, {result}, insn.address));
    return true;
}

// add and sub. Same shape, so `subtract` picks the opcode and the flag rule.
bool Lifter::lift_add_sub(const Instruction& insn, bool subtract, std::vector<IrInst>& out) {
    std::optional<IrOperand> dst;
    std::optional<IrOperand> src;
    if (!read_binary_operands(insn, dst, src, out)) {
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

// The two imul forms that keep the product at the operand's width. The
// one-operand form spreads a double-width result across rdx:rax, which no IR type
// holds, so it becomes an unknown -- as does mul, which only has that form.
//
// Nothing here is signedness-specific: the low half of a product is the same bit
// pattern either way, which is why compilers use imul on unsigned code too.
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

// div and idiv: divide rdx:rax by the operand, quotient to rax, remainder to rdx.
//
// The double-width dividend has no IR type. Compilers never use the extra width
// though -- an unsigned divide clears rdx first, a signed one runs cdq or cqo to
// fill it with rax's sign bit -- so dividing rax at its own width gives the same
// answer.
//
// Hand-written code with a real value in rdx lifts wrong here. It's the one place
// we answer without being able to show we're right, and wants revisiting once
// use-def can trace what wrote rdx.
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

// The flag reads behind a conditional jump. The single-flag conditions cost
// nothing -- a flag register is already an i1 -- and the rest are one or two
// operations on top.
//
// jp and jnp read a pf nothing writes, so those branches read a stale value.
// Lifting them anyway beats the alternative: an unknown mid-function costs the
// whole block after it, and this at least has the shape right.
std::optional<IrOperand> Lifter::emit_condition(std::string_view mnemonic, std::uint64_t address,
                                                std::vector<IrInst>& out) {
    std::optional<ConditionCode> code = condition_code(mnemonic);
    if (!code) {
        return std::nullopt;
    }

    const IrType bit = IrType::i1;
    IrOperand condition;

    switch (code->test) {
    case FlagTest::overflow:
        condition = make_reg("of", bit);
        break;
    case FlagTest::carry:
        condition = make_reg("cf", bit);
        break;
    case FlagTest::zero:
        condition = make_reg("zf", bit);
        break;
    case FlagTest::sign:
        condition = make_reg("sf", bit);
        break;
    case FlagTest::parity:
        condition = make_reg("pf", bit);
        break;
    case FlagTest::below_equal:
        // Unsigned <=, which is < or equal, which is cf or zf.
        condition = new_temp(bit);
        out.push_back(make_inst(Opcode::bit_or, bit, condition,
                                {make_reg("cf", bit), make_reg("zf", bit)}, address));
        break;
    case FlagTest::less:
        // Signed <. The subtraction the compare did came out negative, or it
        // overflowed and came out positive when it shouldn't have -- either way
        // the two flags disagree, and they agree when the result was really
        // positive. Hence a straight comparison of sf against of.
        condition = new_temp(bit);
        out.push_back(make_inst(Opcode::cmp_ne, bit, condition,
                                {make_reg("sf", bit), make_reg("of", bit)}, address));
        break;
    case FlagTest::less_equal: {
        IrOperand differs = new_temp(bit);
        out.push_back(make_inst(Opcode::cmp_ne, bit, differs,
                                {make_reg("sf", bit), make_reg("of", bit)}, address));
        condition = new_temp(bit);
        out.push_back(
            make_inst(Opcode::bit_or, bit, condition, {make_reg("zf", bit), differs}, address));
        break;
    }
    }

    // The jn... half of the pair. bit_not on a one-bit value is just the flip,
    // so the negated conditions cost one operation more than the plain ones and
    // don't need their own arm above.
    if (code->negate) {
        IrOperand flipped = new_temp(bit);
        out.push_back(make_inst(Opcode::bit_not, bit, flipped, {condition}, address));
        condition = flipped;
    }

    return condition;
}

// jmp in all three forms. Direct is the common case and capstone hands over the
// address. The indirect forms have no number to put in the operation, so the
// register or loaded value goes in instead and the IR says "control goes wherever
// this points" -- as much as anyone can say without tracing the register.
bool Lifter::lift_jmp(const Instruction& insn, std::vector<IrInst>& out) {
    const IrType width = IrType::i64;

    if (std::optional<std::uint64_t> target = branch_target(insn)) {
        out.push_back(make_inst(Opcode::jump, IrType::none, IrOperand{},
                                {make_imm(*target, width)}, insn.address));
        return true;
    }

    std::vector<std::string_view> operands = split_operands(insn.op_str);
    if (operands.size() != 1) {
        return false;
    }

    if (!is_memory_text(operands[0])) {
        // "jmp rax". A jump through a 32-bit register isn't a thing in 64-bit
        // mode, so anything narrower means we misread the operand.
        std::optional<IrOperand> target = parse_operand(operands[0], IrType::none);
        if (!target || target->kind != OperandKind::reg || target->type != width) {
            return false;
        }
        out.push_back(make_inst(Opcode::jump, IrType::none, IrOperand{}, {*target}, insn.address));
        return true;
    }

    // "jmp qword ptr [rax*8 + 0x4020]", which is a switch statement nine times
    // out of ten. The destination is sitting in the jump table rather than in
    // the instruction, so read it out and jump to whatever came back.
    std::optional<MemoryOperand> mem = parse_memory(operands[0]);
    if (!mem || (mem->width != IrType::none && mem->width != width)) {
        return false;
    }

    IrOperand address = emit_address(*mem, insn, out);
    IrOperand loaded = new_temp(width);
    out.push_back(make_inst(Opcode::load, width, loaded, {address}, insn.address));
    out.push_back(make_inst(Opcode::jump, IrType::none, IrOperand{}, {loaded}, insn.address));
    return true;
}

// A conditional jump: the flag test, then the branch reading it.
//
// Both destinations are spelled out, including the fall-through, so a pass can
// see where a branch goes without knowing the instruction's length or holding the
// rest of the stream.
bool Lifter::lift_jcc(const Instruction& insn, std::vector<IrInst>& out) {
    // There's no indirect form of a conditional jump -- the encoding only takes
    // a relative offset -- so a target we couldn't read means we misread the
    // operand rather than that the jump goes somewhere we can't name.
    std::optional<std::uint64_t> target = branch_target(insn);
    if (!target) {
        return false;
    }

    std::optional<IrOperand> condition = emit_condition(insn.mnemonic, insn.address, out);
    if (!condition) {
        return false;
    }

    const IrType width = IrType::i64;
    std::uint64_t fall_through = insn.address + insn.size;
    out.push_back(make_inst(Opcode::branch, IrType::none, IrOperand{},
                            {*condition, make_imm(*target, width), make_imm(fall_through, width)},
                            insn.address));
    return true;
}

// call, in the same three forms as jmp. The target resolution is lift_jmp again;
// what differs is everything around it.
//
// The operation takes the target plus all six argument registers, and writes rax.
// Every one of those is an over-statement in the safe direction, so a later pass
// doesn't delete something the callee needed.
//
// Two things it can't say, both of which use-def will have to handle itself. A
// call also clobbers the rest of the caller-saved set, and IrInst has one
// destination slot with nowhere to put that. And a float or struct return comes
// back somewhere other than rax, which needs xmm registers the IR lacks.
//
// The stack is left alone deliberately. A call pushes a return address and the
// callee's ret pops it, so rsp is unchanged from the caller's view. Writing the
// push without the matching pop -- which happens in a function we may never lift
// -- would shift every rsp-relative offset after the call by eight.
bool Lifter::lift_call(const Instruction& insn, std::vector<IrInst>& out) {
    const IrType width = IrType::i64;
    std::optional<IrOperand> target;

    if (std::optional<std::uint64_t> direct = branch_target(insn)) {
        target = make_imm(*direct, width);
    } else {
        std::vector<std::string_view> operands = split_operands(insn.op_str);
        if (operands.size() != 1) {
            return false;
        }

        if (!is_memory_text(operands[0])) {
            // "call rax", usually a function pointer or a virtual dispatch. A
            // narrower register can't hold a 64-bit code address, so anything
            // but i64 means we misread the operand.
            std::optional<IrOperand> reg = parse_operand(operands[0], IrType::none);
            if (!reg || reg->kind != OperandKind::reg || reg->type != width) {
                return false;
            }
            target = *reg;
        } else {
            // "call qword ptr [rip + 0x2f42]", which is how a call through the
            // GOT is written. The address of the function is in the table, not
            // in the instruction, so load it and call whatever came back.
            std::optional<MemoryOperand> mem = parse_memory(operands[0]);
            if (!mem || (mem->width != IrType::none && mem->width != width)) {
                return false;
            }

            IrOperand address = emit_address(*mem, insn, out);
            IrOperand loaded = new_temp(width);
            out.push_back(make_inst(Opcode::load, width, loaded, {address}, insn.address));
            target = loaded;
        }
    }

    std::vector<IrOperand> args;
    args.reserve(1 + std::size(argument_registers));
    args.push_back(*target);
    for (const char* name : argument_registers) {
        args.push_back(make_reg(name, width));
    }

    out.push_back(
        make_inst(Opcode::call, width, make_reg("rax", width), std::move(args), insn.address));
    return true;
}

// ret, which reads rax and leaves.
//
// Naming rax is the same bet as naming the argument registers at a call: a void
// function leaves nothing meaningful there, but a discarded return value is a
// much cheaper mistake than a deleted one.
//
// "ret 0x10" pops that many bytes of arguments, and we ignore the number --
// control has left the function, so nothing we go on to lift reads that rsp.
bool Lifter::lift_ret(const Instruction& insn, std::vector<IrInst>& out) {
    out.push_back(make_inst(Opcode::ret, IrType::none, IrOperand{},
                            {make_reg("rax", IrType::i64)}, insn.address));
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

    // cmp and test come before the arithmetic below because they share its
    // operand shape but write no destination.
    if (insn.mnemonic == "cmp" || insn.mnemonic == "test") {
        if (lift_cmp_test(insn, insn.mnemonic == "test", out)) {
            return out;
        }
        out.clear();
    }

    if (insn.mnemonic == "and" || insn.mnemonic == "or" || insn.mnemonic == "xor") {
        Opcode op = insn.mnemonic == "and"  ? Opcode::bit_and
                    : insn.mnemonic == "or" ? Opcode::bit_or
                                            : Opcode::bit_xor;
        if (lift_bitwise(insn, op, out)) {
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

    if (insn.mnemonic == "jmp") {
        if (lift_jmp(insn, out)) {
            return out;
        }
        out.clear();
    }

    if (insn.mnemonic == "call") {
        if (lift_call(insn, out)) {
            return out;
        }
        out.clear();
    }

    // Only the near return. retf pops a segment selector as well and only turns
    // up in code that switches privilege levels, which isn't anything we're
    // going to be handed a function from, so it stays an unknown.
    if (insn.mnemonic == "ret") {
        if (lift_ret(insn, out)) {
            return out;
        }
        out.clear();
    }

    // Anything else starting with a j is a conditional jump, or close enough to
    // try: lift_jcc looks the mnemonic up in its own table, so the handful that
    // aren't -- jrcxz, and loop if capstone ever spells it with a j -- back out
    // of here and end up as unknowns like anything else we don't model.
    if (!insn.mnemonic.empty() && insn.mnemonic.front() == 'j') {
        if (lift_jcc(insn, out)) {
            return out;
        }
        out.clear();
    }

    out.push_back(make_unknown(insn.address));
    return out;
}

}  // namespace minidec
