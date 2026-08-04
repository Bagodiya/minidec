#ifndef MINIDEC_IR_H
#define MINIDEC_IR_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace minidec {

// The IR everything downstream works on. x86-64 is too irregular to analyse
// directly -- one "add" writes four flags, an operand can hide a whole
// base+index*scale+disp calculation -- so each instruction is lifted once into a
// run of much simpler operations.
//
// Two rules:
//
//   1. Every operation does exactly one thing. Side effects become their own
//      operations, so nothing is implicit.
//   2. Only load and store touch memory. Addresses are computed into a temporary
//      first, and that temporary is what the load or store takes.
//
// Rule 2 is what pays off: with no address hidden inside an operand, use-def and
// SSA can find every value an operation reads by walking its argument list.

// The width an operation works at. No signedness: that's a property of the
// operation, not the value, which is why div_s and div_u are separate opcodes.
//
// i1 is what comparisons produce and what the flag registers hold.
enum class IrType {
    none,  // the operation produces no value at all (store, jump, ret)
    i1,
    i8,
    i16,
    i32,
    i64,
    f32,
    f64,
};

// How wide the type is in bits. Returns 0 for none, which has no width.
inline unsigned type_bits(IrType type) {
    switch (type) {
    case IrType::i1:
        return 1;
    case IrType::i8:
        return 8;
    case IrType::i16:
        return 16;
    case IrType::i32:
        return 32;
    case IrType::f32:
        return 32;
    case IrType::i64:
        return 64;
    case IrType::f64:
        return 64;
    case IrType::none:
        return 0;
    }
    return 0;
}

// none prints as "-" so a listing keeps its columns.
inline const char* type_name(IrType type) {
    switch (type) {
    case IrType::none:
        return "-";
    case IrType::i1:
        return "i1";
    case IrType::i8:
        return "i8";
    case IrType::i16:
        return "i16";
    case IrType::i32:
        return "i32";
    case IrType::i64:
        return "i64";
    case IrType::f32:
        return "f32";
    case IrType::f64:
        return "f64";
    }
    return "?";
}

// What an operand actually refers to.
enum class OperandKind {
    none,  // an unused slot, e.g. the dst of an operation that returns nothing
    reg,   // a machine register, by name
    temp,  // a value the lifter invented, numbered
    imm,   // a constant baked into the instruction
};

// One input or output. Flat by design: no nesting, no addressing, no
// sub-expressions, so an operation's argument list is the whole story of what it
// reads.
//
// Registers are held by name rather than as an enum, which avoids maintaining a
// table of every x86 register and its aliases, and means the flags come along
// free as i1 registers.
//
// Temporaries are values that only exist in the IR. Numbered per function and
// never reused, so an id identifies one value throughout.
struct IrOperand {
    OperandKind kind = OperandKind::none;
    IrType type = IrType::none;

    std::string reg;         // register name when kind == reg, e.g. "rax", "zf"
    unsigned temp_id = 0;    // temp number when kind == temp
    std::uint64_t imm = 0;   // constant value when kind == imm

    bool is_none() const { return kind == OperandKind::none; }

    // A constant is the only kind we can read a value out of without running
    // anything, so folding and target resolution check for this a lot.
    bool is_const() const { return kind == OperandKind::imm; }
};

// Free functions rather than constructors, so IrOperand stays a plain aggregate
// that can still be brace-initialised.
inline IrOperand make_reg(std::string name, IrType type) {
    IrOperand operand;
    operand.kind = OperandKind::reg;
    operand.type = type;
    operand.reg = std::move(name);
    return operand;
}

inline IrOperand make_temp(unsigned id, IrType type) {
    IrOperand operand;
    operand.kind = OperandKind::temp;
    operand.type = type;
    operand.temp_id = id;
    return operand;
}

inline IrOperand make_imm(std::uint64_t value, IrType type) {
    IrOperand operand;
    operand.kind = OperandKind::imm;
    operand.type = type;
    operand.imm = value;
    return operand;
}

// Kept small on purpose: every pass that walks the IR has to handle every
// opcode, so a new one only earns its place if it can't be built from these.
//
// Signed and unsigned divide, remainder, shift-right and compare are split
// because operands carry width but no signedness.
enum class Opcode {
    nop,     // does nothing; a padding or placeholder slot
    assign,  // dst = arg0, a plain copy between registers/temps

    // Arithmetic. Two arguments, result the same width as both of them.
    add,
    sub,
    mul,
    div_u,
    div_s,
    rem_u,
    rem_s,
    neg,  // one argument: dst = -arg0

    // Bitwise. The bit_ prefix isn't decoration -- and, or, xor and not are all
    // reserved alternative tokens in C++, so they can't be enumerator names.
    bit_and,
    bit_or,
    bit_xor,
    bit_not,  // one argument
    shl,
    shr_u,  // logical shift right, zeros shifted in
    shr_s,  // arithmetic shift right, sign bit shifted in

    // Comparisons. Two arguments of the same width, result always i1. Only eq,
    // ne, lt and le are here: gt and ge are the same operations with the
    // arguments the other way round, so the lifter swaps them instead.
    cmp_eq,
    cmp_ne,
    cmp_lt_u,
    cmp_lt_s,
    cmp_le_u,
    cmp_le_s,

    // Width changes, all one argument. The IrInst's type says the width being
    // converted to, the argument's own type says what it's coming from.
    zext,   // widen, filling with zeros
    sext,   // widen, filling with the sign bit
    trunc,  // narrow, dropping the high bits

    // The only two operations that touch memory. load reads from the address in
    // arg0 into dst; store writes arg1 to the address in arg0 and has no result.
    load,
    store,

    // Control flow. These always end a block.
    jump,    // unconditional, to the address in arg0
    branch,  // arg0 is an i1 condition, arg1 the taken address, arg2 the
             // fall-through address
    call,    // arg0 is the target address, the rest the argument registers the
             // callee might read; dst is where the return value comes back
    ret,     // arg0 is the returned value, or no arguments if there isn't one

    // The escape hatch. An instruction the lifter doesn't handle yet becomes one
    // of these so the rest of the function can still be analysed around it. Any
    // pass that sees one has to assume the worst, since we can't say what it did.
    unknown,
};

// For debugging and test failure output.
inline const char* opcode_name(Opcode op) {
    switch (op) {
    case Opcode::nop:
        return "nop";
    case Opcode::assign:
        return "assign";
    case Opcode::add:
        return "add";
    case Opcode::sub:
        return "sub";
    case Opcode::mul:
        return "mul";
    case Opcode::div_u:
        return "div_u";
    case Opcode::div_s:
        return "div_s";
    case Opcode::rem_u:
        return "rem_u";
    case Opcode::rem_s:
        return "rem_s";
    case Opcode::neg:
        return "neg";
    case Opcode::bit_and:
        return "bit_and";
    case Opcode::bit_or:
        return "bit_or";
    case Opcode::bit_xor:
        return "bit_xor";
    case Opcode::bit_not:
        return "bit_not";
    case Opcode::shl:
        return "shl";
    case Opcode::shr_u:
        return "shr_u";
    case Opcode::shr_s:
        return "shr_s";
    case Opcode::cmp_eq:
        return "cmp_eq";
    case Opcode::cmp_ne:
        return "cmp_ne";
    case Opcode::cmp_lt_u:
        return "cmp_lt_u";
    case Opcode::cmp_lt_s:
        return "cmp_lt_s";
    case Opcode::cmp_le_u:
        return "cmp_le_u";
    case Opcode::cmp_le_s:
        return "cmp_le_s";
    case Opcode::zext:
        return "zext";
    case Opcode::sext:
        return "sext";
    case Opcode::trunc:
        return "trunc";
    case Opcode::load:
        return "load";
    case Opcode::store:
        return "store";
    case Opcode::jump:
        return "jump";
    case Opcode::branch:
        return "branch";
    case Opcode::call:
        return "call";
    case Opcode::ret:
        return "ret";
    case Opcode::unknown:
        return "unknown";
    }
    return "?";
}

// Whether the opcode is allowed a destination. A call counts even though plenty
// discard the result -- whether dst is filled in is the lifter's business.
inline bool has_result(Opcode op) {
    switch (op) {
    case Opcode::nop:
    case Opcode::store:
    case Opcode::jump:
    case Opcode::branch:
    case Opcode::ret:
    case Opcode::unknown:
        return false;
    default:
        return true;
    }
}

// Does control leave the block after this operation?
inline bool is_terminator(Opcode op) {
    return op == Opcode::jump || op == Opcode::branch || op == Opcode::ret;
}

// One IR operation. Arguments live in a vector because the count varies: one for
// neg, two for add, three for branch, seven for a call.
//
// `type` is the width the operation works at, which isn't always its arguments'
// width -- a cmp reads two i64s and produces an i1.
//
// `address` is the machine instruction this came from; several operations from
// the same instruction share it. No analysis pass needs it, but it's what lets
// output line up against the disassembly.
struct IrInst {
    Opcode op = Opcode::nop;
    IrType type = IrType::none;
    IrOperand dst;                 // the result, empty when the opcode has none
    std::vector<IrOperand> args;   // everything the operation reads, in order
    std::uint64_t address = 0;     // address of the x86 instruction behind this

    bool writes_result() const { return !dst.is_none(); }
    bool ends_block() const { return is_terminator(op); }
};

}  // namespace minidec

#endif  // MINIDEC_IR_H
