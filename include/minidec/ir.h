#ifndef MINIDEC_IR_H
#define MINIDEC_IR_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace minidec {

// The low-level IR everything from here on works on. x86-64 is far too big and
// too irregular to analyse directly -- one "add" can write four flags, an
// operand can hide a whole base+index*scale+disp address calculation, and the
// same operation shows up under a dozen different encodings. So instead of
// teaching every later pass about all of that, we lift each machine instruction
// into a short run of these much simpler operations once, and the passes only
// ever see the simple version.
//
// Two rules keep it simple enough to be worth the trouble:
//
//   1. Every operation does exactly one thing. If an x86 instruction has a side
//      effect (setting flags, bumping a register) that becomes its own separate
//      IR operation, so nothing is implicit.
//   2. Only load and store touch memory. Everything else works on registers,
//      temporaries and constants. An address is worked out with ordinary
//      arithmetic into a temporary first, and that temporary is what gets handed
//      to the load or store.
//
// Rule 2 is the one that pays off later: because no operand can hide a memory
// address inside it, the use-def pass (step 45) and SSA construction (step 46)
// can find every value an operation reads just by walking its argument list,
// without having to know anything about addressing modes.

// The width an operation works at. Everything in x86-64 is a fixed-width bit
// pattern, so the type is really just a size -- there's no signedness here on
// purpose. Whether a value is treated as signed is a property of the operation,
// not the value, which is why div_s and div_u are separate opcodes below.
//
// i1 is the odd one out at one bit wide: it's what comparisons produce and what
// the flag registers hold, so a conditional branch reads an i1.
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

// What an operand actually refers to.
enum class OperandKind {
    none,  // an unused slot, e.g. the dst of an operation that returns nothing
    reg,   // a machine register, by name
    temp,  // a value the lifter invented, numbered
    imm,   // a constant baked into the instruction
};

// One input or output of an operation. Deliberately small and flat: no nesting,
// no memory addressing, no sub-expressions. An operation's arguments are just a
// list of these, and that's the whole story of what it reads.
//
// Machine registers are held as a name rather than an enum so we can take
// whatever capstone hands us without maintaining a table of every x86 register
// and its aliases. It also means the flags come along for free -- "zf", "sf" and
// friends are just i1 registers as far as the IR cares, which is exactly how the
// lifter models the flag writes an arithmetic instruction does.
//
// Temporaries are the values that only exist inside the IR: the address a load
// reads from, the intermediate result of a two-step operation, anything without
// a machine register to live in. They're numbered per function and never reused,
// so a temp id identifies one value for the whole function.
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

// Building operands by hand is tedious enough that the lifter would be mostly
// boilerplate without these. Free functions rather than constructors so
// IrOperand stays a plain aggregate that can still be brace-initialised.
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

// The operation set. Kept small on purpose: every one of these has to be handled
// by every pass that walks the IR, so a new opcode has a real cost and only
// earns its place if it can't be built out of the ones already here. Anything
// x86 can do that isn't in this list gets lifted into a sequence of these
// instead.
//
// The signed and unsigned versions of divide, remainder, shift-right and compare
// are split because the operands carry a width but no signedness -- the
// operation is the only place that information can live.
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
    call,    // arg0 is the target address; dst is the return value if it's used
    ret,     // arg0 is the returned value, or no arguments if there isn't one

    // The escape hatch. An instruction the lifter doesn't handle yet becomes one
    // of these so the rest of the function can still be analysed around it. Any
    // pass that sees one has to assume the worst, since we can't say what it did.
    unknown,
};

// Opcode name for printing, matching the enumerator spelling. Mostly for
// debugging and test failure output -- the pseudocode emitter in phase 7 prints
// C, not this.
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

// Whether this opcode writes a destination. The ones that don't are the stores,
// the control-flow operations and nop. A call is in the yes column even though
// plenty of calls throw the result away -- whether the dst slot is filled in is
// up to the lifter, this only says the opcode is allowed one.
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

// Does control leave the block after this operation? Used when the lifted
// instructions get grouped back up into blocks.
inline bool is_terminator(Opcode op) {
    return op == Opcode::jump || op == Opcode::branch || op == Opcode::ret;
}

// One IR operation. The arguments live in a vector rather than fixed slots
// because the count genuinely varies -- one for neg, two for add, three for
// branch, and a call could name any number of them once we know the calling
// convention (step 44).
//
// type is the width the operation works at, which isn't always the width of its
// arguments: a cmp reads two i64s and produces an i1, and a trunc's type is what
// it's narrowing to. Where they do agree it's still worth having spelled out,
// since it saves every pass from reaching into args[0] to find out.
//
// address is the machine instruction this came from, and several operations
// lifted out of the same instruction all carry the same one. It's what lets the
// output stage line pseudocode back up against the disassembly, so it's worth
// keeping even though no analysis pass needs it.
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
