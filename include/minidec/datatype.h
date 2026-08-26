#ifndef MINIDEC_DATATYPE_H
#define MINIDEC_DATATYPE_H

#include <cstddef>
#include <string>
#include <vector>

#include "minidec/ir.h"
#include "minidec/ssa.h"

namespace minidec {

// Which of the values in a function are numbers and which are addresses.
//
// Nothing in the IR says. A register is sixty-four bits wide and an add is an
// add, so "add rax, rbx" reads exactly the same whether it is summing two
// counters or stepping a pointer along an array. The only thing left to go on is
// what the rest of the function does with the result.
//
// So the pass works inwards from the operations that can mean one thing and not
// the other. An address is whatever a load or a store dereferences, and whatever
// rsp and rbp hold. A number is whatever gets multiplied, divided, shifted, or
// compared as signed. Between those two ends sit the adds and subtracts, which
// carry the answer along: a pointer plus a number is a pointer, a pointer minus
// a pointer is a number, and read the other way round each of those settles an
// operand instead of the result.
//
// Width decides the easy half before any of that starts. Nothing narrower than
// sixty-four bits is an address on x86-64, so every other width is a number
// already -- bar a single bit, which is a condition. Only the 64-bit values are
// really in question, which on ordinary code is a small share of them.
//
// These are guesses. A function that never dereferences a pointer it was handed
// leaves it looking like any other 64-bit value, and a value used both ways is
// reported as such rather than resolved: which of the two pieces of evidence was
// wrong is not something this pass can see.
//
// Floating point is left out because the lifter does not produce f32 or f64 yet,
// so there is nothing of that shape here to classify.

enum class DataType {
    unknown, // nothing in the function pinned it down
    boolean, // one bit: a comparison result or a flag
    integer,
    pointer,
    conflict, // used as both a number and an address
};

const char* data_type_name(DataType type);

// One value and what it is being used as. Registers are held under their 64-bit
// name, the same folding SSA versions them with, so eax and al land on rax.
struct ValueType {
    OperandKind kind = OperandKind::none; // reg or temp; nothing else holds a value
    std::string reg;
    unsigned version = 0;
    unsigned temp_id = 0;

    // The widest spelling seen, in bits. A value only ever written through eax is
    // 32 bits wide however the reads spell it.
    unsigned width = 0;

    DataType type = DataType::unknown;
};

struct TypeMap {
    // Registers by name and then version, then the temporaries by id, so the
    // same function always gives the same list.
    std::vector<ValueType> values;

    bool empty() const { return values.empty(); }
    std::size_t size() const { return values.size(); }

    // Constants and empty operands are not values anything here tracks, so they
    // come back unknown rather than being an error to ask about.
    DataType type_of(const IrOperand& operand) const;
    DataType type_of(const std::string& reg, unsigned version) const;
    DataType type_of_temp(unsigned id) const;

    // Values the two halves of the pass disagreed about. A handful is normal on
    // hand-written or optimised code; a lot of them means something upstream is
    // lifting an instruction wrongly.
    std::size_t conflicts() const;
};

// Classify every register version and temporary in the function.
TypeMap infer_data_types(const SsaFunction& fn);

} // namespace minidec

#endif // MINIDEC_DATATYPE_H
