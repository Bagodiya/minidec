#include <catch2/catch_test_macros.hpp>

#include <string>

#include "minidec/binary.h"
#include "minidec/loader.h"

// MINIDEC_FIXTURES_DIR is set by tests/CMakeLists.txt so the test can find the
// checked-in object file no matter where ctest is run from.
namespace {
std::string fixture(const std::string& name) {
    return std::string(MINIDEC_FIXTURES_DIR) + "/" + name;
}
}  // namespace

TEST_CASE("load_binary reads the sample object as an x86_64 ELF", "[binary]") {
    auto bin = minidec::load_binary(fixture("sample_x86_64.o"));

    REQUIRE(bin.has_value());
    CHECK(bin->format == minidec::Format::Elf);
    CHECK(bin->arch == "x86_64");
    CHECK(bin->file_size > 0);
}

TEST_CASE("the function symbols from sample.c are all present", "[binary]") {
    auto bin = minidec::load_binary(fixture("sample_x86_64.o"));
    REQUIRE(bin.has_value());

    // add, sub and mul are the three functions in sample.c.
    for (const char* name : {"add", "sub", "mul"}) {
        const minidec::Symbol* sym = bin->symbol_by_name(name);
        REQUIRE(sym != nullptr);
        CHECK(sym->kind == minidec::SymbolKind::Function);
    }
}

TEST_CASE("a global variable comes through as an object symbol", "[binary]") {
    auto bin = minidec::load_binary(fixture("sample_x86_64.o"));
    REQUIRE(bin.has_value());

    const minidec::Symbol* counter = bin->symbol_by_name("global_counter");
    REQUIRE(counter != nullptr);
    CHECK(counter->kind == minidec::SymbolKind::Object);
    CHECK(counter->size == 4);  // a single int
}

TEST_CASE("the text section is loaded with its bytes", "[binary]") {
    auto bin = minidec::load_binary(fixture("sample_x86_64.o"));
    REQUIRE(bin.has_value());

    const minidec::Section* text = bin->section_by_name(".text");
    REQUIRE(text != nullptr);
    CHECK(text->size > 0);
    CHECK(text->bytes.size() == text->size);
}

TEST_CASE("loading a path that isn't there returns nothing", "[binary]") {
    auto bin = minidec::load_binary(fixture("does_not_exist.o"));
    CHECK_FALSE(bin.has_value());
}
