#include <catch2/catch_test_macros.hpp>

#include "minidec/cli.h"

TEST_CASE("version string reports 0.0.1", "[cli]") {
    REQUIRE(minidec::version_string() == "minidec 0.0.1");
}

TEST_CASE("help text lists the usage line and subcommands", "[cli]") {
    std::string help = minidec::help_text();

    REQUIRE(help.find("usage: minidec") != std::string::npos);
    REQUIRE(help.find("symbols") != std::string::npos);
    REQUIRE(help.find("disasm") != std::string::npos);
    REQUIRE(help.find("cfg") != std::string::npos);
    REQUIRE(help.find("decompile") != std::string::npos);
}
