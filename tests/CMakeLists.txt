include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.5.2
)
FetchContent_MakeAvailable(Catch2)

add_executable(minidec_tests
    test_smoke.cpp
    test_cli.cpp
    test_binary.cpp
    test_disasm.cpp
    test_cfg.cpp
    test_lift.cpp
    ${CMAKE_SOURCE_DIR}/src/cli.cpp
    ${CMAKE_SOURCE_DIR}/src/cmd_symbols.cpp
    ${CMAKE_SOURCE_DIR}/src/cmd_disasm.cpp
    ${CMAKE_SOURCE_DIR}/src/cmd_cfg.cpp
    ${CMAKE_SOURCE_DIR}/src/cmd_ir.cpp
    ${CMAKE_SOURCE_DIR}/src/disasm.cpp
    ${CMAKE_SOURCE_DIR}/src/elf_loader.cpp
    ${CMAKE_SOURCE_DIR}/src/macho_loader.cpp
    ${CMAKE_SOURCE_DIR}/src/cfg.cpp
    ${CMAKE_SOURCE_DIR}/src/lift.cpp
    ${CMAKE_SOURCE_DIR}/src/usedef.cpp
)
target_link_libraries(minidec_tests PRIVATE Catch2::Catch2WithMain LIEF::LIEF ${CAPSTONE_LIBRARIES})
target_include_directories(minidec_tests PRIVATE ${CMAKE_SOURCE_DIR}/include ${CAPSTONE_INCLUDE_DIRS})

# Let test_binary.cpp locate the checked-in fixtures regardless of cwd.
target_compile_definitions(minidec_tests PRIVATE
    MINIDEC_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(minidec_tests)
