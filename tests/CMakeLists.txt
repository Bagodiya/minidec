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
    ${CMAKE_SOURCE_DIR}/src/cli.cpp
    ${CMAKE_SOURCE_DIR}/src/cmd_symbols.cpp
    ${CMAKE_SOURCE_DIR}/src/elf_loader.cpp
    ${CMAKE_SOURCE_DIR}/src/macho_loader.cpp
)
target_link_libraries(minidec_tests PRIVATE Catch2::Catch2WithMain LIEF::LIEF)
target_include_directories(minidec_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(minidec_tests)
