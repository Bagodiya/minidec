cmake_minimum_required(VERSION 3.16)
project(minidec
    VERSION 0.0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Capstone does the actual instruction decoding later on. Nothing links
# against it yet, but look for it now so the build stops here with a clear
# message instead of failing in the middle of a later disasm step.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CAPSTONE QUIET capstone)
endif()

# pkg-config isn't installed by default on macOS, so fall back to looking
# for the header and library directly. The PATHS hints cover the usual
# Homebrew prefixes on Intel and Apple Silicon.
if(NOT CAPSTONE_FOUND)
    find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h
        PATHS /usr/local/opt/capstone/include /opt/homebrew/opt/capstone/include)
    find_library(CAPSTONE_LIBRARY NAMES capstone
        PATHS /usr/local/opt/capstone/lib /opt/homebrew/opt/capstone/lib)
    if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
        set(CAPSTONE_FOUND TRUE)
    endif()
endif()

if(CAPSTONE_FOUND)
    if(CAPSTONE_VERSION)
        message(STATUS "minidec: found capstone ${CAPSTONE_VERSION}")
    else()
        message(STATUS "minidec: found capstone")
    endif()
else()
    message(FATAL_ERROR
        "capstone not found. install it and re-run cmake:\n"
        "  macOS:  brew install capstone\n"
        "  ubuntu: sudo apt install libcapstone-dev")
endif()

# LIEF handles the ELF/Mach-O parsing in phase 2. It ships its own cmake
# config, so find_package picks up the imported target on both Homebrew and
# apt installs. Same idea as capstone above: check now, fail with a hint.
find_package(LIEF QUIET CONFIG)
if(LIEF_FOUND)
    message(STATUS "minidec: found LIEF ${LIEF_VERSION}")
else()
    message(FATAL_ERROR
        "LIEF not found. install it and re-run cmake:\n"
        "  macOS:  brew install lief\n"
        "  ubuntu: sudo apt install liblief-dev")
endif()

add_executable(minidec
    src/main.cpp
    src/cli.cpp
)
target_include_directories(minidec PRIVATE include)

enable_testing()
add_subdirectory(tests)
