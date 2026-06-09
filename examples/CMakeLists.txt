# Compiles the sample C programs in examples/c into the build dir so we have
# real binaries to throw at minidec while testing. This is opt-in: nothing
# here is built unless you ask for the "examples" target explicitly, e.g.
#   cmake --build build --target examples

# We only need a plain C compiler here. The main project is CXX-only so the C
# language isn't enabled, which is why we shell out to the compiler by hand
# instead of using add_executable.
find_program(EXAMPLE_CC NAMES clang gcc cc)

if(NOT EXAMPLE_CC)
    message(STATUS "minidec: no C compiler found, skipping examples target")
    return()
endif()

file(GLOB EXAMPLE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/c/*.c")

set(EXAMPLE_BINARIES "")
foreach(src ${EXAMPLE_SOURCES})
    # strip the .c so hello.c becomes a binary just called "hello"
    get_filename_component(name ${src} NAME_WE)
    set(out "${CMAKE_CURRENT_BINARY_DIR}/${name}")

    # -O0 keeps the output close to the source and -g leaves the symbols in,
    # which makes the disassembly a lot easier to follow later on.
    add_custom_command(
        OUTPUT ${out}
        COMMAND ${EXAMPLE_CC} -O0 -g -o ${out} ${src}
        DEPENDS ${src}
        COMMENT "compiling example ${name}"
        VERBATIM
    )
    list(APPEND EXAMPLE_BINARIES ${out})
endforeach()

# Grouping everything under one target means "build the examples" is a single
# command. EXCLUDE_FROM_ALL would be the executable equivalent, but custom
# targets already stay out of the default build unless something depends on them.
add_custom_target(examples DEPENDS ${EXAMPLE_BINARIES})
