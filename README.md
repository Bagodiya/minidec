# minidec

A small decompiler for x86-64 ELF and Mach-O binaries, written in C++17.

`minidec` reads compiled binaries, disassembles selected functions, recovers
control flow and basic types, and emits readable C-like pseudocode. It's a
study project intended to make the inner workings of tools like Ghidra and
Hex-Rays approachable.

## Requirements

- A C++17 compiler (Clang 10+, GCC 9+)
- CMake 3.16 or newer
- [Capstone](https://www.capstone-engine.org/) for disassembly
- [LIEF](https://lief.re/) for binary parsing

On macOS:

```sh
brew install capstone lief cmake
```

## Build

```sh
cmake -B build
cmake --build build
```

## Usage

List symbols in a binary:

```sh
./build/minidec symbols examples/hello
```

Disassemble a function:

```sh
./build/minidec disasm examples/hello --func main
```

Decompile a function to C-like pseudocode:

```sh
./build/minidec decompile examples/hello --func main
```

## Project Structure

```
minidec/
├── include/minidec/   Public headers
├── src/               Implementation
├── tests/             Unit tests
├── examples/c/        Sample C programs to compile and decompile
└── CMakeLists.txt     Build configuration
```

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
