/* A small "Hello, world" — the first thing we'll try to decompile.
 * Compile with: clang -O0 -o examples/hello examples/c/hello.c
 */

#include <stdio.h>

int main(void) {
    puts("Hello, world!");
    return 0;
}
