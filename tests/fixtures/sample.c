// Source for sample_x86_64.o, the fixture used by test_binary.cpp.
//
// The .o is checked in so the tests don't depend on a cross-compiler being
// around. If you ever need to regenerate it, run this from the fixtures dir:
//
//   clang -target x86_64-linux-gnu -O0 -c sample.c -o sample_x86_64.o
//
// Keep the symbols below stable -- the tests check for these names by hand.

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }

int global_counter = 7;
