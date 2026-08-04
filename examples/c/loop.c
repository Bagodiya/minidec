#include <stdio.h>

// A loop with a branch inside it, which is the smallest thing that gives the
// CFG something interesting to find: the for loop shows up as a back edge, and
// the if/else becomes a diamond hanging off the middle of it.
int classify(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (i % 3 == 0) {
            total += i;
        } else {
            total -= i;
        }
    }
    return total > 100 ? 1 : 0;
}

int main(void) {
    printf("%d\n", classify(30));
    return 0;
}
