/* Ground-truth corpus: every function/string/branch below is known, so a
   disassembler can be scored exactly instead of argued about. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char kBanner[] = "rea-disassembler-corpus-v1";
static const char kSecret[] = "string-xref-target-12345";

int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }

int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

int classify(int x) {
    switch (x) {
        case 0: return 100;
        case 1: return 200;
        case 2: return 300;
        default: return -1;
    }
}

const char *banner(void) { return kBanner; }
const char *secret(void) { return kSecret; }

int sum_array(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}

double average(const int *a, int n) {
    if (n == 0) return 0.0;
    return (double)sum_array(a, n) / (double)n;
}

int main(int argc, char **argv) {
    int xs[] = {1, 2, 3, 4, 5, 6, 7, 8};
    printf("%s %s %d %d %d %.2f\n", banner(), secret(),
           fib(10), classify(argc), add(mul(3, 4), 5), average(xs, 8));
    return argc > 100 ? EXIT_FAILURE : EXIT_SUCCESS;
}
