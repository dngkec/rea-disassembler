/* Freestanding ELF corpus (no libc): known functions, strings, branches. */
static const char kBanner[] = "rea-disassembler-corpus-v1";
static const char kSecret[] = "string-xref-target-12345";
int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }
int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
int classify(int x) {
    switch (x) { case 0: return 100; case 1: return 200; case 2: return 300; default: return -1; }
}
const char *banner(void) { return kBanner; }
const char *secret(void) { return kSecret; }
int sum_array(const int *a, int n) { int s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
void _start(void) {
    int xs[] = {1, 2, 3, 4};
    volatile int r = fib(6) + classify(1) + sum_array(xs, 4) + add(mul(2, 3), banner()[0] + secret()[0]);
    (void)r;
#if defined(__linux__) && defined(__x86_64__)
    __asm__ volatile("syscall" :: "a"(60L), "D"((long)(r == 0)));
#endif
}
