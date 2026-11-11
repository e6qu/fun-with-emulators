/* A program for a debugger to step through: built with debug information,
 * unoptimized, so its functions, arguments and locals are as written.
 * Freestanding, as the other C guests: only the C library's `printf`. */

int printf(const char *format, ...);

int add(int a, int b) {
    int sum = a + b;
    return sum;
}

int main(void) {
    int total = 0;
    for (int i = 1; i <= 3; i++) {
        total = add(total, i);
    }
    printf("total %d\n", total);
    return 0;
}
