/* A static executable linked at a fixed address below 4 GiB, which macOS
 * keeps from every process: fwe moves it higher when its link kept its
 * relocations (`--emit-relocs`), changing each absolute address it holds.
 * Built with `-mcmodel=large`, so code builds addresses from 16-bit pieces
 * (`movz`/`movk`) too. It prints what it reaches through each kind, and
 * whether it runs where it was linked.
 *
 * Freestanding: its own `_start` and system calls, no C library. */

typedef unsigned long u64;

static long sys(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static u64 len(const char *s) {
    u64 n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

static void put(const char *s) {
    sys(64, 1, (long)s, (long)len(s));
}

static const char *one(void) { return "one"; }
static const char *two(void) { return "two"; }

/* Pointers in data: functions, strings, and a global's address. */
static const char *(*const fns[])(void) = {one, two};
static const char *const words[] = {"alpha", "beta"};
static int target = 42;
static int *const where = &target;

/* Set by a constructor that `.init_array` names. */
static const char *by_ctor = "not run";
static void ctor(void) { by_ctor = "ran"; }
__attribute__((section(".init_array"), used)) static void (*const init_entry)(void) = ctor;

static volatile long zero = 0;

extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

void _start(void) {
    for (void (**f)(void) = __init_array_start; f < __init_array_end; f++) {
        (*f)();
    }
    /* An index the compiler cannot know (0), so the tables are read. */
    long i = zero;
    put(fns[i]());
    put(" ");
    put(fns[i + 1]());
    put(" ");
    put(words[i]);
    put(" ");
    put(words[i + 1]);
    put(*where == 42 ? " target" : " lost");
    put(" ctor ");
    put(by_ctor);
    /* Where `_start` runs: above 4 GiB once moved. */
    put((u64)&_start >> 32 ? " above\n" : " below\n");
    sys(93, 0, 0, 0);
}
