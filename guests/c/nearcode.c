/* Memory asked for near the program's own code, as a JIT asks for room for
 * machine code its own code reaches with a branch (LuaJIT probes addresses
 * within 128 MiB of its exit handler, with a hint, until one is given):
 * a free address given as a hint is where the mapping goes. Every line
 * printed is what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int munmap(void *addr, size_t len);
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

#define SIZE (64u << 10)
/* LuaJIT's reach on arm64: a branch's, less 2 MiB. */
#define RANGE ((1ul << 26) - (1ul << 21))

static void *at(uintptr_t hint) {
    return mmap((void *)hint, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int within(uintptr_t p, uintptr_t target) {
    return p + SIZE - target < RANGE || target - p < RANGE;
}

int main(void) {
    uintptr_t target = (uintptr_t)(void *)main & ~(uintptr_t)0xffff;

    /* 32 MiB below the program's code. */
    uintptr_t below = target - (32u << 20);
    void *p = at(below);
    printf("below its code: %s\n", p == (void *)below ? "at the hint" : "elsewhere");
    if (p != MAP_FAILED) {
        munmap(p, SIZE);
    }

    /* LuaJIT's probe: 32 tries at 64 KiB-aligned addresses within reach,
     * each kept only if it lands within reach. */
    uint64_t x = 0x9e3779b97f4a7c15u;
    int found = 0;
    for (int i = 0; i < 32 && !found; i++) {
        uintptr_t hint;
        do {
            x = x * 6364136223846793005u + 1442695040888963407u;
            hint = (x >> 16) & ((1ul << 27) - 0x10000);
        } while (!(hint + SIZE < RANGE + RANGE));
        hint = target + hint - RANGE;
        void *q = at(hint);
        if (q == MAP_FAILED) {
            continue;
        }
        found = within((uintptr_t)q, target);
        munmap(q, SIZE);
    }
    printf("probing within reach: %s\n", found ? "found" : "none");
    return 0;
}
