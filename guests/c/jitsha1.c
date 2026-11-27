/* A real program's SHA-1 compression run by translation: git's
 * `sha1_compression_states` (sha1dc, as Debian 13's GCC 14 compiled it,
 * x18 among the registers it computes in), read from the git binary the
 * first argument names at the file offset and length the next two give,
 * copied into memory made executable at run time, so fwe runs it by
 * translation, and checked against a plain SHA-1 compression of the same
 * blocks. The function takes no calls and no pc-relative data, so it runs
 * wherever it is copied. */
typedef unsigned int u32;
typedef unsigned long u64;

int printf(const char *fmt, ...);
int open(const char *path, int flags, ...);
long pread(int fd, void *buf, u64 n, long off);
void *mmap(void *addr, u64 len, int prot, int flags, int fd, long off);
int mprotect(void *addr, u64 len, int prot);
unsigned long strtoul(const char *s, char **end, int base);

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

typedef void (*compress_fn)(u32 ihv[5], const u32 m[16], u32 w[80], u32 states[80][5]);

static u32 rol(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

/* SHA-1's compression of one block, as FIPS 180-4 gives it. */
static void reference(u32 ihv[5], const unsigned char block[64]) {
    u32 w[80];
    for (int t = 0; t < 16; t++) {
        w[t] = (u32)block[4 * t] << 24 | (u32)block[4 * t + 1] << 16 |
               (u32)block[4 * t + 2] << 8 | block[4 * t + 3];
    }
    for (int t = 16; t < 80; t++) {
        w[t] = rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    u32 a = ihv[0], b = ihv[1], c = ihv[2], d = ihv[3], e = ihv[4];
    for (int t = 0; t < 80; t++) {
        u32 f, k;
        if (t < 20) {
            f = (b & c) | (~b & d), k = 0x5a827999;
        } else if (t < 40) {
            f = b ^ c ^ d, k = 0x6ed9eba1;
        } else if (t < 60) {
            f = (b & c) | (b & d) | (c & d), k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d, k = 0xca62c1d6;
        }
        u32 temp = rol(a, 5) + f + e + k + w[t];
        e = d, d = c, c = rol(b, 30), b = a, a = temp;
    }
    ihv[0] += a, ihv[1] += b, ihv[2] += c, ihv[3] += d, ihv[4] += e;
}

static u64 next = 0x9e3779b97f4a7c15ul;

static u32 random32(void) {
    next ^= next << 13;
    next ^= next >> 7;
    next ^= next << 17;
    return (u32)next;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("usage: jitsha1 GIT OFFSET LENGTH\n");
        return 2;
    }
    long off = (long)strtoul(argv[2], 0, 0);
    u64 len = strtoul(argv[3], 0, 0);
    int fd = open(argv[1], 0);
    char *code = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fd < 0 || pread(fd, code, len, off) != (long)len) {
        printf("could not read the function\n");
        return 2;
    }
    /* paciasp; stp x29, x30, [sp, #-0x60]!; mov w5, #0x7999; movk w5, #0x5a82, lsl #16 */
    const u32 *words = (const u32 *)code;
    if (words[0] != 0xd503233f || words[1] != 0xa9ba7bfd || words[2] != 0x528f3325 ||
        words[3] != 0x72ab5045) {
        printf("no sha1_compression_states at %#lx\n", (u64)off);
        return 2;
    }
    for (char *p = code; p < code + len; p += 4) {
        __asm__ volatile("dc cvau, %0" ::"r"(p) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (char *p = code; p < code + len; p += 4) {
        __asm__ volatile("ic ivau, %0" ::"r"(p) : "memory");
    }
    __asm__ volatile("dsb ish\n isb" ::: "memory");
    mprotect(code, len, PROT_READ | PROT_EXEC);
    compress_fn compress = (compress_fn)(void *)code;

    int blocks = 2000, alike = 0;
    for (int i = 0; i < blocks; i++) {
        u32 block[16], ihv[5], want[5], w[80], states[80][5];
        for (int j = 0; j < 16; j++) {
            block[j] = random32();
        }
        for (int j = 0; j < 5; j++) {
            ihv[j] = want[j] = random32();
        }
        reference(want, (const unsigned char *)block);
        compress(ihv, block, w, states);
        int same = 1;
        for (int j = 0; j < 5; j++) {
            same &= ihv[j] == want[j];
        }
        if (!same && blocks - alike - (blocks - i) < 5) {
            printf("block %d: %08x %08x %08x %08x %08x, not %08x %08x %08x %08x %08x\n", i, ihv[0],
                   ihv[1], ihv[2], ihv[3], ihv[4], want[0], want[1], want[2], want[3], want[4]);
        }
        alike += same;
    }
    printf("sha1 blocks compressed by translation: %d of %d alike\n", alike, blocks);
    return 0;
}
