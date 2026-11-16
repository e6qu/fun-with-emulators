/* Programs that treat themselves as data:
 *
 * - it runs itself again, fifty deep, through /proc/self/exe;
 * - it copies its own executable, changes a string in the copy, and runs
 *   the copy, which prints the changed string;
 * - it writes instructions into a buffer on its stack, makes the stack's
 *   page executable, and calls them.
 *
 * Every line printed is what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
int sprintf(char *s, const char *fmt, ...);
int execv(const char *path, char *const argv[]);
long strtol(const char *s, char **end, int base);
int strcmp(const char *a, const char *b);
void *memcpy(void *d, const void *s, size_t n);
void *memmem(const void *h, size_t hl, const void *n, size_t nl);
int open(const char *path, int flags, ...);
long read(int fd, void *buf, size_t n);
long write(int fd, const void *buf, size_t n);
int close(int fd);
int mprotect(void *addr, size_t len, int prot);
long sysconf(int name);
void *malloc(size_t n);
int fork(void);
int waitpid(int pid, int *status, int options);
int fflush(void *f);

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x40
#define O_TRUNC 0x200
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define _SC_PAGESIZE 30

/* The string the copy of the executable has changed. */
static const char marker[] = "as built: lowercase";

/* The program's own file, read whole: its bytes and their count. */
static char *own_file(long *len) {
    int fd = open("/proc/self/exe", O_RDONLY);
    char *buf = malloc(1 << 24);
    long n = 0, r;
    while ((r = read(fd, buf + n, (1 << 24) - n)) > 0) {
        n += r;
    }
    close(fd);
    *len = n;
    return buf;
}

/* Flush code just written to `p` for instruction fetch. */
static void flush(void *p, size_t n) {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t dline = 4ull << ((ctr >> 16) & 15), iline = 4ull << (ctr & 15);
    uint64_t start = (uint64_t)p, end = start + n;
    for (uint64_t a = start & ~(dline - 1); a < end; a += dline) {
        __asm__ volatile("dc cvau, %0" ::"r"(a) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (uint64_t a = start & ~(iline - 1); a < end; a += iline) {
        __asm__ volatile("ic ivau, %0" ::"r"(a) : "memory");
    }
    __asm__ volatile("dsb ish\n isb" ::: "memory");
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "deeper") == 0) {
        long depth = strtol(argv[2], 0, 10);
        if (depth < 50) {
            char next[16];
            sprintf(next, "%ld", depth + 1);
            char *args[] = {argv[0], "deeper", next, 0};
            execv("/proc/self/exe", args);
            return 1;
        }
        printf("ran itself again: %ld deep\n", depth);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "copy") == 0) {
        printf("the copy says: %s\n", marker);
        return 0;
    }

    /* Code on the stack. */
    uint32_t code[16] __attribute__((aligned(64)));
    code[0] = 0xd28009a0; /* mov x0, #77 */
    code[1] = 0xd65f03c0; /* ret */
    long page = sysconf(_SC_PAGESIZE);
    void *stack_page = (void *)((uintptr_t)code & ~(uintptr_t)(page - 1));
    int r = mprotect(stack_page, (size_t)page, PROT_READ | PROT_WRITE | PROT_EXEC);
    flush(code, sizeof code);
    long got = ((long (*)(void))code)();
    mprotect(stack_page, (size_t)page, PROT_READ | PROT_WRITE);
    printf("code on the stack: %ld (mprotect %d)\n", got, r);

    /* A changed copy of itself. */
    long len;
    char *self = own_file(&len);
    char *at = memmem(self, (size_t)len, marker, sizeof marker - 1);
    if (at) {
        memcpy(at + 10, "UPPERCASE", 9);
    }
    int fd = open("/tmp/perverse-copy", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(fd, self, (size_t)len);
    close(fd);
    printf("changed its copy: %s\n", at ? "yes" : "no");
    char *copy[] = {"/tmp/perverse-copy", "copy", 0};
    /* Run the copy, then itself again, each in a child. */
    fflush(0);
    if (fork() == 0) {
        execv(copy[0], copy);
        return 1;
    }
    int st;
    waitpid(-1, &st, 0);
    if (fork() == 0) {
        char *deep[] = {argv[0], "deeper", "1", 0};
        execv("/proc/self/exe", deep);
        return 1;
    }
    waitpid(-1, &st, 0);
    return 0;
}
