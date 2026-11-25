/* RLIMIT_DATA and RLIMIT_AS as Linux enforces them (Chromium's sandbox
 * lowers RLIMIT_DATA before it starts): data (writable private memory) at
 * mmap, mprotect and brk; the whole size at mmap and mremap; a soft data
 * limit of 0 lets data up to the hard one through. */
int printf(const char *fmt, ...);
long syscall(long n, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int munmap(void *addr, unsigned long len);
int mprotect(void *addr, unsigned long len, int prot);
void *mremap(void *old, unsigned long old_len, unsigned long new_len, int flags, ...);
int open(const char *path, int flags, ...);
long read(int fd, void *buf, unsigned long n);
int close(int fd);
char *strstr(const char *s, const char *t);
long strtol(const char *s, char **end, int base);
int fork(void);
int waitpid(int pid, int *status, int options);
int fflush(void *f);
void _exit(int status);
int *__errno_location(void);
#define errno (*__errno_location())

struct rlimit { unsigned long cur, max; };
#define SYS_brk 214
#define SYS_prlimit64 261
#define RLIMIT_DATA 2
#define RLIMIT_AS 9
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MREMAP_MAYMOVE 1
#define MAP_FAILED ((void *)-1)
#define MiB (1ul << 20)

static int set(int res, unsigned long cur, unsigned long max) {
    struct rlimit r = {cur, max};
    return syscall(SYS_prlimit64, 0, res, &r, 0) ? errno : 0;
}

/* A mapping of `len` with `prot`, `flags`: "ok" (unmapped again), or its
 * error. */
static const char *map(unsigned long len, int prot, int flags) {
    void *p = mmap(0, len, prot, flags | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return errno == 12 ? "ENOMEM" : "other error";
    munmap(p, len);
    return "ok";
}

static unsigned long vm_size(void) {
    static char buf[4096];
    int fd = open("/proc/self/status", 0);
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    char *s = strstr(buf, "VmSize:");
    return s ? strtol(s + 7, 0, 10) * 1024 : 0;
}

int main(void) {
    struct rlimit r;
    syscall(SYS_prlimit64, 0, RLIMIT_DATA, 0, &r);
    printf("data: %s\n", r.cur == ~0ul && r.max == ~0ul ? "unlimited" : "limited");
    syscall(SYS_prlimit64, 0, RLIMIT_AS, 0, &r);
    printf("as: %s\n", r.cur == ~0ul && r.max == ~0ul ? "unlimited" : "limited");
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        printf("set data 64 MiB: %d\n", set(RLIMIT_DATA, 64 * MiB, 64 * MiB));
        printf("128 MiB private writable: %s\n", map(128 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE));
        printf("16 MiB private writable: %s\n", map(16 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE));
        printf("128 MiB shared writable: %s\n", map(128 * MiB, PROT_READ | PROT_WRITE, MAP_SHARED));
        void *ro = mmap(0, 128 * MiB, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("128 MiB private read-only: %s\n", ro == MAP_FAILED ? "failed" : "ok");
        printf("made writable: %s\n", mprotect(ro, 128 * MiB, PROT_READ | PROT_WRITE) ? (errno == 12 ? "ENOMEM" : "other error") : "ok");
        printf("16 MiB of it made writable: %s\n", mprotect(ro, 16 * MiB, PROT_READ | PROT_WRITE) ? "failed" : "ok");
        unsigned long b = syscall(SYS_brk, 0);
        printf("brk by 128 MiB: %s\n", (unsigned long)syscall(SYS_brk, b + 128 * MiB) == b ? "refused" : "grown");
        printf("brk by 1 MiB: %s\n", (unsigned long)syscall(SYS_brk, b + MiB) == b + MiB ? "grown" : "refused");
        fflush(0);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    pid = fork();
    if (pid == 0) {
        unsigned long size = vm_size();
        printf("VmSize below 1 GiB: %s\n", size > 0 && size < 1024 * MiB ? "yes" : "no");
        printf("set as: %d\n", set(RLIMIT_AS, size + 256 * MiB, size + 256 * MiB));
        printf("128 MiB inaccessible: %s\n", map(128 * MiB, PROT_NONE, MAP_PRIVATE));
        printf("512 MiB inaccessible: %s\n", map(512 * MiB, PROT_NONE, MAP_PRIVATE));
        void *p = mmap(0, 64 * MiB, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void *q = mremap(p, 64 * MiB, 512 * MiB, MREMAP_MAYMOVE);
        printf("grown to 512 MiB: %s\n", q == MAP_FAILED ? (errno == 12 ? "ENOMEM" : "other error") : "ok");
        q = mremap(p, 64 * MiB, 128 * MiB, MREMAP_MAYMOVE);
        printf("grown to 128 MiB: %s\n", q == MAP_FAILED ? "failed" : "ok");
        fflush(0);
        _exit(0);
    }
    waitpid(pid, &status, 0);
    pid = fork();
    if (pid == 0) {
        printf("set data 0, hard 64 MiB: %d\n", set(RLIMIT_DATA, 0, 64 * MiB));
        printf("32 MiB private writable: %s\n", map(32 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE));
        printf("128 MiB private writable: %s\n", map(128 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE));
        fflush(0);
        _exit(0);
    }
    waitpid(pid, &status, 0);
    return 0;
}
