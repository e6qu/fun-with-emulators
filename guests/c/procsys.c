/* Lookups in /proc/sys: /proc/sys/crypto/fips_enabled, which libgcrypt
 * reads as it starts (any error but ENOENT is fatal to it), names /proc/sys
 * does not have, and one it has; then the same once /proc/sys is bound onto
 * itself read-only in a mount namespace of the program's own, and once a
 * fresh proc's is bound so through a descriptor, as bubblewrap covers it;
 * then a file masked with /dev/null bound through its descriptor. */
int open(const char *path, int flags, ...);
long read(int fd, void *buf, unsigned long n);
int close(int fd);
int printf(const char *fmt, ...);
int snprintf(char *s, unsigned long n, const char *fmt, ...);
int *__errno_location(void);
int unshare(int flags);
int mount(const char *src, const char *dst, const char *type, unsigned long flags, const void *data);
unsigned getuid(void);

static void look(const char *path) {
    int fd = open(path, 0);
    if (fd < 0) {
        int e = *__errno_location();
        printf("%s: %s\n", path, e == 2 ? "ENOENT" : e == 20 ? "ENOTDIR" : "other");
        return;
    }
    char b[16] = {0};
    long n = read(fd, b, sizeof b - 1);
    printf("%s: %ld bytes: %s", path, n, n > 0 ? b : "\n");
    close(fd);
}

static void all(void) {
    look("/proc/sys/crypto/fips_enabled");
    look("/proc/sys/nope");
    look("/proc/sys/nope/deeper");
    look("/proc/sys/kernel/nope");
    look("/proc/sys/kernel/ostype");
}

int main(void) {
    all();
    /* CLONE_NEWNS, with CLONE_NEWUSER where it is not root. */
    int flags = 0x20000 | (getuid() ? 0x10000000 : 0);
    if (unshare(flags) != 0) {
        printf("unshare failed\n");
        return 1;
    }
    /* Private, then bound and made read-only (MS_BIND 0x1000, MS_REC 0x4000,
     * MS_PRIVATE 0x40000, MS_REMOUNT 0x20, MS_RDONLY 0x1, MS_NOSUID 0x2,
     * MS_NODEV 0x4). */
    int r1 = mount("none", "/", 0, 0x40000 | 0x4000, 0);
    int r2 = mount("/proc/sys", "/proc/sys", 0, 0x1000 | 0x4000, 0);
    int r3 = mount("none", "/proc/sys", 0, 0x20 | 0x1000 | 0x1 | 0x2 | 0x4, 0);
    printf("bound: %d %d %d\n", r1, r2, r3);
    all();
    /* A fresh proc mounted (MS_NOSUID|MS_NODEV|MS_NOEXEC), its sys bound
     * onto itself through a descriptor's path, as bubblewrap does. */
    int r4 = mount("proc", "/proc", "proc", 0x2 | 0x4 | 0x8, 0);
    int fd = open("/proc/sys", 0x200000 /* O_PATH */ | 0x4000 /* O_DIRECTORY */);
    char at[32];
    snprintf(at, sizeof at, "/proc/self/fd/%d", fd);
    int r5 = mount(at, at, 0, 0x1000 | 0x4000, 0);
    int r6 = mount("none", "/proc/sys", 0, 0x20 | 0x1000 | 0x1 | 0x2 | 0x4, 0);
    printf("fresh proc, bound through a descriptor: %d %d %d\n", r4, r5, r6);
    close(fd);
    all();
    /* /dev/null bound over a file through its descriptor, as crun masks
     * files: the file reads as empty. */
    int null = open("/dev/null", 0x200000 /* O_PATH */);
    snprintf(at, sizeof at, "/proc/self/fd/%d", null);
    printf("masked: %d\n", mount(at, "/proc/sys/kernel/ostype", 0, 0x1000, 0));
    look("/proc/sys/kernel/ostype");
    return 0;
}
