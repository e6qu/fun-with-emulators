/* Processes made with CLONE_FS share their root, working directory and
 * umask, as threads do: a change either makes is the other's too. One
 * made without it has a copy of its own. They stay shared across the
 * child's execve.
 *
 * Then Chromium's sandbox (sandbox/linux/services/credentials.cc,
 * ChrootToSafeEmptyDir): a child made with CLONE_FS, CLONE_VM, CLONE_VFORK
 * and a TLS of its own changes the root to its own /proc/self/fdinfo and
 * its working directory to that root, and exits; its parent's root is then
 * that directory of a process that has ended. The child makes system calls
 * only through `svc`, as Chromium's does: its thread pointer is a zeroed
 * buffer. A descriptor of /proc opened before still reaches it, its own
 * directories too, as Chromium's sandbox then checks (proc_util.cc). */
int printf(const char *fmt, ...);
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...);
int waitpid(int pid, int *status, int options);
unsigned umask(unsigned mask);
char *getcwd(char *buf, unsigned long size);
int chdir(const char *path);
int mkdir(const char *path, unsigned mode);
int stat(const char *path, void *st);
void *opendir(const char *path);
void *readdir(void *dir);
char *strerror(int e);
int strcmp(const char *a, const char *b);
int open(const char *path, int flags, ...);
int openat(int dirfd, const char *path, int flags, ...);
int fchdir(int fd);
int close(int fd);
long read(int fd, void *buf, unsigned long n);
void *fdopendir(int fd);
int closedir(void *dir);
int *__errno_location(void);
#define errno (*__errno_location())

#define O_DIRECTORY 0x4000
#define O_CLOEXEC 0x80000
#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_VFORK 0x4000
#define CLONE_SETTLS 0x80000
#define SIGCHLD 17
#define SYS_chdir 49
#define SYS_chroot 51
#define SYS_execve 221
#define SYS_exit 93
#define SYS_umask 166
/* struct dirent's d_name, after d_ino, d_off, d_reclen and d_type. */
#define D_NAME 19

static long raw3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static long raw(long n, long a) { return raw3(n, a, 0, 0); }

static int moves(void *arg) {
    (void)arg;
    if (raw(SYS_chdir, (long)"/moved") != 0) raw(SYS_exit, 2);
    raw(SYS_umask, 027);
    raw(SYS_exit, 0);
    return 0;
}

static char *again[] = {"clonefs", "moves", 0};

static int runs_again(void *arg) {
    (void)arg;
    raw3(SYS_execve, (long)"/proc/self/exe", (long)again, 0);
    raw(SYS_exit, 4);
    return 0;
}

static int empty_root(void *arg) {
    (void)arg;
    if (raw(SYS_chroot, (long)"/proc/self/fdinfo/") != 0) raw(SYS_exit, 2);
    if (raw(SYS_chdir, (long)"/") != 0) raw(SYS_exit, 3);
    raw(SYS_exit, 0);
    return 0;
}

static char stack[65536] __attribute__((aligned(16)));
static char tls[16384] __attribute__((aligned(64)));

static int run(int (*fn)(void *), int flags) {
    int pid = clone(fn, stack + sizeof stack, flags | SIGCHLD, 0, 0, tls, 0);
    if (pid < 0) return -errno;
    int status;
    if (waitpid(pid, &status, 0) != pid) return -errno;
    return (status & 0x7f) == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f);
}

/* The entries of directory `fd` but . and .., or -errno. */
static int entries(int fd) {
    void *d = fdopendir(fd);
    if (!d) return -errno;
    int n = 0;
    errno = 0;
    char *e;
    while ((e = readdir(d)) != 0)
        if (strcmp(e + D_NAME, ".") && strcmp(e + D_NAME, "..")) n++;
    int bad = errno;
    closedir(d);
    return bad ? -bad : n;
}

static void where(const char *what) {
    char cwd[256];
    unsigned m = umask(022);
    printf("%s: cwd %s, umask %03o\n", what, getcwd(cwd, sizeof cwd) ? cwd : strerror(errno), m);
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        /* Run again by a child made with CLONE_FS: its parent's too. */
        if (chdir("/moved") != 0) return 5;
        umask(0);
        return 0;
    }
    char st[256];
    umask(022);
    if (chdir("/") != 0 || mkdir("/moved", 0755) != 0) return 1;
    printf("without CLONE_FS: child %d\n", run(moves, 0));
    where("its parent");
    printf("with CLONE_FS: child %d\n", run(moves, CLONE_FS));
    where("its parent");
    if (chdir("/") != 0) return 1;
    printf("with CLONE_FS, across execve: child %d\n", run(runs_again, CLONE_FS));
    where("its parent");
    if (chdir("/") != 0) return 1;
    int proc = open("/proc/", O_DIRECTORY | O_CLOEXEC);
    if (proc < 0) return 1;
    printf("Chromium's empty root: child %d\n",
           run(empty_root, CLONE_FS | CLONE_VM | CLONE_VFORK | CLONE_SETTLS));
    printf("/proc: %s\n", stat("/proc", st) == 0 ? "found" : strerror(errno));
    printf("/: %s\n", stat("/", st) == 0 ? "found" : strerror(errno));
    char cwd[256];
    printf("cwd: %s\n", getcwd(cwd, sizeof cwd) ? cwd : strerror(errno));
    int root = open("/", O_DIRECTORY | O_CLOEXEC);
    int n = root < 0 ? -errno : entries(root);
    printf("listing /: %s\n", n < 0 ? strerror(-n) : "listed");
    /* Through the descriptor of /proc. */
    int fds = openat(proc, "self/fd/", O_DIRECTORY | O_CLOEXEC);
    n = fds < 0 ? -errno : entries(fds);
    printf("/proc's self/fd: %s\n", n < 0 ? strerror(-n) : n > 2 ? "listed" : "too few");
    int status = openat(proc, "self/status", O_CLOEXEC);
    char buf[5] = {0};
    printf("/proc's self/status: %s\n",
           status < 0 ? strerror(errno) : read(status, buf, 4) == 4 ? buf : "unread");
    if (fchdir(proc) != 0) return 1;
    printf("in /proc: cwd %s\n", getcwd(cwd, sizeof cwd) ? cwd : strerror(errno));
    printf("in /proc: self %s\n", stat("self", st) == 0 ? "found" : strerror(errno));
    return 0;
}
