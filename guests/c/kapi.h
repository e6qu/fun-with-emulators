/* What the kernel-interface guests (sysctls.c, cgroups.c, nsprocs.c,
 * procfiles.c, newcalls.c, memlimits.c, restore.c) declare of the C library
 * and Linux's ABI: they
 * are built freestanding with no system headers, as the other dynamic
 * guests, and linked against glibc's shared library. */

typedef unsigned long size_t;
typedef long ssize_t;
typedef int pid_t;
typedef unsigned long pthread_t;

long syscall(long number, ...);
int *__errno_location(void);
#define errno (*__errno_location())

int open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
ssize_t pread(int fd, void *buf, size_t n, long off);
int close(int fd);
int mkdir(const char *path, unsigned mode);
int rmdir(const char *path);
int unlink(const char *path);
int chdir(const char *path);
int pipe(int fds[2]);
pid_t fork(void);
pid_t getpid(void);
pid_t getppid(void);
pid_t gettid(void);
pid_t waitpid(pid_t pid, int *status, int options);
int kill(pid_t pid, int sig);
int usleep(unsigned us);
void _exit(int status);
int unshare(int flags);
int setns(int fd, int nstype);
int prctl(int option, ...);
int ioctl(int fd, unsigned long request, ...);
int listen(int fd, int backlog);
int socket(int domain, int type, int protocol);
int bind(int fd, const void *addr, unsigned len);
int connect(int fd, const void *addr, unsigned len);
int setuid(unsigned uid);
int setgid(unsigned gid);
int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);
int pthread_join(pthread_t thread, void **ret);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int munmap(void *addr, size_t len);
int printf(const char *format, ...);
int snprintf(char *s, size_t n, const char *format, ...);
int fflush(void *stream);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
size_t strlen(const char *s);
char *strstr(const char *h, const char *n);
char *strchr(const char *s, int c);
void *memset(void *s, int c, size_t n);
void *memcpy(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
long strtol(const char *s, char **end, int base);

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 040000
#define O_CLOEXEC 02000000
#define WNOHANG 1

#define CLONE_NEWNS 0x00020000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWPID 0x20000000
#define CLONE_NEWNET 0x40000000
#define CLONE_VM 0x00000100
#define CLONE_SIGHAND 0x00000800
#define CLONE_THREAD 0x00010000

#define SIGKILL 9
#define SIGCONT 18
#define SIGSTOP 19

/* The whole of a small file at `path` into `buf` (NUL-terminated), its
 * length, or -errno. */
static long slurp(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }
    long total = 0;
    for (;;) {
        ssize_t n = read(fd, buf + total, size - 1 - total);
        if (n < 0) {
            total = -errno;
            break;
        }
        if (n == 0) {
            break;
        }
        total += n;
    }
    close(fd);
    buf[total < 0 ? 0 : total] = 0;
    return total;
}

/* Write `text` to the file at `path`: 0, or -errno. */
static int put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -errno;
    }
    int r = write(fd, text, strlen(text)) < 0 ? -errno : 0;
    close(fd);
    return r;
}

/* The status a child ended with, waited for. */
static int reap(pid_t pid) {
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}
