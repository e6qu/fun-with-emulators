/* Writes to a file opened to append, as Linux places them: pwrite and an
 * AIO write at an offset append; pwritev2 with RWF_NOAPPEND (Linux 6.9,
 * musl's pwrite) writes at the offset, or at the file's position with
 * offset -1 and moves it; so does an AIO write that says RWF_NOAPPEND. */
int printf(const char *fmt, ...);
int open(const char *path, int flags, ...);
int close(int fd);
long pread(int fd, void *buf, unsigned long n, long off);
long pwrite(int fd, const void *buf, unsigned long n, long off);
long lseek(int fd, long off, int whence);
long syscall(long n, ...);
int unlink(const char *path);
void *memset(void *p, int c, unsigned long n);

struct iovec { const void *base; unsigned long len; };
struct iocb {
    unsigned long data;
    unsigned key, rw_flags;
    unsigned short opcode;
    short prio;
    unsigned fd;
    unsigned long buf, nbytes;
    long offset;
    unsigned long reserved2;
    unsigned flags, resfd;
};
struct io_event { unsigned long data, obj; long res, res2; };

#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define SYS_io_setup 0
#define SYS_io_submit 2
#define SYS_io_getevents 4
#define SYS_pwritev2 287
#define RWF_NOAPPEND 0x20

static const char *path = "fwe-noappend";

static void show(int fd, const char *what) {
    char buf[32] = {0};
    long n = pread(fd, buf, sizeof buf - 1, 0);
    printf("%s: %.*s (position %ld)\n", what, (int)(n > 0 ? n : 0), buf, lseek(fd, 0, 1));
}

static long pwritev2(int fd, const char *s, unsigned long n, long off, int flags) {
    struct iovec v = {s, n};
    return syscall(SYS_pwritev2, fd, &v, 1, off, 0, flags);
}

static long aio_write(int fd, const char *s, unsigned long n, long off, unsigned flags) {
    unsigned long ctx = 0;
    if (syscall(SYS_io_setup, 1, &ctx)) return -1;
    struct iocb cb;
    memset(&cb, 0, sizeof cb);
    cb.opcode = 1; /* IOCB_CMD_PWRITE */
    cb.fd = fd;
    cb.buf = (unsigned long)s;
    cb.nbytes = n;
    cb.offset = off;
    cb.rw_flags = flags;
    struct iocb *list[1] = {&cb};
    if (syscall(SYS_io_submit, ctx, 1, list) != 1) return -1;
    struct io_event ev;
    if (syscall(SYS_io_getevents, ctx, 1, 1, &ev, 0) != 1) return -1;
    return ev.res;
}

int main(void) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0600);
    pwrite(fd, "aaaa", 4, 0);
    show(fd, "pwrite at 0");
    printf("pwritev2 at 1, RWF_NOAPPEND: %ld\n", pwritev2(fd, "XY", 2, 1, RWF_NOAPPEND));
    show(fd, "then");
    lseek(fd, 0, 0);
    printf("pwritev2 at the position, RWF_NOAPPEND: %ld\n", pwritev2(fd, "Z", 1, -1, RWF_NOAPPEND));
    show(fd, "then");
    printf("pwritev2 at 0: %ld\n", pwritev2(fd, "b", 1, 0, 0));
    show(fd, "then");
    printf("AIO at 0: %ld\n", aio_write(fd, "c", 1, 0, 0));
    show(fd, "then");
    printf("AIO at 2, RWF_NOAPPEND: %ld\n", aio_write(fd, "D", 1, 2, RWF_NOAPPEND));
    show(fd, "then");
    close(fd);
    unlink(path);
    return 0;
}
