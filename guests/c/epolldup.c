/* A duplicated epoll descriptor is the same epoll set, as mio's
 * `Registry::try_clone` (Tokio's) duplicates it: a descriptor added
 * through one number is reported through the other, the duplicate made
 * with dup, dup3 and F_DUPFD_CLOEXEC alike; the set outlives the number
 * it was made with; and a fork child's copies are one set too.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef long ssize_t;
typedef unsigned long size_t;

struct epoll_event {
    unsigned events;
    unsigned long data;
};

int printf(const char *fmt, ...);
int fflush(void *f);
int fork(void);
int waitpid(int pid, int *status, int flags);
void _exit(int status);
int pipe(int fds[2]);
ssize_t write(int fd, const void *buf, size_t n);
int close(int fd);
int dup(int fd);
int dup3(int old, int new, int flags);
int fcntl(int fd, int cmd, ...);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, struct epoll_event *ev);
int epoll_wait(int ep, struct epoll_event *events, int max, int timeout);
int *__errno_location(void);

#define EPOLL_CLOEXEC 0x80000
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLLIN 1
#define F_DUPFD_CLOEXEC 1030

/* What the set `ep` reports now: the data word of its one ready entry, or
 * -1 for none (or more than one). */
static long ready(int ep) {
    struct epoll_event ev[2];
    int n = epoll_wait(ep, ev, 2, 0);
    return n == 1 ? (long)ev[0].data : -n - 1;
}

/* Add `fd` to `ep` with data word `data`. */
static int add(int ep, int fd, unsigned long data) {
    struct epoll_event ev = {EPOLLIN, data};
    return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
}

/* One duplicate, made by `how`: a pipe added through the duplicate is
 * reported through the original and the other way round, then the
 * original closed and the set still used through the duplicate. */
static void one(const char *how) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int copy = how[0] == 'd' && how[3] == 0  ? dup(ep)
               : how[0] == 'd'               ? dup3(ep, 40, EPOLL_CLOEXEC)
                                             : fcntl(ep, F_DUPFD_CLOEXEC, 0);
    int a[2], b[2];
    pipe(a);
    pipe(b);
    write(a[1], "x", 1);
    write(b[1], "x", 1);
    int r1 = add(copy, a[0], 7);
    long seen1 = ready(ep);
    int r2 = add(ep, b[0], 8);
    int again = add(copy, b[0], 8) == 0 ? 0 : *__errno_location();
    epoll_ctl(copy, EPOLL_CTL_DEL, a[0], 0);
    long seen2 = ready(copy);
    close(ep);
    epoll_ctl(copy, EPOLL_CTL_DEL, b[0], 0);
    int r3 = add(copy, a[0], 9);
    long seen3 = ready(copy);
    printf("%s: add through it %d, seen through the original %ld; "
           "add through the original %d, again through it errno %d, seen through it %ld; "
           "original closed, add %d, seen %ld\n",
           how, r1, seen1, r2, again, seen2, r3, seen3);
    close(copy);
    close(a[0]), close(a[1]), close(b[0]), close(b[1]);
}

int main(void) {
    one("dup");
    one("dup3");
    one("F_DUPFD_CLOEXEC");

    /* A fork child: its two numbers are one set, holding what the
     * parent's held. */
    int ep = epoll_create1(0);
    int copy = dup(ep);
    int a[2], b[2];
    pipe(a);
    pipe(b);
    write(a[1], "x", 1);
    write(b[1], "x", 1);
    add(ep, a[0], 5);
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        long inherited = ready(copy);
        epoll_ctl(copy, EPOLL_CTL_DEL, a[0], 0);
        add(ep, b[0], 6);
        long seen = ready(copy);
        printf("fork child: inherited %ld through the copy, added through the original, seen %ld\n",
               inherited, seen);
        fflush(0);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    return 0;
}
