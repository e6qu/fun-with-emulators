/* FIONBIO and FIOCLEX/FIONCLEX on descriptors of every kind: each sets
 * what fcntl reads back (O_NONBLOCK, FD_CLOEXEC), as Linux's generic
 * ioctls do whatever the file. */
int printf(const char *fmt, ...);
int ioctl(int fd, unsigned long req, ...);
int fcntl(int fd, int cmd, ...);
int pipe(int fds[2]);
int socketpair(int domain, int type, int proto, int sv[2]);
int eventfd(unsigned initval, int flags);
int memfd_create(const char *name, unsigned flags);
int timerfd_create(int clock, int flags);
int epoll_create1(int flags);
int open(const char *path, int flags, ...);

#define FIONBIO 0x5421
#define FIOCLEX 0x5451
#define FIONCLEX 0x5450
#define F_GETFD 1
#define F_GETFL 3
#define O_NONBLOCK 04000

static void check(const char *what, int fd) {
    int on = 1, off = 0;
    int a = ioctl(fd, FIONBIO, &on);
    int set = (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0;
    int b = ioctl(fd, FIONBIO, &off);
    int cleared = (fcntl(fd, F_GETFL) & O_NONBLOCK) == 0;
    int c = ioctl(fd, FIOCLEX);
    int cloexec = fcntl(fd, F_GETFD) & 1;
    int d = ioctl(fd, FIONCLEX);
    int kept = !(fcntl(fd, F_GETFD) & 1);
    printf("%s: FIONBIO %d %d, nonblocking %s; FIOCLEX %d %d, close-on-exec %s\n", what, a, b,
           set && cleared ? "set and cleared" : "WRONG", c, d,
           cloexec && kept ? "set and cleared" : "WRONG");
}

int main(void) {
    int p[2], s[2];
    pipe(p);
    socketpair(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0, s);
    check("pipe", p[0]);
    check("unix socket", s[0]);
    check("eventfd", eventfd(0, 0));
    check("memfd", memfd_create("m", 0));
    check("timerfd", timerfd_create(1 /* CLOCK_MONOTONIC */, 0));
    check("epoll", epoll_create1(0));
    check("/dev/null", open("/dev/null", 2));
    return 0;
}
