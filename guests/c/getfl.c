/* F_GETFL of each kind of descriptor, as Linux reports it: O_LARGEFILE
 * (0x20000 on arm64) only on what open (or memfd_create) made, not on
 * pipes, sockets or the descriptors of epoll, eventfd, signalfd, timerfd,
 * inotify and pidfd. Chromium's GPU sandbox lets F_SETFL take back only
 * the flags it knows, which on arm64 leave O_LARGEFILE out, so a socket's
 * flags set back with that bit kill the process.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

int printf(const char *fmt, ...);
int open(const char *path, int flags, ...);
int fcntl(int fd, int cmd, ...);
int pipe(int fds[2]);
int socket(int domain, int type, int protocol);
int socketpair(int domain, int type, int protocol, int sv[2]);
int mkfifo(const char *path, unsigned mode);
int unlink(const char *path);
int epoll_create1(int flags);
int eventfd(unsigned initval, int flags);
int signalfd(int fd, const void *mask, int flags);
int timerfd_create(int clock, int flags);
int inotify_init1(int flags);
int memfd_create(const char *name, unsigned flags);
int sigemptyset(void *set);
int getpid(void);
long syscall(long nr, ...);

#define F_GETFL 3
#define O_RDONLY 0
#define O_RDWR 2
#define O_NONBLOCK 0x800
#define O_DIRECTORY 0x4000
#define O_CREAT 0x40
#define O_WRONLY 1
#define O_APPEND 0x400
#define O_SYNC 0x101000
#define O_NOFOLLOW 0x8000
#define O_CLOEXEC 0x80000
#define O_PATH 0x200000
#define O_NOATIME 0x40000
#define O_TMPFILE 0x404000
#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SYS_pidfd_open 434

static void show(const char *what, int fd) {
    printf("%s: %#x\n", what, fd < 0 ? -1 : fcntl(fd, F_GETFL));
}

int main(void) {
    show("file", open("/getfl-file", O_RDWR | O_CREAT, 0600));
    unlink("/getfl-file");
    show("directory", open("/", O_RDONLY | O_DIRECTORY));
    show("directory, plain open", open("/", O_RDONLY));
    show("file, O_CLOEXEC | O_NOFOLLOW", open("/getfl-file2", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
    show("file, O_WRONLY | O_APPEND | O_SYNC", open("/getfl-file2", O_WRONLY | O_APPEND | O_SYNC));
    show("file, O_NOATIME", open("/getfl-file2", O_RDONLY | O_NOATIME));
    unlink("/getfl-file2");
    show("O_PATH | O_DIRECTORY", open("/", O_PATH | O_DIRECTORY));
    show("O_TMPFILE", open("/", O_TMPFILE | O_RDWR, 0600));
    show("/dev/null", open("/dev/null", O_RDWR));
    int p[2];
    pipe(p);
    show("pipe read end", p[0]);
    show("pipe write end", p[1]);
    unlink("/getfl-fifo");
    mkfifo("/getfl-fifo", 0600);
    show("named FIFO", open("/getfl-fifo", O_RDWR | O_NONBLOCK));
    unlink("/getfl-fifo");
    show("TCP socket", socket(AF_INET, SOCK_STREAM, 0));
    show("UDP socket", socket(AF_INET, SOCK_DGRAM, 0));
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    show("socketpair", sv[0]);
    show("epoll", epoll_create1(0));
    show("eventfd", eventfd(0, 0));
    unsigned long mask[16];
    sigemptyset(mask);
    show("signalfd", signalfd(-1, mask, 0));
    show("timerfd", timerfd_create(1, 0));
    show("inotify", inotify_init1(0));
    show("memfd", memfd_create("getfl", 0));
    show("pidfd", (int)syscall(SYS_pidfd_open, getpid(), 0));
    return 0;
}
