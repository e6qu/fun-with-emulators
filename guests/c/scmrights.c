/* Descriptors and credentials passed over Unix sockets, as Linux passes
 * them. The first argument names the case.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;

struct iovec {
    void *iov_base;
    size_t iov_len;
};
struct msghdr {
    void *msg_name;
    unsigned msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

int socketpair(int domain, int type, int protocol, int sv[2]);
int socket(int domain, int type, int protocol);
int pipe(int fds[2]);
int fork(void);
int waitpid(int pid, int *status, int options);
void _exit(int status);
long read(int fd, void *buf, size_t n);
long write(int fd, const void *buf, size_t n);
long send(int fd, const void *buf, size_t n, int flags);
long recv(int fd, void *buf, size_t n, int flags);
int eventfd(unsigned initval, int flags);
int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags, const void *new_value, void *old_value);
int signalfd(int fd, const void *mask, int flags);
int sigprocmask(int how, const void *set, void *old);
int getpid(void);
int kill(int pid, int sig);
long syscall(long nr, ...);
int poll(void *fds, unsigned long n, int timeout);
int fflush(void *stream);
int bind(int fd, const void *addr, unsigned len);
int listen(int fd, int backlog);
int accept(int fd, void *addr, unsigned *len);
int connect(int fd, const void *addr, unsigned len);
int getsockopt(int fd, int level, int name, void *val, unsigned *len);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
int setgid(unsigned gid);
int setuid(unsigned uid);
int *__errno_location(void);
long sendmsg(int fd, const struct msghdr *msg, int flags);
long recvmsg(int fd, struct msghdr *msg, int flags);
int fcntl(int fd, int cmd, ...);
int close(int fd);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);
void *memset(void *s, int c, size_t n);
void *memcpy(void *d, const void *s, size_t n);

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define MSG_CTRUNC 8
#define MSG_CMSG_CLOEXEC 0x40000000
#define F_GETFD 1
#define FD_CLOEXEC 1

#define CMSG_LEN(n) (sizeof(struct cmsghdr) + (n))
#define CMSG_SPACE(n) (sizeof(struct cmsghdr) + (((n) + 7) & ~7UL))
#define CMSG_DATA(c) ((unsigned char *)((struct cmsghdr *)(c) + 1))

static char control[8192] __attribute__((aligned(8)));

/* Send `n` descriptors on `s` in one SCM_RIGHTS message, with a byte. */
static long send_fds(int s, const int *fds, int n) {
    char byte = 'x';
    struct iovec iov = {&byte, 1};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(control, 0, sizeof control);
    struct cmsghdr *c = (struct cmsghdr *)control;
    c->cmsg_len = CMSG_LEN(n * sizeof(int));
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(c), fds, n * sizeof(int));
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = CMSG_SPACE(n * sizeof(int));
    return sendmsg(s, &m, 0);
}

/* Receive a message on `s` into `room` bytes of control: the descriptors
 * it carried into `fds` (their count), its flags into `*flags`. */
static int recv_fds(int s, size_t room, int flags, int *fds, int *mflags) {
    char byte;
    struct iovec iov = {&byte, 1};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(control, 0, sizeof control);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = room;
    if (recvmsg(s, &m, flags) < 0)
        return -1;
    *mflags = m.msg_flags;
    int n = 0;
    struct cmsghdr *c = (struct cmsghdr *)control;
    if (m.msg_controllen >= sizeof *c && c->cmsg_type == SCM_RIGHTS) {
        n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        memcpy(fds, CMSG_DATA(c), n * sizeof(int));
    }
    return n;
}

/* MSG_CMSG_CLOEXEC: received descriptors are close-on-exec. */
static int cloexec(void) {
    int sv[2], got[2], mflags;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int fds[2] = {0, 1};
    for (int pass = 0; pass < 2; pass++) {
        send_fds(sv[0], fds, 2);
        int n = recv_fds(sv[1], sizeof control, pass ? MSG_CMSG_CLOEXEC : 0, got, &mflags);
        if (n != 2)
            return printf("received %d\n", n), 1;
        for (int i = 0; i < 2; i++) {
            int on = fcntl(got[i], F_GETFD) & FD_CLOEXEC;
            if (on != pass)
                return printf("pass %d: close-on-exec %d\n", pass, on), 1;
            close(got[i]);
        }
    }
    printf("close-on-exec as asked\n");
    return 0;
}

/* All of Linux's 253 descriptors go in one message; one more is EINVAL. */
static int many(void) {
    int sv[2], fds[254], got[254], mflags;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    for (int i = 0; i < 254; i++)
        fds[i] = 0;
    if (send_fds(sv[0], fds, 254) != -1)
        return printf("254 went\n"), 1;
    if (send_fds(sv[0], fds, 253) != 1)
        return printf("253 did not go\n"), 1;
    int n = recv_fds(sv[1], sizeof control, 0, got, &mflags);
    for (int i = 0; i < n; i++)
        close(got[i]);
    printf("received %d\n", n);
    return n != 253;
}

/* Descriptors that do not fit the receiver's buffer are closed: once
 * those that did and the original are closed, the pipe has no writer. */
static int truncated(void) {
    int sv[2], p[2], got[4], mflags;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pipe(p);
    int fds[4] = {p[1], p[1], p[1], p[1]};
    send_fds(sv[0], fds, 4);
    int n = recv_fds(sv[1], CMSG_SPACE(2 * sizeof(int)), 0, got, &mflags);
    for (int i = 0; i < n; i++)
        close(got[i]);
    close(p[1]);
    char b;
    long r = read(p[0], &b, 1);
    printf("kept %d, truncated %d, end of pipe %ld\n", n, !!(mflags & MSG_CTRUNC), r);
    return n != 2 || r != 0;
}

#define EFD_NONBLOCK 04000
#define SIGUSR1 10
#define SIG_BLOCK 0
#define AF_NETLINK 16
#define SOCK_RAW 3

struct pollfd {
    int fd;
    short events, revents;
};

/* Descriptors fwe stands in for, made after a fork and passed to the
 * child, work there as they do in their maker. */
static int emulated(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int child = fork();
    if (child == 0) {
        int got[8], mflags;
        int n = recv_fds(sv[1], sizeof control, 0, got, &mflags);
        if (n != 5) {
            printf("child received %d\n", n);
            fflush(0);
            _exit(1);
        }
        /* The eventfd's count is the maker's. */
        unsigned long long v = 5;
        write(got[0], &v, 8);
        /* The timerfd fires when the maker set it to. */
        v = 0;
        long r = read(got[1], &v, 8);
        printf("timerfd: %ld %llu\n", r, v);
        /* The signalfd reads this process's signals. */
        unsigned long long set = 1ULL << (SIGUSR1 - 1);
        sigprocmask(SIG_BLOCK, &set, 0);
        kill(getpid(), SIGUSR1);
        unsigned char info[128];
        r = read(got[2], info, sizeof info);
        printf("signalfd: %ld signal %d\n", r, *(int *)info);
        /* The netlink socket answers. */
        struct {
            unsigned len;
            unsigned short type, flags;
            unsigned seq, pid;
            unsigned char family, pad[15];
        } req = {32, 18, 0x301, 1, 0, 0, {0}};
        send(got[3], &req, sizeof req, 0);
        unsigned char reply[4096];
        r = recv(got[3], reply, sizeof reply, 0);
        printf("netlink: answered %d\n", r > 16 && *(unsigned short *)(reply + 4) == 16);
        /* The process descriptor is readable once its process ended. */
        struct pollfd pfd = {got[4], 1, 0};
        printf("pidfd: %d\n", poll(&pfd, 1, 5000));
        fflush(0);
        _exit(0);
    }
    int efd = eventfd(0, 0);
    int tfd = timerfd_create(1, 0);
    long spec[4] = {0, 0, 0, 100000000L};
    timerfd_settime(tfd, 0, spec, 0);
    int sfd = signalfd(-1, &(unsigned long long){1ULL << (SIGUSR1 - 1)}, 0);
    int nfd = socket(AF_NETLINK, SOCK_RAW, 0);
    int gone = fork();
    if (gone == 0)
        _exit(0);
    int pfd = syscall(434, gone, 0);
    int fds[5] = {efd, tfd, sfd, nfd, pfd};
    send_fds(sv[0], fds, 5);
    unsigned long long v = 0;
    read(efd, &v, 8);
    int status;
    waitpid(child, &status, 0);
    waitpid(gone, &status, 0);
    printf("eventfd: %llu\n", v);
    return 0;
}

#define SCM_CREDENTIALS 2
#define errno (*__errno_location())
#define SO_PASSCRED 16
#define SO_PEERCRED 17

/* Send a byte on `s` with credentials `creds` (pid, uid, gid). */
static long send_creds(int s, const unsigned *creds) {
    char byte = 'c';
    struct iovec iov = {&byte, 1};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(control, 0, sizeof control);
    struct cmsghdr *c = (struct cmsghdr *)control;
    c->cmsg_len = CMSG_LEN(12);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_CREDENTIALS;
    memcpy(CMSG_DATA(c), creds, 12);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = CMSG_SPACE(12);
    return sendmsg(s, &m, 0);
}

/* The credentials a received message carries: 1 if it had them. */
static int recv_creds(int s, unsigned *creds) {
    char byte;
    struct iovec iov = {&byte, 1};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    memset(control, 0, sizeof control);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = control;
    m.msg_controllen = 64;
    if (recvmsg(s, &m, 0) != 1)
        return 0;
    struct cmsghdr *c = (struct cmsghdr *)control;
    if (m.msg_controllen < CMSG_LEN(12) || c->cmsg_type != SCM_CREDENTIALS)
        return 0;
    memcpy(creds, CMSG_DATA(c), 12);
    return 1;
}

/* SO_PEERCRED names the peer as the guest knows it (its ids after it
 * changed them), SO_PASSCRED brings the sender's credentials, and a
 * sender without privilege cannot claim another's. */
static int creds(void) {
    struct {
        unsigned short family;
        char path[108];
    } a;
    memset(&a, 0, sizeof a);
    a.family = AF_UNIX;
    memcpy(a.path + 1, "fwe-creds-test", 14);
    unsigned alen = 2 + 1 + 14;
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(srv, &a, alen);
    listen(srv, 1);
    int child = fork();
    if (child == 0) {
        setgid(1000);
        setuid(1000);
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        connect(c, &a, alen);
        unsigned own[3] = {(unsigned)getpid(), 1000, 1000}, root[3] = {(unsigned)getpid(), 0, 0};
        long spoof = send_creds(c, root);
        int e = errno;
        printf("child: claiming root %ld errno %d\n", spoof, e);
        fflush(0);
        char b = 'x';
        write(c, &b, 1);
        send_creds(c, own);
        read(c, &b, 1);
        _exit(0);
    }
    int s = accept(srv, 0, 0);
    unsigned peer[3];
    unsigned len = sizeof peer;
    getsockopt(s, SOL_SOCKET, SO_PEERCRED, peer, &len);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    unsigned got[3] = {0}, given[3] = {0};
    int had = recv_creds(s, got);
    int had2 = recv_creds(s, given);
    write(s, "x", 1);
    int status;
    waitpid(child, &status, 0);
    printf("peer is child %d uid %u gid %u\n", peer[0] == (unsigned)child, peer[1], peer[2]);
    printf("passed %d: child %d uid %u gid %u\n", had, got[0] == (unsigned)child, got[1], got[2]);
    printf("given %d: child %d uid %u gid %u\n", had2, given[0] == (unsigned)child, given[1],
           given[2]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "creds"))
        return creds();
    if (!strcmp(argv[1], "cloexec"))
        return cloexec();
    if (!strcmp(argv[1], "many"))
        return many();
    if (!strcmp(argv[1], "truncated"))
        return truncated();
    if (!strcmp(argv[1], "emulated"))
        return emulated();
    return 2;
}
