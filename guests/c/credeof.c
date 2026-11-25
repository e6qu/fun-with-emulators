/* SO_PASSCRED at the end of a Unix socket's stream: a message carries the
 * sender's credentials; once the peer is gone, recvmsg returns 0 with no
 * control message (crashpad tells the end so), for each socket type; a
 * datagram socket, which has no end, has nothing more. */
typedef unsigned long size_t;
typedef long ssize_t;
struct iovec { void *base; size_t len; };
struct msghdr {
    void *name; unsigned namelen; struct iovec *iov; size_t iovlen;
    void *control; size_t controllen; int flags;
};
int socketpair(int domain, int type, int protocol, int fds[2]);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
ssize_t recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t write(int fd, const void *buf, size_t n);
int close(int fd);
int printf(const char *fmt, ...);
int getpid(void);
unsigned getuid(void);
unsigned getgid(void);
int *__errno_location(void);
#define errno (*__errno_location())

static void probe(const char *name, int type) {
    int sv[2];
    socketpair(1, type, 0, sv);
    int on = 1;
    setsockopt(sv[0], 1, 16 /* SO_PASSCRED */, &on, sizeof on);
    write(sv[1], "hello", 5);
    close(sv[1]);
    for (int i = 0; i < 2; i++) {
        char buf[16], ctl[64];
        struct iovec io = {buf, sizeof buf};
        struct msghdr m = {0, 0, &io, 1, ctl, sizeof ctl, 0};
        /* Without waiting: a datagram socket has no end, only nothing. */
        ssize_t r = recvmsg(sv[0], &m, 0x40 /* MSG_DONTWAIT */);
        printf("%s %s: %ld%s, control ", name, i ? "then" : "first", (long)r,
               r < 0 ? (errno == 11 ? " EAGAIN" : " other") : " bytes");
        if (r < 0 && errno != 11) printf("(errno %d) ", errno);
        if (r >= 0 && m.controllen) {
            /* struct ucred after the 16-byte cmsghdr */
            int *c = (int *)(ctl + 16);
            printf("with credentials: pid %s, uid %s, gid %s\n",
                   c[0] == getpid() ? "mine" : c[0] == 0 ? "0" : "other",
                   (unsigned)c[1] == getuid() ? "mine" : c[1] == 0 ? "0" : c[1] == 65534 ? "overflow" : "other",
                   (unsigned)c[2] == getgid() ? "mine" : c[2] == 0 ? "0" : c[2] == 65534 ? "overflow" : "other");
        } else printf("none\n");
    }
    close(sv[0]);
}

int main(void) {
    probe("stream", 1);
    probe("datagram", 2);
    probe("seqpacket", 5);
    return 0;
}
