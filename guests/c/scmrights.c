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

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "cloexec"))
        return cloexec();
    return 2;
}
