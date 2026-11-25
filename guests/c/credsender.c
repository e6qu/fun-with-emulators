/* SO_PASSCRED gives each message's sender: a process forked after the
 * socket pair was made, sending on its inherited end, is named by the
 * credentials its message carries, whether it is still there when the
 * message is read or not, while SO_PEERCRED still names the process that
 * made the pair (Chromium's zygote learns its children's pids so). For
 * each socket type. */
typedef unsigned long size_t;
typedef long ssize_t;
struct iovec { void *base; size_t len; };
struct msghdr {
    void *name; unsigned namelen; struct iovec *iov; size_t iovlen;
    void *control; size_t controllen; int flags;
};
int socketpair(int domain, int type, int protocol, int fds[2]);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
int getsockopt(int fd, int level, int name, void *val, unsigned *len);
ssize_t recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t write(int fd, const void *buf, size_t n);
ssize_t read(int fd, void *buf, size_t n);
int pipe(int fds[2]);
int close(int fd);
int fork(void);
int waitpid(int pid, int *status, int options);
void _exit(int status);
int printf(const char *fmt, ...);
int getpid(void);

static const char *who(int pid, int me, int child) {
    return pid == me ? "mine" : pid == child ? "the sender's" : pid == 0 ? "0" : "other";
}

/* The child sends, then waits until the parent has read (alive), or ends
 * first (gone): its message names it either way. */
static void probe(const char *name, int type, int gone) {
    int sv[2], sent[2], done[2];
    socketpair(1, type, 0, sv);
    pipe(sent);
    pipe(done);
    int on = 1;
    setsockopt(sv[0], 1, 16 /* SO_PASSCRED */, &on, sizeof on);
    int child = fork();
    if (child == 0) {
        close(sv[0]);
        write(sv[1], "hello", 5);
        if (!gone) {
            char c;
            write(sent[1], "s", 1);
            read(done[0], &c, 1);
        }
        _exit(0);
    }
    close(sv[1]);
    char c;
    if (gone)
        waitpid(child, 0, 0);
    else
        read(sent[0], &c, 1);
    char buf[16], ctl[64];
    struct iovec io = {buf, sizeof buf};
    struct msghdr m = {0, 0, &io, 1, ctl, sizeof ctl, 0};
    ssize_t r = recvmsg(sv[0], &m, 0x40 /* MSG_DONTWAIT */);
    int me = getpid();
    printf("%s, sender %s: %ld bytes, credentials pid %s", name, gone ? "gone" : "alive",
           (long)r, r > 0 && m.controllen ? who(((int *)(ctl + 16))[0], me, child) : "none");
    int cred[3] = {0};
    unsigned len = sizeof cred;
    getsockopt(sv[0], 1, 17 /* SO_PEERCRED */, cred, &len);
    printf(", peer pid %s\n", who(cred[0], me, child));
    if (!gone) {
        write(done[1], "d", 1);
        waitpid(child, 0, 0);
    }
    close(sv[0]);
    close(sent[0]);
    close(sent[1]);
    close(done[0]);
    close(done[1]);
}

int main(void) {
    for (int gone = 0; gone < 2; gone++) {
        probe("stream", 1, gone);
        probe("datagram", 2, gone);
        probe("seqpacket", 5, gone);
    }
    return 0;
}
