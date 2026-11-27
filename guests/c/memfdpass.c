/* A sealed memfd passed to another process, as Firefox shares memory with
 * its content processes: made sealable, sized, its size sealed; a
 * read-only descriptor of it opened through /proc/self/fd; both sent over
 * a Unix socket to a forked child, which reads their seals and size and
 * maps the read-only one, then starts a process of its own in new user,
 * IPC and network namespaces (as Firefox's fork server starts a content
 * process), which is sent them again and reads their seals. Last, over
 * a stream socket (Firefox's IPC channel), messages of data carrying them
 * sent ahead of reads of 4 KiB, which stop at each message's descriptors,
 * a child of the sender's having ended (and another having started a
 * program: this one, which ends at once given an argument) before they
 * are read.
 * First, Firefox's test of memfds: one made with
 * MFD_NOEXEC_SEAL, reopened read-only through /proc/self/fd. */
struct stat {
    unsigned long st_dev, st_ino;
    unsigned st_mode, st_nlink, st_uid, st_gid;
    unsigned long st_rdev, pad1;
    long st_size;
    int st_blksize, pad2;
    long st_blocks, times[6];
    unsigned unused[2];
};
struct iovec {
    void *iov_base;
    unsigned long iov_len;
};
struct msghdr {
    void *msg_name;
    unsigned msg_namelen;
    struct iovec *msg_iov;
    unsigned long msg_iovlen;
    void *msg_control;
    unsigned long msg_controllen;
    int msg_flags;
};
struct cmsghdr {
    unsigned long cmsg_len;
    int cmsg_level, cmsg_type;
};
int memfd_create(const char *name, unsigned flags);
int ftruncate(int fd, long len);
void *mmap(void *at, unsigned long len, int prot, int flags, int fd, long off);
int fcntl(int fd, int cmd, ...);
int open(const char *path, int flags, ...);
int fstat(int fd, struct stat *st);
int socketpair(int domain, int type, int proto, int sv[2]);
long sendmsg(int sock, const struct msghdr *m, int flags);
long recvmsg(int sock, struct msghdr *m, int flags);
int fork(void);
int waitpid(int pid, int *status, int options);
int close(int fd);
void _exit(int status);
int printf(const char *fmt, ...);
int snprintf(char *s, unsigned long n, const char *fmt, ...);
int fflush(void *f);
char *strcpy(char *d, const char *s);
void *memcpy(void *d, const void *s, unsigned long n);
long syscall(long n, ...);
int execv(const char *path, char *const argv[]);

#define MFD_CLOEXEC 1
#define MFD_ALLOW_SEALING 2
#define MFD_NOEXEC_SEAL 8
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 1
#define F_SEAL_SHRINK 2
#define F_SEAL_GROW 4
#define F_SEAL_FUTURE_WRITE 0x10
#define O_RDONLY 0
#define O_CLOEXEC 02000000
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_FAILED ((void *)-1)
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_SEQPACKET 5
#define SOCK_CLOEXEC 02000000
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define CMSG_ALIGN(n) (((n) + 7) & ~7UL)
#define CMSG_SPACE(n) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(n))
#define CMSG_LEN(n) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (n))
#define CMSG_DATA(c) ((unsigned char *)(c) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define WIFEXITED(s) (((s) & 0x7f) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)

static void report(const char *who, int fd) {
    struct stat st;
    int seals = fcntl(fd, F_GET_SEALS);
    int sized = fstat(fd, &st);
    printf("%s: seals %#x, size %ld\n", who, seals, sized == 0 ? (long)st.st_size : -1L);
}

static int send_fds(int sock, int a, int b) {
    char byte = 'x';
    struct iovec iov = {&byte, 1};
    union {
        struct cmsghdr h;
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } u;
    struct msghdr m = {0, 0, 0, 0, 0, 0, 0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof u.buf;
    struct cmsghdr *c = (struct cmsghdr *)u.buf;
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int fds[2] = {a, b};
    memcpy(CMSG_DATA(c), fds, sizeof fds);
    return (int)sendmsg(sock, &m, 0);
}

/* `len` bytes of data from `sock` (a stream) carrying descriptors `a` and
 * `b`. */
static int send_data_fds(int sock, int a, int b, unsigned long len) {
    static char data[8192];
    struct iovec iov = {data, len};
    union {
        struct cmsghdr h;
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } u;
    struct msghdr m = {0, 0, 0, 0, 0, 0, 0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof u.buf;
    struct cmsghdr *c = (struct cmsghdr *)u.buf;
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int fds[2] = {a, b};
    memcpy(CMSG_DATA(c), fds, sizeof fds);
    return (int)sendmsg(sock, &m, 0);
}

/* Reads of up to 4 KiB from stream `sock` until `total` bytes came: each
 * read's length, and the seals of the descriptors it carried. */
static void read_stream(int sock, long total) {
    static char data[4096];
    long got = 0;
    while (got < total) {
        struct iovec iov = {data, sizeof data};
        union {
            struct cmsghdr h;
            char buf[CMSG_SPACE(8 * sizeof(int))];
        } u;
        struct msghdr m = {0, 0, 0, 0, 0, 0, 0};
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = u.buf;
        m.msg_controllen = sizeof u.buf;
        long n = recvmsg(sock, &m, 0x40000000 /* MSG_CMSG_CLOEXEC */);
        if (n <= 0) {
            printf("read: %ld\n", n);
            return;
        }
        got += n;
        struct cmsghdr *c = (struct cmsghdr *)u.buf;
        if (m.msg_controllen >= sizeof *c && c->cmsg_type == SCM_RIGHTS) {
            int k = (int)((c->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            int fds[8];
            memcpy(fds, CMSG_DATA(c), k * sizeof(int));
            printf("read %ld bytes with %d descriptors, seals", n, k);
            for (int i = 0; i < k; i++) printf(" %#x", fcntl(fds[i], F_GET_SEALS));
            printf("\n");
        } else {
            printf("read %ld bytes\n", n);
        }
    }
}

static int recv_fds(int sock, int *a, int *b) {
    char byte;
    struct iovec iov = {&byte, 1};
    union {
        struct cmsghdr h;
        char buf[CMSG_SPACE(2 * sizeof(int))];
    } u;
    struct msghdr m = {0, 0, 0, 0, 0, 0, 0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof u.buf;
    if (recvmsg(sock, &m, 0) != 1) return -1;
    struct cmsghdr *c = (struct cmsghdr *)u.buf;
    if (m.msg_controllen < sizeof *c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fds[2];
    memcpy(fds, CMSG_DATA(c), sizeof fds);
    *a = fds[0];
    *b = fds[1];
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) return 0;
    int test = memfd_create("test", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL);
    char tpath[64];
    snprintf(tpath, sizeof tpath, "/proc/self/fd/%d", test);
    int tro = open(tpath, O_RDONLY | O_CLOEXEC);
    printf("noexec memfd: seals %#x, reopened read-only: %s\n", fcntl(test, F_GET_SEALS),
           tro >= 0 ? "yes" : "no");
    int fd = memfd_create("shared", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, 65536) != 0) return 1;
    char *w = mmap(0, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (w == MAP_FAILED) return 1;
    strcpy(w, "fwe");
    printf("size sealed: %d\n", fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW));
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    int ro = open(path, O_RDONLY | O_CLOEXEC);
    printf("reopened read-only: %s\n", ro >= 0 ? "yes" : "no");
    report("read-only, here", ro);
    printf("frozen: %d\n",
           fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL | F_SEAL_FUTURE_WRITE));
    report("writable, here", fd);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) return 1;
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        close(sv[0]);
        int a, b;
        if (recv_fds(sv[1], &a, &b) != 0) _exit(2);
        report("writable, there", a);
        report("read-only, there", b);
        char *r = mmap(0, 65536, PROT_READ, MAP_SHARED, b, 0);
        printf("read there: %s\n", r == MAP_FAILED ? "(not mapped)" : r);
        char *rw = mmap(0, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, b, 0);
        printf("mapped to write through the read-only one: %s\n",
               rw == MAP_FAILED ? "no" : "yes");
        fflush(0);
        /* clone(CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD) */
        long inner = syscall(220, 0x58000011L, 0L, 0L, 0L, 0L);
        if (inner == 0) {
            int c, d;
            if (recv_fds(sv[1], &c, &d) != 0) _exit(2);
            report("writable, in new namespaces", c);
            report("read-only, in new namespaces", d);
            fflush(0);
            _exit(0);
        }
        int st;
        waitpid((int)inner, &st, 0);
        printf("in new namespaces: exit %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        fflush(0);
        _exit(0);
    }
    close(sv[1]);
    if (send_fds(sv[0], fd, ro) != 1 || send_fds(sv[0], fd, ro) != 1) return 1;
    int status;
    waitpid(pid, &status, 0);
    printf("child: exit %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    int st[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, st) != 0) return 1;
    for (int i = 0; i < 3; i++)
        if (send_data_fds(st[0], fd, ro, 3000) != 3000) return 1;
    fflush(0);
    int gone = fork();
    if (gone == 0) _exit(0);
    waitpid(gone, &status, 0);
    int ran = fork();
    if (ran == 0) {
        char *argv[] = {"memfdpass", "end", 0};
        execv("/proc/self/exe", argv);
        _exit(127);
    }
    waitpid(ran, &status, 0);
    printf("a child ended, another ran a program: exit %d\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    fflush(0);
    int reader = fork();
    if (reader == 0) {
        read_stream(st[1], 9000);
        fflush(0);
        _exit(0);
    }
    waitpid(reader, &status, 0);
    printf("reader: exit %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
