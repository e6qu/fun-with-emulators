/* Firefox's fork server, as it starts a sandboxed content process
 * (ipc/glue/ForkServer.cpp, security/sandbox/linux/launch/SandboxLaunch.cpp):
 * the parent sends the server one end of an exec socket (SCM_RIGHTS, into a
 * control buffer of room for 8192 descriptors); the server clones a child
 * in new user, network and IPC namespaces; the child starts a chroot
 * helper with CLONE_FS, which closes every descriptor but its own socket;
 * the child then reads what the parent writes on the exec socket, and has
 * the helper chroot them both into the helper's /proc/self/fdinfo. */
typedef unsigned int socklen_t;
struct iovec { void *base; unsigned long len; };
struct msghdr {
    void *name; socklen_t namelen; struct iovec *iov; unsigned long iovlen;
    void *control; unsigned long controllen; int flags;
};
struct cmsghdr { unsigned long len; int level; int type; };

int printf(const char *fmt, ...);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);
int socketpair(int domain, int type, int protocol, int fds[2]);
long sendmsg(int fd, const struct msghdr *m, int flags);
long recvmsg(int fd, struct msghdr *m, int flags);
long read(int fd, void *buf, unsigned long n);
long write(int fd, const void *buf, unsigned long n);
int close(int fd);
int open(const char *path, int flags, ...);
long syscall(long n, ...);
int fork(void);
int waitpid(int pid, int *status, int options);
int getuid(void);
int getgid(void);
int chroot(const char *path);
int chdir(const char *path);
void *opendir(const char *path);
void *readdir(void *dir);
int dirfd(void *dir);
int closedir(void *dir);
long strtol(const char *s, char **end, int base);
void *memset(void *p, int c, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);
int fflush(void *f);
void _exit(int status);
char *strerror(int e);
int *__errno_location(void);
#define errno (*__errno_location())

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_CLOEXEC 0x80000
#define SOL_SOCKET 1
#define SCM_RIGHTS 1
#define SIGCHLD 17
#define SYS_clone 220
#define CLONE_FS 0x200
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNET 0x40000000
#define O_WRONLY 1
#define CMSG_ALIGN(n) (((n) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#define CMSG_SPACE(n) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(n))
#define CMSG_LEN(n) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (n))
#define CMSG_DATA(c) ((unsigned char *)(c) + CMSG_ALIGN(sizeof(struct cmsghdr)))

/* As Firefox's MiniTransceiver: room for 8192 descriptors. */
static char control[CMSG_SPACE(sizeof(int) * 8192)];

static void send_fd(int sock, int fd) {
    char byte = 'x';
    struct iovec iov = {&byte, 1};
    union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int))]; } c;
    memset(&c, 0, sizeof c);
    struct msghdr m = {0, 0, &iov, 1, c.buf, sizeof c.buf, 0};
    c.h.len = CMSG_LEN(sizeof(int));
    c.h.level = SOL_SOCKET;
    c.h.type = SCM_RIGHTS;
    memcpy(CMSG_DATA(&c.h), &fd, sizeof fd);
    if (sendmsg(sock, &m, 0) != 1) printf("sendmsg: %s\n", strerror(errno));
}

static int recv_fd(int sock) {
    char byte;
    struct iovec iov = {&byte, 1};
    struct msghdr m = {0, 0, &iov, 1, control, sizeof control, 0};
    long n = recvmsg(sock, &m, 0);
    if (n != 1 || m.controllen < CMSG_LEN(sizeof(int))) {
        printf("recvmsg: %ld %s\n", n, n < 0 ? strerror(errno) : "no descriptor");
        return -1;
    }
    int fd;
    memcpy(&fd, CMSG_DATA((struct cmsghdr *)control), sizeof fd);
    return fd;
}

static void write_file(const char *path, const char *s, unsigned long n) {
    int fd = open(path, O_WRONLY);
    if (fd < 0 || write(fd, s, n) != (long)n) printf("%s: %s\n", path, strerror(errno));
    if (fd >= 0) close(fd);
}

/* The chroot helper: every descriptor but `keep` closed, as Firefox's
 * CloseSuperfluousFds does; then chroot both into its fdinfo. */
static void helper(int keep) {
    void *d = opendir("/proc/self/fd");
    int own = d ? dirfd(d) : -1;
    char *e;
    int fds[256], n = 0;
    while (d && (e = readdir(d)) != 0 && n < 256) {
        int fd = (int)strtol(e + 19, 0, 10);
        if (e[19] != '.' && fd != keep && fd != own) fds[n++] = fd;
    }
    if (d) closedir(d);
    for (int i = 0; i < n; i++) close(fds[i]);
    char c;
    if (read(keep, &c, 1) != 1) _exit(0);
    if (chroot("/proc/self/fdinfo") != 0 || chdir("/") != 0) _exit(2);
    write(keep, "r", 1);
    _exit(0);
}

static void child(int exec_fd, int chroot_client, int chroot_server, int uid, int gid) {
    char map[64];
    int n = snprintf(map, sizeof map, "%d %d 1", uid, uid);
    write_file("/proc/self/uid_map", map, n);
    write_file("/proc/self/setgroups", "deny", 4);
    n = snprintf(map, sizeof map, "%d %d 1", gid, gid);
    write_file("/proc/self/gid_map", map, n);
    long h = syscall(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
    if (h == 0) helper(chroot_server);
    close(chroot_server);
    char buf[64] = {0};
    long got = read(exec_fd, buf, sizeof buf - 1);
    printf("child read: %s\n", got > 0 ? buf : got == 0 ? "end of file" : strerror(errno));
    write(chroot_client, "q", 1);
    char c;
    printf("chroot answered: %s\n", read(chroot_client, &c, 1) == 1 ? "yes" : "no");
    fflush(0);
    _exit(0);
}

int main(void) {
    int chan[2], exec[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, chan) || socketpair(AF_UNIX, SOCK_STREAM, 0, exec)) return 1;
    int uid = getuid(), gid = getgid();
    fflush(0);
    int server = fork();
    if (server == 0) {
        close(chan[0]);
        close(exec[0]);
        close(exec[1]);
        int exec_fd = recv_fd(chan[1]);
        if (exec_fd < 0) _exit(1);
        int chroot_fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, chroot_fds)) _exit(1);
        fflush(0);
        long pid = syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWIPC | SIGCHLD, 0, 0, 0, 0);
        if (pid == 0) child(exec_fd, chroot_fds[0], chroot_fds[1], uid, gid);
        close(exec_fd);
        close(chroot_fds[0]);
        close(chroot_fds[1]);
        write(chan[1], "p", 1);
        int status;
        waitpid((int)pid, &status, 0);
        printf("server: child %d\n", status);
        fflush(0);
        _exit(0);
    }
    close(chan[1]);
    send_fd(chan[0], exec[1]);
    close(exec[1]);
    char c;
    read(chan[0], &c, 1);
    long wrote = write(exec[0], "exec info", 9);
    int status;
    waitpid(server, &status, 0);
    printf("parent wrote: %ld, server: %d\n", wrote, status);
    return 0;
}
