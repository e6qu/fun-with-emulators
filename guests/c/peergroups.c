/* SO_PEERGROUPS, as D-Bus reads it: the peer's supplementary groups,
 * the size needed for a buffer too small (ERANGE), ENODATA where there is
 * no peer; and another process's /proc/<pid>/status lists its groups. */
int printf(const char *fmt, ...);
int socketpair(int domain, int type, int protocol, int fds[2]);
int socket(int domain, int type, int protocol);
int getsockopt(int fd, int level, int name, void *val, unsigned *len);
int getgroups(int n, unsigned *list);
int fork(void);
int waitpid(int pid, int *status, int options);
int pipe(int fds[2]);
long read(int fd, void *buf, unsigned long n);
long write(int fd, const void *buf, unsigned long n);
int open(const char *path, int flags, ...);
int close(int fd);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);
char *strstr(const char *s, const char *t);
char *strchr(const char *s, int c);
int strcmp(const char *a, const char *b);
void _exit(int status);
int *__errno_location(void);
#define errno (*__errno_location())
#define SO_PEERGROUPS 59

static int status_groups(int pid, char *out, int n) {
    char path[64], buf[4096];
    if (pid < 0) snprintf(path, sizeof path, "/proc/self/status");
    else snprintf(path, sizeof path, "/proc/%d/status", pid);
    int fd = open(path, 0);
    long got = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[got > 0 ? got : 0] = 0;
    char *g = strstr(buf, "Groups:");
    if (!g) return -1;
    char *nl = strchr(g, '\n');
    if (nl) *nl = 0;
    snprintf(out, n, "%s", g);
    return 0;
}

int main(void) {
    unsigned mine[256];
    int n = getgroups(256, mine);
    int sv[2];
    socketpair(1, 1, 0, sv);
    unsigned got[256], len = 0;
    int r = getsockopt(sv[0], 1, SO_PEERGROUPS, got, &len);
    printf("no room: %d %s, needed: %s\n", r, errno == 34 ? "ERANGE" : "other",
           len == 4u * n ? "the groups' size" : "other");
    len = sizeof got;
    r = getsockopt(sv[0], 1, SO_PEERGROUPS, got, &len);
    int same = r == 0 && len == 4u * n;
    for (int i = 0; same && i < n; i++) same = got[i] == mine[i];
    printf("peer's groups: %d, getgroups' own: %s\n", r, same ? "yes" : "no");
    int lone = socket(1, 1, 0);
    len = sizeof got;
    r = getsockopt(lone, 1, SO_PEERGROUPS, got, &len);
    printf("unconnected: %d %s\n", r, errno == 61 ? "ENODATA" : "other");
    int tcp = socket(2, 1, 0);
    len = sizeof got;
    r = getsockopt(tcp, 1, SO_PEERGROUPS, got, &len);
    printf("TCP: %d %s\n", r, errno == 61 ? "ENODATA" : "other");
    int p[2];
    pipe(p);
    int pid = fork();
    if (pid == 0) {
        char c;
        read(p[0], &c, 1);
        _exit(0);
    }
    char a[512], b[512];
    status_groups(pid, b, sizeof b);
    status_groups(-1, a, sizeof a);
    write(p[1], "x", 1);
    waitpid(pid, 0, 0);
    printf("child's status lists the groups: %s\n", strcmp(a, b) == 0 ? "yes" : "no");
    /* The line as Linux writes it: each group then a space. */
    char want[512] = "Groups:\t";
    int at = 8;
    for (int i = 0; i < n; i++) at += snprintf(want + at, sizeof want - at, "%u ", mine[i]);
    if (n == 0) snprintf(want + at, sizeof want - at, " ");
    printf("each group then a space: %s\n", strcmp(a, want) == 0 ? "yes" : "no");
    return 0;
}
