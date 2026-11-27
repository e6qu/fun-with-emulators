/* rtnetlink dumps by the family asked for, as programs ask for them
 * (Firefox's network monitor asks for addresses and routes with
 * AF_PACKET, and for neighbours): how many messages of each family come,
 * in a new network namespace with lo up; in the initial one, which
 * families come (neighbours: whether each is of the family asked for, as
 * what neighbours a host has varies). */
int printf(const char *fmt, ...);
int socket(int domain, int type, int protocol);
long send(int fd, const void *buf, unsigned long n, int flags);
long recv(int fd, void *buf, unsigned long n, int flags);
int close(int fd);
int unshare(int flags);
int fork(void);
int waitpid(int pid, int *status, int options);
void *memset(void *p, int c, unsigned long n);
int fflush(void *f);
void _exit(int status);

struct nlmsghdr { unsigned len; unsigned short type, flags; unsigned seq, pid; };
static char buf[65536];

/* Dump `type` for `family`: "error N", or the count of each family. */
static int host_neighbours;

static void dump(int fd, int type, int family, const char *name, int body) {
    char req[64];
    memset(req, 0, sizeof req);
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    h->len = 16 + body;
    h->type = type;
    h->flags = 1 | 0x300;
    h->seq = 1;
    req[16] = family;
    send(fd, req, h->len, 0);
    int counts[64] = {0}, error = 0, done = 0;
    while (!done) {
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + 16 <= n;) {
            struct nlmsghdr *m = (struct nlmsghdr *)(buf + at);
            if (m->type == 3) { done = 1; break; }
            if (m->type == 2) { error = *(int *)(m + 1); done = 1; break; }
            int f = (unsigned char)buf[at + 16];
            if (f < 64) counts[f]++;
            at += (m->len + 3) & ~3u;
        }
    }
    printf("  %s family %d:", name, family);
    if (error) printf(" error %d", error);
    if (type == 30 && host_neighbours) {
        int others = 0;
        for (int f = 0; f < 64; f++)
            if (counts[f] && family && f != family) others = 1;
        printf(" answered, each of the family asked for: %s\n", others ? "no" : "yes");
        return;
    }
    for (int f = 0; f < 64; f++)
        if (counts[f]) printf(" %d:%s", f, counts[f] > 0 ? "some" : "");
    printf("\n");
}

static void all(int fd) {
    int fams[] = {0, 2, 10, 17};
    for (int i = 0; i < 4; i++) {
        dump(fd, 22, fams[i], "addresses", 8);
        dump(fd, 26, fams[i], "routes", 12);
        dump(fd, 30, fams[i], "neighbours", 12);
    }
}

int main(void) {
    int fd = socket(16, 3, 0);
    printf("initial namespace:\n");
    host_neighbours = 1;
    all(fd);
    host_neighbours = 0;
    close(fd);
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        if (unshare(0x10000000 | 0x40000000)) _exit(1);
        fd = socket(16, 3, 0);
        char req[48];
        memset(req, 0, sizeof req);
        struct nlmsghdr *h = (struct nlmsghdr *)req;
        h->len = 32; h->type = 16; h->flags = 5; h->seq = 2;
        *(int *)(req + 20) = 1; *(unsigned *)(req + 24) = 1; *(unsigned *)(req + 28) = 1;
        send(fd, req, 32, 0);
        recv(fd, buf, sizeof buf, 0);
        printf("new namespace, lo up:\n");
        all(fd);
        fflush(0);
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
    return 0;
}
