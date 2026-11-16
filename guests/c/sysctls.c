/* The sysctls programs read and set: the socket buffer limits, the
 * namespace limits of /proc/sys/user (each user namespace's own, held to
 * on creation with ENOSPC, as is Linux's nesting depth), listen's backlog
 * cap and the random directory. Runs as root; everything it sets is in
 * namespaces of its own, so other programs are not affected.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_NONBLOCK 04000

struct sockaddr_un {
    unsigned short family;
    char path[108];
};

static char buf[4096];

static void show(const char *path) {
    long n = slurp(path, buf, sizeof buf);
    if (n < 0) {
        printf("%s: errno %ld\n", path, -n);
    } else {
        printf("%s: %s", path, buf);
    }
}

/* How many user namespaces nest in a fresh child before ENOSPC. */
static void depth(void) {
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        int n = 0;
        while (unshare(CLONE_NEWUSER) == 0 && n < 100) {
            n++;
        }
        printf("nested user namespaces: %d, then errno %d\n", n, errno);
        fflush(0);
        _exit(0);
    }
    reap(pid);
}

/* Connections a listener with backlog 100 queues under somaxconn 1. */
static void backlog(void) {
    if (put("/proc/sys/net/core/somaxconn", "1") != 0) {
        printf("somaxconn: not set\n");
        return;
    }
    show("/proc/sys/net/core/somaxconn");
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.family = AF_UNIX;
    snprintf(a.path, sizeof a.path, "/tmp/fwe-backlog-%d", getpid());
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    unlink(a.path);
    if (bind(l, &a, sizeof a) != 0 || listen(l, 100) != 0) {
        printf("listen: errno %d\n", errno);
        return;
    }
    int queued = 0;
    for (int i = 0; i < 20; i++) {
        int c = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (connect(c, &a, sizeof a) == 0) {
            queued++;
        }
    }
    unlink(a.path);
    printf("queued with somaxconn 1: %s\n", queued <= 4 ? "few" : "many");
}

int main(void) {
    show("/proc/sys/net/core/rmem_max");
    show("/proc/sys/net/core/wmem_max");
    show("/proc/sys/user/max_user_namespaces");
    show("/proc/sys/kernel/random/poolsize");
    int fd = open("/proc/sys/kernel/random", O_RDONLY | O_DIRECTORY);
    printf("random is a directory: %d\n", fd >= 0);
    depth();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        printf("unshare: errno %d\n", errno);
        return 1;
    }
    /* A new user namespace has no limit of its own until one is set. */
    show("/proc/sys/user/max_user_namespaces");
    printf("set max_net_namespaces 0: %d\n", put("/proc/sys/user/max_net_namespaces", "0"));
    printf("new net namespace: %d\n", unshare(CLONE_NEWNET) == 0 ? 0 : errno);
    printf("set max_user_namespaces 1: %d\n", put("/proc/sys/user/max_user_namespaces", "1"));
    printf("first new user namespace: %d\n", unshare(CLONE_NEWUSER) == 0 ? 0 : errno);
    printf("second new user namespace: %d\n", unshare(CLONE_NEWUSER) == 0 ? 0 : errno);
    backlog();
    fflush(0);
    return 0;
}
