/* Namespaces as a process sees them: unshare of what a single-threaded
 * process shares with no one (its thread group, signal handlers and
 * memory), refused with other threads; NS_GET_USERNS of a namespace that
 * is not a user namespace gives the user namespace it was made in; and
 * /proc/<pid>/cgroup of another process is relative to the reader's cgroup
 * namespace. Runs as root.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

#define NS_GET_USERNS 0xb701

static char path[256], buf[256];

struct kstat {
    unsigned long dev, ino;
    unsigned mode, nlink, uid, gid;
    unsigned long rdev, pad;
    long size;
    int blksize, pad2;
    long blocks;
    long times[6];
    unsigned unused[2];
};

static unsigned long inode(int fd) {
    struct kstat st;
    if (syscall(80, fd, &st) != 0) {
        return 0;
    }
    return st.ino;
}

static unsigned long ns_inode(const char *path) {
    int fd = open(path, O_RDONLY);
    unsigned long ino = inode(fd);
    close(fd);
    return ino;
}

static int stop_pipe[2];

static void *waiter(void *arg) {
    char c;
    read(stop_pipe[0], &c, 1);
    return arg;
}

static void unshare_shared(void) {
    printf("single-threaded: thread %d sighand %d vm %d\n", unshare(CLONE_THREAD),
           unshare(CLONE_SIGHAND), unshare(CLONE_VM));
    pipe(stop_pipe);
    pthread_t t;
    pthread_create(&t, 0, waiter, 0);
    int r[3];
    int flags[3] = {CLONE_THREAD, CLONE_SIGHAND, CLONE_VM};
    for (int i = 0; i < 3; i++) {
        r[i] = unshare(flags[i]) == 0 ? 0 : errno;
    }
    printf("with a thread: thread %d sighand %d vm %d\n", r[0], r[1], r[2]);
    write(stop_pipe[1], "x", 1);
    pthread_join(t, 0);
}

static void owner(void) {
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        unshare(CLONE_NEWUSER);
        /* A child makes a user namespace and a UTS namespace in it: the
         * UTS namespace's owner is the child's, not this process's. */
        int ready[2], done[2];
        pipe(ready);
        pipe(done);
        pid_t kid = fork();
        if (kid == 0) {
            unshare(CLONE_NEWUSER | CLONE_NEWUTS);
            write(ready[1], "x", 1);
            char c;
            read(done[0], &c, 1);
            _exit(0);
        }
        char c;
        read(ready[0], &c, 1);
        snprintf(path, sizeof path, "/proc/%d/ns/user", kid);
        unsigned long kids = ns_inode(path);
        snprintf(path, sizeof path, "/proc/%d/ns/uts", kid);
        int uts = open(path, O_RDONLY);
        int owner = ioctl(uts, NS_GET_USERNS);
        printf("uts owner is the user namespace it was made in: %d\n",
               owner >= 0 && inode(owner) == kids && kids != ns_inode("/proc/self/ns/user"));
        write(done[1], "x", 1);
        reap(kid);
        snprintf(buf, sizeof buf, "/proc/%d/ns/uts", getppid());
        int init_uts = open(buf, O_RDONLY);
        int r = ioctl(init_uts, NS_GET_USERNS);
        printf("an initial namespace's owner, from below: %d\n", r < 0 ? errno : 0);
        fflush(0);
        _exit(0);
    }
    reap(pid);
}


static void cgroups(void) {
    char top[128];
    snprintf(top, sizeof top, "/sys/fs/cgroup/fwe-nsprocs-%d", getpid());
    mkdir(top, 0755);
    snprintf(path, sizeof path, "%s/a", top);
    mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/b", top);
    mkdir(path, 0755);
    int ready[2], done[2];
    pipe(ready);
    pipe(done);
    fflush(0);
    pid_t b = fork();
    if (b == 0) {
        snprintf(path, sizeof path, "%s/b/cgroup.procs", top);
        put(path, "0");
        write(ready[1], "x", 1);
        char c;
        read(done[0], &c, 1);
        _exit(0);
    }
    char c;
    read(ready[0], &c, 1);
    pid_t a = fork();
    if (a == 0) {
        snprintf(path, sizeof path, "%s/a/cgroup.procs", top);
        put(path, "0");
        unshare(CLONE_NEWCGROUP);
        slurp("/proc/self/cgroup", buf, sizeof buf);
        printf("own: %s", buf);
        snprintf(path, sizeof path, "/proc/%d/cgroup", b);
        slurp(path, buf, sizeof buf);
        printf("sibling's: %s", buf);
        snprintf(path, sizeof path, "/proc/%d/cgroup", getppid());
        slurp(path, buf, sizeof buf);
        printf("the root's: %s", buf);
        fflush(0);
        _exit(0);
    }
    reap(a);
    write(done[1], "x", 1);
    reap(b);
    snprintf(path, sizeof path, "%s/a", top);
    rmdir(path);
    snprintf(path, sizeof path, "%s/b", top);
    rmdir(path);
    rmdir(top);
}

int main(void) {
    unshare_shared();
    owner();
    cgroups();
    fflush(0);
    return 0;
}
