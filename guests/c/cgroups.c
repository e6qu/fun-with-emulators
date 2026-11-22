/* The cgroup v2 hierarchy's rules as a container runtime meets them: the
 * hierarchy limits on mkdir, cgroup.type, pids.max over threads as well as
 * processes (with pids.events counting the refusals), cgroup.threads
 * listing threads, a freeze that holds every cgroup below and every
 * process that joins or is forked into one, delegation (write access to
 * the common ancestor's cgroup.procs, the cgroup namespace's bounds), and
 * no cgroup v1. Runs as root, in cgroups of its own that it removes.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

int chown(const char *path, unsigned uid, unsigned gid);
int setrlimit(int resource, const unsigned long limit[2]);
int getrlimit(int resource, unsigned long limit[2]);

#define RLIMIT_NPROC 6
#define RLIM_INFINITY (~0UL)

static char top[128], path[256], buf[4096];

static const char *at(const char *rel) {
    snprintf(path, sizeof path, "%s/%s", top, rel);
    return path;
}

static int put_at(const char *rel, const char *text) {
    char p[256];
    snprintf(p, sizeof p, "%s/%s", top, rel);
    return put(p, text);
}

static void show(const char *rel) {
    long n = slurp(at(rel), buf, sizeof buf);
    if (n < 0) {
        printf("%s: errno %ld\n", rel, -n);
    } else {
        printf("%s: %s", rel, buf);
    }
}

static int mk(const char *rel) {
    return mkdir(at(rel), 0755) == 0 ? 0 : errno;
}

/* The state letter /proc/<pid>/stat shows. */
static char state(pid_t pid) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/stat", pid);
    if (slurp(p, buf, sizeof buf) < 0) {
        return '?';
    }
    char *close_paren = 0;
    for (char *c = buf; *c; c++) {
        if (*c == ')') {
            close_paren = c;
        }
    }
    return close_paren ? close_paren[2] : '?';
}

/* The state of `pid` once it settles on being `want` (or after a while). */
static char settled(pid_t pid, char want) {
    char s = state(pid);
    for (int i = 0; i < 200 && (s == want) != 1; i++) {
        usleep(5000);
        s = state(pid);
    }
    return s;
}

static void limits(void) {
    printf("max.depth x: %d\n", put_at("cgroup.max.depth", "x"));
    put_at("cgroup.max.depth", "1");
    printf("mkdir depth 1: %d\n", mk("a"));
    printf("mkdir depth 2: %d\n", mk("a/b"));
    put_at("cgroup.max.depth", "max");
    put_at("cgroup.max.descendants", "1");
    printf("mkdir past descendants: %d\n", mk("c"));
    put_at("cgroup.max.descendants", "max");
    rmdir(at("a"));
    show("cgroup.type");
    printf("type threaded: %d, type junk: %d\n", put_at("cgroup.type", "threaded"),
           put_at("cgroup.type", "junk"));
}

static int stop_pipe[2];

static void *waiter(void *arg) {
    char c;
    read(stop_pipe[0], &c, 1);
    return arg;
}

static void pids(void) {
    mk("p");
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        put_at("p/cgroup.procs", "0");
        pipe(stop_pipe);
        pthread_t t;
        pthread_create(&t, 0, waiter, 0);
        slurp(at("p/cgroup.threads"), buf, sizeof buf);
        int lines = 0;
        for (char *c = buf; *c; c++) {
            lines += *c == '\n';
        }
        printf("cgroup.threads lists the threads: %d\n", lines);
        /* As many tasks as there are: no more. */
        slurp(at("p/pids.current"), buf, sizeof buf);
        char now[32];
        snprintf(now, sizeof now, "%ld", strtol(buf, 0, 10));
        put_at("p/pids.max", now);
        pthread_t t2;
        printf("thread past pids.max: %d\n", pthread_create(&t2, 0, waiter, 0));
        pid_t kid = fork();
        printf("fork past pids.max: %d\n", kid < 0 ? errno : 0);
        if (kid == 0) {
            _exit(0);
        }
        show("p/pids.events");
        put_at("p/pids.max", "max");
        printf("thread within pids.max: %d\n", pthread_create(&t2, 0, waiter, 0));
        write(stop_pipe[1], "xx", 2);
        pthread_join(t, 0);
        pthread_join(t2, 0);
        fflush(0);
        _exit(0);
    }
    reap(pid);
    rmdir(at("p"));
    /* RLIMIT_NPROC counts a user's threads too. */
    fflush(0);
    pid = fork();
    if (pid == 0) {
        setgid(1000);
        setuid(1000);
        unsigned long was[2], one[2];
        getrlimit(RLIMIT_NPROC, was);
        one[0] = 1;
        one[1] = was[1];
        setrlimit(RLIMIT_NPROC, one);
        pipe(stop_pipe);
        pthread_t t;
        printf("thread past RLIMIT_NPROC: %d\n", pthread_create(&t, 0, waiter, 0));
        setrlimit(RLIMIT_NPROC, was);
        printf("thread within RLIMIT_NPROC: %d\n", pthread_create(&t, 0, waiter, 0));
        write(stop_pipe[1], "x", 1);
        pthread_join(t, 0);
        fflush(0);
        _exit(0);
    }
    reap(pid);
}

struct clone_args {
    unsigned long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls,
        set_tid, set_tid_size, cgroup;
};

#define CLONE_INTO_CGROUP 0x200000000UL

static pid_t spin(void) {
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) {
            usleep(1000);
        }
    }
    return pid;
}

static void freeze(void) {
    mk("f");
    mk("f/k");
    pid_t a = spin();
    char num[32];
    snprintf(num, sizeof num, "%d", a);
    put_at("f/k/cgroup.procs", num);
    put_at("f/cgroup.freeze", "1");
    printf("member frozen: %c\n", settled(a, 'T'));
    show("f/k/cgroup.events");
    put_at("f/k/cgroup.freeze", "0");
    show("f/k/cgroup.events");
    printf("still frozen under a frozen parent: %c\n", settled(a, 'T'));
    pid_t b = spin();
    snprintf(num, sizeof num, "%d", b);
    put_at("f/k/cgroup.procs", num);
    printf("joined a frozen cgroup: %c\n", settled(b, 'T'));
    int dir = open(at("f/k"), O_RDONLY | O_DIRECTORY);
    struct clone_args args;
    memset(&args, 0, sizeof args);
    args.flags = CLONE_INTO_CGROUP;
    args.exit_signal = 17;
    args.cgroup = dir;
    fflush(0);
    pid_t c = syscall(435, &args, sizeof args);
    if (c == 0) {
        for (;;) {
            usleep(1000);
        }
    }
    printf("forked into a frozen cgroup: %c\n", settled(c, 'T'));
    put_at("f/cgroup.freeze", "0");
    char s = settled(a, 'S');
    printf("thawed: %d\n", s == 'S' || s == 'R');
    put_at("f/cgroup.kill", "1");
    reap(a);
    reap(b);
    reap(c);
    rmdir(at("f/k"));
    rmdir(at("f"));
}

static void delegation(void) {
    mk("d1");
    mk("d2");
    int go[2], done[2];
    pipe(go);
    pipe(done);
    chown(at("d2/cgroup.procs"), 1000, 1000);
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        put_at("d1/cgroup.procs", "0");
        setgid(1000);
        setuid(1000);
        printf("unprivileged, common ancestor not writable: %d\n", -put_at("d2/cgroup.procs", "0"));
        fflush(0);
        write(done[1], "x", 1);
        char c;
        read(go[0], &c, 1);
        printf("common ancestor writable: %d\n", -put_at("d2/cgroup.procs", "0"));
        fflush(0);
        _exit(0);
    }
    char c;
    read(done[0], &c, 1);
    chown(at("cgroup.procs"), 1000, 1000);
    fflush(0);
    write(go[1], "x", 1);
    reap(pid);
    chown(at("cgroup.procs"), 0, 0);
    pid = fork();
    if (pid == 0) {
        put_at("d1/cgroup.procs", "0");
        unshare(CLONE_NEWCGROUP);
        printf("out of the cgroup namespace: %d\n", -put_at("d2/cgroup.procs", "0"));
        fflush(0);
        _exit(0);
    }
    reap(pid);
    rmdir(at("d1"));
    rmdir(at("d2"));
}

/* A cgroup's directory is kernfs's: no file is made or removed but by the
 * kernel, no cgroup renamed, a file opened to cut is not cut, and the
 * filesystem is cgroup2's. */
static void kernfs(void) {
    int fd = open(at("made"), O_WRONLY | O_CREAT, 0644);
    printf("file made: %d\n", fd < 0 ? errno : 0);
    printf("file removed: %d\n", unlink(at("cgroup.max.depth")) == 0 ? 0 : errno);
    mk("r");
    char to[256];
    snprintf(to, sizeof to, "%s/s", top);
    printf("cgroup renamed: %d\n", syscall(38, -100, at("r"), -100, to, 0) == 0 ? 0 : errno);
    rmdir(at("r"));
    put_at("cgroup.max.depth", "7");
    fd = open(at("cgroup.max.depth"), O_WRONLY | O_TRUNC);
    close(fd);
    show("cgroup.max.depth");
    put_at("cgroup.max.depth", "max");
    long st[15] = {0};
    syscall(43, "/sys/fs/cgroup", st);
    printf("filesystem: %lx\n", st[0]);
}

int main(void) {
    snprintf(top, sizeof top, "/sys/fs/cgroup/fwe-cgroups-%d", getpid());
    put("/sys/fs/cgroup/cgroup.subtree_control", "+pids");
    mkdir(top, 0755);
    put_at("cgroup.subtree_control", "+pids");
    limits();
    kernfs();
    pids();
    freeze();
    delegation();
    mkdir("/tmp/v1", 0755);
    long r = syscall(40, "none", "/tmp/v1", "cgroup", 0, "cpu");
    printf("cgroup v1 mount: %d\n", r == 0 ? 0 : errno);
    rmdir(top);
    fflush(0);
    return 0;
}
