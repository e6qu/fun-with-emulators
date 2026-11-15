/* The system calls of Linux 6.x a program may reach for: the *xattrat
 * calls, the futex2 calls, kcmp, process_madvise, clone3 with set_tid,
 * PR_SET_VMA anonymous names; and the calls of features fwe's kernel is
 * built without (modules, io_uring, perf events, fanotify, userfaultfd),
 * which fail with ENOSYS. Runs as root.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

int dup(int fd);
long sysconf(int name);

#define AT_FDCWD (-100)
#define AT_EMPTY_PATH 0x1000
#define FUTEX2_SIZE_U32 2
#define FUTEX2_PRIVATE 128
#define CLOCK_MONOTONIC 1
#define KCMP_FILE 0
#define KCMP_VM 1
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define PR_SET_VMA 0x53564d41
#define PROT_RW 3
#define MAP_PRIVATE_ANON 0x22

struct xattr_args {
    unsigned long value;
    unsigned size, flags;
};

struct futex_waitv {
    unsigned long val, uaddr;
    unsigned flags, reserved;
};

struct clone_args {
    unsigned long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls,
        set_tid, set_tid_size, cgroup;
};

static char buf[65536];

static long rc(long r) {
    return r < 0 ? -errno : r;
}

static void xattrs(void) {
    mkdir("/tmp/x", 0755);
    close(open("/tmp/x/f", O_CREAT | O_WRONLY, 0644));
    int dir = open("/tmp/x", O_RDONLY | O_DIRECTORY);
    struct xattr_args set = {(unsigned long)"value", 5, 0};
    printf("setxattrat: %ld\n", rc(syscall(463, dir, "f", 0, "user.fwe", &set, sizeof set)));
    char got[16] = {0};
    struct xattr_args get = {(unsigned long)got, sizeof got, 0};
    printf("getxattrat: %ld %s\n", rc(syscall(464, dir, "f", 0, "user.fwe", &get, sizeof get)),
           got);
    struct xattr_args bad = {(unsigned long)got, sizeof got, 1};
    printf("getxattrat with flags: %ld\n",
           rc(syscall(464, dir, "f", 0, "user.fwe", &bad, sizeof bad)));
    printf("small args: %ld\n", rc(syscall(464, dir, "f", 0, "user.fwe", &get, 8)));
    long n = syscall(465, dir, "f", 0, buf, sizeof buf);
    printf("listxattrat has it: %d\n", n > 0 && memcmp(buf, "user.fwe", 9) == 0);
    int f = open("/tmp/x/f", O_RDONLY);
    memset(got, 0, sizeof got);
    printf("getxattrat of the descriptor: %ld %s\n",
           rc(syscall(464, f, "", AT_EMPTY_PATH, "user.fwe", &get, sizeof get)), got);
    printf("removexattrat: %ld, again: %ld\n", rc(syscall(466, dir, "f", 0, "user.fwe")),
           rc(syscall(466, dir, "f", 0, "user.fwe")));
    printf("unknown at flags: %ld\n", rc(syscall(466, dir, "f", 1, "user.fwe")));
    unlink("/tmp/x/f");
    rmdir("/tmp/x");
}

static unsigned word, other;

static void *waker(void *arg) {
    usleep(20000);
    __atomic_store_n(&word, 1, __ATOMIC_SEQ_CST);
    syscall(454, &word, 0xff, 1, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
    return arg;
}

static void futex2(void) {
    pthread_t t;
    pthread_create(&t, 0, waker, 0);
    long r = syscall(455, &word, 0, 0xff, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, CLOCK_MONOTONIC);
    pthread_join(t, 0);
    printf("futex_wait woken: %ld, word %u\n", rc(r), word);
    printf("futex_wait on a changed word: %ld\n",
           rc(syscall(455, &word, 0, 0xff, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0, CLOCK_MONOTONIC)));
    printf("64-bit futex: %ld\n", rc(syscall(454, &word, 0xff, 1, 3)));
    printf("futex_wake with none waiting: %ld\n",
           rc(syscall(454, &word, 0xff, 1, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE)));
    struct futex_waitv w[2] = {{1, (unsigned long)&word, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0},
                               {0, (unsigned long)&other, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, 0}};
    printf("futex_requeue: %ld\n", rc(syscall(456, w, 0, 1, 1)));
    w[0].val = 5;
    printf("futex_requeue on a changed word: %ld\n", rc(syscall(456, w, 0, 1, 1)));
}

static void compare(void) {
    pid_t me = getpid();
    int a = open("/proc/self/status", O_RDONLY);
    int b = dup(a);
    int c = open("/proc/self/status", O_RDONLY);
    int p[2];
    pipe(p);
    int q = dup(p[0]);
    printf("kcmp dup: %ld, pipe dup: %ld, two pipe ends differ: %d\n",
           rc(syscall(272, me, me, KCMP_FILE, a, b)), rc(syscall(272, me, me, KCMP_FILE, p[0], q)),
           syscall(272, me, me, KCMP_FILE, p[0], p[1]) > 0);
    mkdir("/tmp/k", 0755);
    int f1 = open("/tmp/k/f", O_CREAT | O_RDWR, 0644);
    int f2 = open("/tmp/k/f", O_RDWR);
    int f3 = dup(f1);
    printf("same file opened twice: %d, duplicated: %ld\n",
           syscall(272, me, me, KCMP_FILE, f1, f2) > 0, rc(syscall(272, me, me, KCMP_FILE, f1, f3)));
    printf("bad descriptor: %ld, bad type: %ld\n", rc(syscall(272, me, me, KCMP_FILE, a, 999)),
           rc(syscall(272, me, me, 99, 0, 0)));
    fflush(0);
    pid_t kid = fork();
    if (kid == 0) {
        char ch;
        read(p[0], &ch, 1);
        _exit(0);
    }
    long vm = syscall(272, me, kid, KCMP_VM, 0, 0);
    printf("own memory: %ld, a child's: %d, inherited pipe: %ld\n",
           rc(syscall(272, me, me, KCMP_VM, 0, 0)), vm == 1 || vm == 2,
           rc(syscall(272, me, kid, KCMP_FILE, p[1], p[1])));
    write(p[1], "x", 1);
    reap(kid);
    (void)c;
    unlink("/tmp/k/f");
    rmdir("/tmp/k");
}

static void advise(void) {
    long page = sysconf(30);
    char *m = mmap(0, 16 * page, PROT_RW, MAP_PRIVATE_ANON, -1, 0);
    int pidfd = syscall(434, getpid(), 0);
    struct {
        void *base;
        size_t len;
    } iov[2] = {{m, 4 * page}, {m + 8 * page, 2 * page}};
    printf("process_madvise: %ld\n", rc(syscall(440, pidfd, iov, 2, MADV_WILLNEED, 0)));
    printf("destructive advice: %ld, flags: %ld, not a pidfd: %ld\n",
           rc(syscall(440, pidfd, iov, 2, MADV_DONTNEED, 0)),
           rc(syscall(440, pidfd, iov, 2, MADV_WILLNEED, 1)),
           rc(syscall(440, 0, iov, 2, MADV_WILLNEED, 0)));
    printf("PR_SET_VMA: %d\n", prctl(PR_SET_VMA, 0, m + 4 * page, 4 * page, "fwe-buffer"));
    printf("bad name: %d\n", prctl(PR_SET_VMA, 0, m, page, "a$b") == 0 ? 0 : errno);
    slurp("/proc/self/maps", buf, sizeof buf);
    printf("maps names it: %d\n", strstr(buf, " [anon:fwe-buffer]\n") != 0);
}

static void set_tid(void) {
    fflush(0);
    pid_t outer = fork();
    if (outer != 0) {
        reap(outer);
        return;
    }
    struct clone_args args;
    memset(&args, 0, sizeof args);
    int tids[2] = {1, 0};
    args.exit_signal = 17;
    args.set_tid = (unsigned long)tids;
    args.set_tid_size = 1;
    printf("set_tid in the host's namespace: %ld\n", rc(syscall(435, &args, sizeof args)));
    unshare(CLONE_NEWPID);
    tids[0] = 7;
    printf("set_tid other than 1 with no init: %ld\n", rc(syscall(435, &args, sizeof args)));
    tids[0] = 1;
    fflush(0);
    long init = syscall(435, &args, sizeof args);
    if (init == 0) {
        tids[0] = 42;
        int go[2];
        pipe(go);
        fflush(0);
        long kid = syscall(435, &args, sizeof args);
        if (kid == 0) {
            printf("chosen pid: %d\n", getpid());
            fflush(0);
            char c;
            read(go[0], &c, 1);
            _exit(0);
        }
        printf("taken: %ld, too many: ", rc(syscall(435, &args, sizeof args)));
        args.set_tid_size = 3;
        printf("%ld\n", rc(syscall(435, &args, sizeof args)));
        write(go[1], "x", 1);
        reap(kid);
        fflush(0);
        _exit(0);
    }
    reap(init);
    printf("init made: %d\n", init > 0);
    fflush(0);
    _exit(0);
}

int main(void) {
    xattrs();
    futex2();
    compare();
    advise();
    set_tid();
    printf("modules: %ld %ld %ld\n", rc(syscall(105, 0, 0, "")), rc(syscall(273, -1, "", 0)),
           rc(syscall(106, "x", 0)));
    printf("io_uring %ld, perf %ld, fanotify %ld, userfaultfd %ld\n", rc(syscall(425, 1, buf)),
           rc(syscall(241, buf, 0, -1, -1, 0)), rc(syscall(262, 0, 0)), rc(syscall(282, 0)));
    fflush(0);
    return 0;
}
