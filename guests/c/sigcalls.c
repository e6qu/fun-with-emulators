/* Calls Linux always has and the signals and limits around processes:
 * FUTEX_WAKE_OP, restart_syscall, process_mrelease; kill and
 * rt_sigqueueinfo of another process's thread id (its process), and
 * rt_tgsigqueueinfo to another process's other thread; a uid_map checked
 * against the parent namespace's; RLIMIT_NPROC at the execve after a
 * setuid; timerfd's alarm clocks needing CAP_WAKE_ALARM. Runs as root.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

int execve(const char *path, char *const argv[], char *const envp[]);
int setrlimit(int resource, const void *limit);
int sigaction(int sig, const void *act, void *old);
int pause(void);

#define SYS_futex 98
#define SYS_restart_syscall 128
#define SYS_tgkill 131
#define SYS_rt_sigqueueinfo 138
#define SYS_rt_tgsigqueueinfo 240
#define SYS_timerfd_create 85
#define SYS_pidfd_open 434
#define SYS_process_mrelease 448
#define FUTEX_WAIT 0
#define FUTEX_WAKE_OP 5
#define FUTEX_PRIVATE 128
#define FUTEX_OP(op, oparg, cmp, cmparg) \
    (((op) << 28) | ((cmp) << 24) | (((oparg) & 0xfff) << 12) | ((cmparg) & 0xfff))
#define FUTEX_OP_SET 0
#define FUTEX_OP_ADD 1
#define FUTEX_OP_CMP_EQ 0
#define PROT_RW 3
#define MAP_SHARED_ANON 0x21
#define SIGUSR1 10
#define SIGUSR2 12
#define SA_SIGINFO 4
#define SI_QUEUE (-1)
#define RLIMIT_NPROC 6
#define CLOCK_REALTIME_ALARM 8
#define CLOCK_BOOTTIME_ALARM 9

/* glibc's struct sigaction on arm64. */
struct sigact {
    void *handler;
    unsigned long mask[16];
    int flags;
    void *restorer;
};

struct siginfo {
    int signo, err, code, pad;
    int pid;
    unsigned uid;
    unsigned long value;
    char rest[96];
};

static long rc(long r) {
    return r < 0 ? -errno : r;
}

/* FUTEX_WAKE_OP: the second word changed, its waiter woken when its old
 * value meets the comparison; for a process's own futexes and for shared
 * ones between processes. */
static unsigned *word, *word2;
static int private_flag;

static void *wait_on_second(void *arg) {
    (void)arg;
    syscall(SYS_futex, word2, FUTEX_WAIT | private_flag, 0, 0, 0, 0);
    return 0;
}

static long wake_op_until_woken(void) {
    long woken = 0;
    for (int i = 0; i < 200 && woken == 0; i++) {
        usleep(10000);
        /* Set to 0 if it was 0 (the waiter still waits on 0); woken if so. */
        woken = rc(syscall(SYS_futex, word, FUTEX_WAKE_OP | private_flag, 1, 1, word2,
                           FUTEX_OP(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, 0)));
    }
    return woken;
}

static void wake_op(void) {
    unsigned *words = mmap(0, 4096, PROT_RW, MAP_SHARED_ANON, -1, 0);
    word = words;
    word2 = words + 1;
    private_flag = FUTEX_PRIVATE;
    *word2 = 0;
    pthread_t t;
    pthread_create(&t, 0, wait_on_second, 0);
    long woken = wake_op_until_woken();
    pthread_join(t, 0);
    printf("wake_op woken: %ld\n", woken);
    /* Not met: changed, none woken. */
    *word2 = 5;
    long r = rc(syscall(SYS_futex, word, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 1, word2,
                        FUTEX_OP(FUTEX_OP_ADD, 2, FUTEX_OP_CMP_EQ, 0)));
    printf("wake_op not met: %ld, word %u\n", r, *word2);
    r = rc(syscall(SYS_futex, word, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 1, word2, 7u << 28));
    printf("unknown operation: %ld, unaligned: %ld\n", r,
           rc(syscall(SYS_futex, word, FUTEX_WAKE_OP | FUTEX_PRIVATE, 1, 1,
                      (char *)word2 + 1, 0)));
    /* Shared, between processes. */
    private_flag = 0;
    *word2 = 0;
    pid_t child = fork();
    if (child == 0) {
        syscall(SYS_futex, word2, FUTEX_WAIT, 0, 0, 0, 0);
        _exit(*word2 == 0 ? 0 : 1);
    }
    woken = wake_op_until_woken();
    printf("shared wake_op woken: %ld, child %d\n", woken, reap(child));
}

static void restart(void) {
    printf("restart_syscall: %ld\n", rc(syscall(SYS_restart_syscall)));
}

/* process_mrelease: only of a process on its way out. */
static void mrelease(void) {
    pid_t child = fork();
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    int fd = syscall(SYS_pidfd_open, child, 0);
    long alive = rc(syscall(SYS_process_mrelease, fd, 0));
    long flags = rc(syscall(SYS_process_mrelease, fd, 1));
    long notpidfd = rc(syscall(SYS_process_mrelease, 1, 0));
    kill(child, SIGKILL);
    long killed = rc(syscall(SYS_process_mrelease, fd, 0));
    reap(child);
    long reaped = rc(syscall(SYS_process_mrelease, fd, 0));
    printf("process_mrelease alive: %ld, flags: %ld, not a pidfd: %ld\n", alive, flags,
           notpidfd);
    printf("killed: %ld, reaped: %ld\n", killed, reaped);
}

/* Another process's thread: kill and rt_sigqueueinfo of its id reach its
 * process; rt_tgsigqueueinfo reaches the thread itself. */
static int report[2];
static int thread_tid;

static void on_signal(int sig, struct siginfo *info, void *ctx) {
    (void)ctx;
    char line[64];
    int n = snprintf(line, sizeof line, "%d %d %d %lu\n", sig, gettid() == thread_tid,
                     info->code, info->code == SI_QUEUE ? info->value : 0);
    write(report[1], line, n);
}

static void *other_thread(void *arg) {
    int *ready = arg;
    /* It takes the signals the main thread blocks, from before it says it
     * is ready. */
    unsigned long unblock[16] = {(1ul << (SIGUSR1 - 1)) | (1ul << (SIGUSR2 - 1))};
    syscall(135, 1 /* SIG_UNBLOCK */, unblock, 0, 8);
    thread_tid = gettid();
    write(ready[1], &thread_tid, sizeof thread_tid);
    for (;;) {
        pause();
    }
    return 0;
}

static void read_line(char *buf, size_t n) {
    size_t at = 0;
    while (at + 1 < n && read(report[0], buf + at, 1) == 1 && buf[at] != '\n') {
        at++;
    }
    buf[at] = 0;
}

static void other_threads(void) {
    int ready[2];
    pipe(ready);
    pipe(report);
    pid_t child = fork();
    if (child == 0) {
        struct sigact sa = {0};
        sa.handler = (void *)on_signal;
        sa.flags = SA_SIGINFO;
        sigaction(SIGUSR1, &sa, 0);
        sigaction(SIGUSR2, &sa, 0);
        /* The main thread blocks them, before the other thread is made:
         * the other thread takes them, whichever thread a process signal
         * lands on. */
        unsigned long block[16] = {(1ul << (SIGUSR1 - 1)) | (1ul << (SIGUSR2 - 1))};
        syscall(135, 0 /* SIG_BLOCK */, block, 0, 8);
        pthread_t t;
        pthread_create(&t, 0, other_thread, ready);
        for (;;) {
            usleep(1000);
        }
    }
    int tid = 0;
    read(ready[0], &tid, sizeof tid);
    char line[64];
    printf("kill of the thread's id: %ld\n", rc(kill(tid, SIGUSR1)));
    read_line(line, sizeof line);
    printf("  taken: %s\n", line);
    struct siginfo info = {0};
    info.signo = SIGUSR2;
    info.code = SI_QUEUE;
    info.pid = getpid();
    info.value = 42;
    printf("rt_sigqueueinfo of the thread's id: %ld\n",
           rc(syscall(SYS_rt_sigqueueinfo, tid, SIGUSR2, &info)));
    read_line(line, sizeof line);
    printf("  taken: %s\n", line);
    info.value = 43;
    printf("rt_tgsigqueueinfo to the thread: %ld\n",
           rc(syscall(SYS_rt_tgsigqueueinfo, child, tid, SIGUSR2, &info)));
    read_line(line, sizeof line);
    printf("  taken: %s\n", line);
    printf("to a thread not the process's: %ld\n",
           rc(syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, SIGUSR2, &info)));
    info.code = 0;
    printf("as the kernel: %ld\n", rc(syscall(SYS_rt_tgsigqueueinfo, child, tid, SIGUSR2, &info)));
    kill(child, SIGKILL);
    reap(child);
}

/* A uid_map names only ids the parent namespace has, even written by a
 * process privileged over it. */
static void uid_maps(void) {
    int go[2], done[2];
    pipe(go);
    pipe(done);
    pid_t child = fork();
    if (child == 0) {
        unshare(CLONE_NEWUSER);
        write(done[1], "u", 1);
        char c;
        read(go[0], &c, 1);
        /* Root inside, mapped to the parent's root alone; a namespace
         * inside this one can name only that id. */
        int inner[2], back[2];
        pipe(inner);
        pipe(back);
        pid_t grandchild = fork();
        if (grandchild == 0) {
            unshare(CLONE_NEWUSER);
            write(back[1], "u", 1);
            read(inner[0], &c, 1);
            _exit(0);
        }
        read(back[0], &c, 1);
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/uid_map", grandchild);
        int unmapped = put(path, "0 1 1\n");
        int across = put(path, "0 0 2\n");
        int mapped = put(path, "0 0 1\n");
        write(inner[1], "x", 1);
        reap(grandchild);
        printf("uid_map of an id the parent lacks: %d, past its extent: %d, its own: %d\n",
               unmapped, across, mapped);
        fflush(0);
        _exit(0);
    }
    char c;
    read(done[0], &c, 1);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/uid_map", child);
    int top = put(path, "0 0 1\n");
    printf("uid_map inside the initial namespace: %d\n", top);
    fflush(0);
    write(go[1], "x", 1);
    reap(child);
}

/* RLIMIT_NPROC: a setuid to a user past it fails the next execve
 * (EAGAIN) while the user still has too many tasks. */
#define USER 54321

static void nproc(void) {
    /* Another process of the user's. */
    int ready[2];
    pipe(ready);
    pid_t other = fork();
    if (other == 0) {
        setuid(USER);
        write(ready[1], "r", 1);
        for (;;) {
            pause();
        }
    }
    char c;
    read(ready[0], &c, 1);
    for (int alone = 0; alone < 2; alone++) {
        if (alone) {
            kill(other, SIGKILL);
            reap(other);
        }
        pid_t child = fork();
        if (child == 0) {
            unsigned long limit[2] = {0, 0};
            setrlimit(RLIMIT_NPROC, limit);
            long set = rc(setuid(USER));
            /* No such program: past the limit the execve fails before it
             * looks (EAGAIN), else it looks (ENOENT). */
            char *argv[] = {"none", 0};
            char *envp[] = {0};
            long r = rc(execve("/no/such/program", argv, envp));
            printf("%s: setuid: %ld, execve: %ld\n", alone ? "alone" : "with another", set, r);
            fflush(0);
            _exit(0);
        }
        reap(child);
        fflush(0);
    }
}

static void alarms(void) {
    long root = rc(syscall(SYS_timerfd_create, CLOCK_REALTIME_ALARM, 0));
    printf("alarm timerfd as root: %d\n", root >= 0);
    fflush(0);
    pid_t child = fork();
    if (child == 0) {
        setuid(1000);
        printf("as a user: %ld %ld, bad flags: %ld\n",
               rc(syscall(SYS_timerfd_create, CLOCK_REALTIME_ALARM, 0)),
               rc(syscall(SYS_timerfd_create, CLOCK_BOOTTIME_ALARM, 0)),
               rc(syscall(SYS_timerfd_create, CLOCK_BOOTTIME_ALARM, 1)));
        fflush(0);
        _exit(0);
    }
    reap(child);
}

int main(void) {
    wake_op();
    restart();
    mrelease();
    fflush(0);
    other_threads();
    fflush(0);
    uid_maps();
    nproc();
    alarms();
    fflush(0);
    return 0;
}
