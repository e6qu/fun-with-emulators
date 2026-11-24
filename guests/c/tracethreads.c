/* A tracer of another process's thread finds that thread's stops as
 * Linux reports them: by a wait for its process group (`waitpid(0)`,
 * `waitid(P_PGID)`, with the thread's user as the sender), by its thread
 * id inside a pid namespace, and in two pid namespaces at once, whose
 * threads have the same numbers, each tracer its own thread's.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;
typedef long ssize_t;
typedef unsigned long size_t;

long ptrace(int request, ...);
long syscall(long n, ...);
int unshare(int flags);
int fork(void);
int getpgrp(void);
unsigned getuid(void);
int kill(int pid, int sig);
int pause(void);
int pipe(int fds[2]);
int close(int fd);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int usleep(unsigned us);
int waitpid(int pid, int *status, int options);
int waitid(int idtype, unsigned id, void *info, int options);
int pthread_create(pthread_t *t, const void *attr, void *(*f)(void *), void *arg);
int printf(const char *format, ...);
void _exit(int status);

#define SYS_gettid 178
#define PTRACE_CONT 7
#define PTRACE_DETACH 17
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define SIGKILL 9
#define WNOHANG 1
#define WEXITED 4
#define __WALL 0x40000000
#define P_PGID 2
#define CLONE_NEWPID 0x20000000

/* How a case ended, as its exit code. */
enum { OK, NO_TRACEE, NO_SEIZE, NOT_FOUND, WRONG_USER, NO_CHILD, NOT_FOUND_BY_WAITID };

static int tid_pipe[2];

static void *thread(void *arg) {
    (void)arg;
    int tid = (int)syscall(SYS_gettid);
    write(tid_pipe[1], &tid, sizeof tid);
    for (;;)
        pause();
}

/* A child whose second thread is the tracee: its tid, or -1. */
static int tracee(int *child) {
    if (pipe(tid_pipe) != 0)
        return -1;
    *child = fork();
    if (*child < 0)
        return -1;
    if (*child == 0) {
        pthread_t t;
        pthread_create(&t, 0, thread, 0);
        for (;;)
            pause();
    }
    int tid = -1;
    if (read(tid_pipe[0], &tid, sizeof tid) != sizeof tid)
        return -1;
    return tid;
}

/* Wait (`pid` as waitpid takes it) for tracee `tid`'s stop, for up to
 * three seconds: whether it was found. */
static int stop_found(int pid, int tid) {
    for (int i = 0; i < 300; i++) {
        int status = 0;
        int r = waitpid(pid, &status, __WALL | WNOHANG);
        if (r == tid && (status & 0xff) == 0x7f)
            return 1;
        if (r != 0)
            return 0;
        usleep(10000);
    }
    return 0;
}

/* `waitid(P_PGID)` for tracee `tid`'s stop: OK, or how it failed. */
static int stop_found_by_group(int tid) {
    for (int i = 0; i < 300; i++) {
        int info[32] = {0};
        if (waitid(P_PGID, (unsigned)getpgrp(), info, WEXITED | __WALL | WNOHANG) != 0)
            return NOT_FOUND_BY_WAITID;
        if (info[4] == tid)
            return (unsigned)info[5] == getuid() ? OK : WRONG_USER;
        usleep(10000);
    }
    return NOT_FOUND_BY_WAITID;
}

static void end(int child) {
    kill(child, SIGKILL);
    int status;
    waitpid(child, &status, 0);
}

/* The tracer waits for its process group. */
static int by_group(void) {
    int child;
    int tid = tracee(&child);
    if (tid < 0)
        return NO_TRACEE;
    int r = OK;
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0)
        r = NO_SEIZE;
    else if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0 || !stop_found(0, tid))
        r = NOT_FOUND;
    else if (ptrace(PTRACE_CONT, tid, 0, 0) != 0 || ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0)
        r = NOT_FOUND;
    else
        r = stop_found_by_group(tid);
    end(child);
    return r;
}

/* In a pid namespace of its own, the tracer waits for the thread by its
 * id; `go` (if not -1) is read once the thread is seized, so another
 * namespace's tracer holds its own at the same time. */
static int by_tid(int ready, int go) {
    int child;
    int tid = tracee(&child);
    if (tid < 0)
        return NO_TRACEE;
    int r = OK;
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0)
        r = NO_SEIZE;
    if (ready >= 0) {
        /* Its number (the other namespace's thread has the same). */
        write(ready, &tid, sizeof tid);
        char c;
        read(go, &c, 1);
    }
    if (r == OK && (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0 || !stop_found(tid, tid)))
        r = NOT_FOUND;
    if (r == OK)
        ptrace(PTRACE_DETACH, tid, 0, 0);
    end(child);
    return r;
}

/* A process in a new pid namespace whose init runs `by_tid`: its exit
 * code. */
static int in_namespace(int ready, int go) {
    if (unshare(CLONE_NEWPID) != 0)
        return NO_CHILD;
    int init = fork();
    if (init < 0)
        return NO_CHILD;
    if (init == 0)
        _exit(by_tid(ready, go));
    int status = 0;
    if (waitpid(init, &status, 0) != init)
        return NO_CHILD;
    return (status >> 8) & 0xff;
}

static int code_of(int pid) {
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return NO_CHILD;
    return (status >> 8) & 0xff;
}

int main(void) {
    printf("by id: %d\n", by_tid(-1, -1));
    printf("by group: %d\n", by_group());
    int one = fork();
    if (one == 0)
        _exit(in_namespace(-1, -1));
    printf("in a namespace: %d\n", code_of(one));
    /* Two namespaces whose tracers hold their threads at once. */
    int ready[2], go[2];
    if (pipe(ready) != 0 || pipe(go) != 0)
        return 1;
    int a = fork();
    if (a == 0)
        _exit(in_namespace(ready[1], go[0]));
    int b = fork();
    if (b == 0)
        _exit(in_namespace(ready[1], go[0]));
    close(ready[1]);
    close(go[0]);
    int tids[2] = {0, 0};
    read(ready[0], &tids[0], sizeof tids[0]);
    read(ready[0], &tids[1], sizeof tids[1]);
    write(go[1], "gg", 2);
    int ca = code_of(a), cb = code_of(b);
    printf("side by side: %d %d, same thread numbers: %d\n", ca, cb, tids[0] == tids[1]);
    return 0;
}
