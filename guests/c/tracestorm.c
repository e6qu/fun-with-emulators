/* Tracers side by side, as ptrace05 run beside other tests: each forks
 * a child that asks to be traced and sends itself a signal, and a child
 * that stops for it is continued. Every continue finds its tracee
 * stopped: one tracer's requests never reach another's tracee, however
 * the shared pages their mailboxes are kept in are freed and made again.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef long ssize_t;
typedef unsigned long size_t;

long ptrace(int request, ...);
int fork(void);
int getpid(void);
int kill(int pid, int sig);
void _exit(int status);
int waitpid(int pid, int *status, int options);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int printf(const char *format, ...);

#define PTRACE_TRACEME 0
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define SIGKILL 9
#define WORKERS 16
#define ROUNDS 40

/* One worker's rounds: the continues that failed, or -1. */
static int worker(void) {
    int failed = 0;
    for (int round = 0; round < ROUNDS; round++)
        for (int sig = 1; sig <= 64; sig++) {
            /* SIGKILL ends it, SIGCHLD and SIGCONT among them; the C
             * library's own real-time signals are left alone. */
            if (sig == SIGKILL || (sig >= 32 && sig < 35))
                continue;
            int pid = fork();
            if (pid < 0)
                return -1;
            if (pid == 0) {
                ptrace(PTRACE_TRACEME, 0, 0, 0);
                kill(getpid(), sig);
                _exit(0);
            }
            int status;
            waitpid(pid, &status, 0);
            if ((status & 0xff) != 0x7f) {
                failed++;
                continue;
            }
            if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) {
                failed++;
                ptrace(PTRACE_KILL, pid, 0, 0);
            }
            waitpid(pid, &status, 0);
        }
    return failed;
}

int main(void) {
    int fds[2];
    if (pipe(fds) != 0)
        return 2;
    int pids[WORKERS];
    for (int w = 0; w < WORKERS; w++) {
        pids[w] = fork();
        if (pids[w] < 0)
            return 2;
        if (pids[w] == 0) {
            int failed = worker();
            write(fds[1], &failed, sizeof failed);
            _exit(0);
        }
    }
    int total = 0, broken = 0;
    for (int w = 0; w < WORKERS; w++) {
        int failed;
        if (read(fds[0], &failed, sizeof failed) != sizeof failed || failed < 0)
            broken++;
        else
            total += failed;
        waitpid(pids[w], 0, 0);
    }
    printf("workers broken: %d, tracees not stopped or continued: %d\n", broken, total);
    return 0;
}
