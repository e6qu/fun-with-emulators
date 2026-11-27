/* A tracer that ends without detaching, as Linux leaves its tracee:
 * one attached (its SIGSTOP's stop) and one continued after it, each
 * then waited for by its parent, which reports how it stands: stopped,
 * running, or ended.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef long ssize_t;
typedef unsigned long size_t;

long ptrace(int request, ...);
int fork(void);
int getppid(void);
int kill(int pid, int sig);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int usleep(unsigned us);
unsigned alarm(unsigned s);
int waitpid(int pid, int *status, int options);
int printf(const char *format, ...);
int fflush(void *f);
void _exit(int status);

#define PTRACE_CONT 7
#define PTRACE_ATTACH 16
#define WNOHANG 1
#define WUNTRACED 2
#define WALL 0x40000000

/* A target that counts, a tracer that attaches to it and ends (having
 * continued it first if `cont`), and how the target stands after. */
static void run(const char *name, int cont) {
    int ready[2];
    pipe(ready);
    int target = fork();
    if (target == 0) {
        write(ready[1], "r", 1);
        for (;;) usleep(1000);
    }
    char c;
    read(ready[0], &c, 1);
    int tracer = fork();
    if (tracer == 0) {
        int status = 0;
        if (ptrace(PTRACE_ATTACH, target, 0, 0) != 0) _exit(2);
        waitpid(target, &status, WALL);
        if (cont) ptrace(PTRACE_CONT, target, 0, 0);
        _exit(0);
    }
    int status = 0;
    waitpid(tracer, &status, 0);
    usleep(200000);
    int r = waitpid(target, &status, WNOHANG | WUNTRACED);
    if (r == 0) printf("%s: running\n", name);
    else if (r == target && (status & 0xff) == 0x7f)
        printf("%s: stopped by %d\n", name, (status >> 8) & 0xff);
    else printf("%s: status %#x\n", name, status);
    kill(target, 9);
    waitpid(target, &status, 0);
}

int main(void) {
    alarm(20);
    run("left at the attach's stop", 0);
    run("continued, then left", 1);
    fflush(0);
    return 0;
}
