/* A process in a pid namespace of its own keeps its pid there across an
 * execve made while other threads run (which fwe makes by running a fresh
 * fwe in the process, from the exec state it records).
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;

int unshare(int flags);
int fork(void);
int getpid(void);
int execl(const char *path, const char *arg, ...);
int waitpid(int pid, int *status, int options);
int pause(void);
int pthread_create(pthread_t *t, const void *attr, void *(*f)(void *), void *arg);
int printf(const char *format, ...);
int fflush(void *stream);
void _exit(int status);

#define CLONE_NEWPID 0x20000000

static void *waits(void *arg) {
    (void)arg;
    for (;;) {
        pause();
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        printf("after execve: pid %d\n", getpid());
        return 0;
    }
    if (unshare(CLONE_NEWPID) != 0) {
        printf("unshare failed\n");
        return 1;
    }
    int pid = fork();
    if (pid == 0) {
        pthread_t t;
        pthread_create(&t, 0, waits, 0);
        printf("before execve: pid %d\n", getpid());
        fflush(0);
        execl("/proc/self/exe", argv[0], "again", (char *)0);
        _exit(1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status == 0 ? 0 : 1;
}
