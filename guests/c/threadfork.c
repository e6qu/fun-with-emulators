/* A program with a second thread forks, and its child execs the program
 * its arguments name: Chromium starts its GPU process so, and that program
 * then finds the Mac's GPU through fwe's driver. The parent prints how the
 * child ended. */
typedef unsigned long pthread_t;
int pthread_create(pthread_t *t, const void *attr, void *(*f)(void *), void *arg);
int fork(void);
int execv(const char *path, char *const argv[]);
int waitpid(int pid, int *status, int options);
int printf(const char *fmt, ...);
int usleep(unsigned us);
void _exit(int status);

static void *idle(void *arg) {
    (void)arg;
    for (;;) usleep(100000);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    pthread_t t;
    pthread_create(&t, 0, idle, 0);
    int pid = fork();
    if (pid == 0) {
        execv(argv[1], argv + 1);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("child: %s %d\n", (status & 0x7f) ? "signal" : "exit",
           (status & 0x7f) ? status & 0x7f : (status >> 8) & 0xff);
    return 0;
}
