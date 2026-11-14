/* A signal sent to a child the moment it exists ends it as Linux reports:
 * the signals fwe leaves deliverable across the host's fork (SIGBUS,
 * SIGSEGV, SIGSYS) too, which reach the child before it is set up.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

int fork(void);
int kill(int pid, int sig);
int pause(void);
int waitpid(int pid, int *status, int options);
int printf(const char *format, ...);
void _exit(int status);

int main(void) {
    static const int sigs[] = {7, 11, 31, 15};
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        for (int round = 0; round < 5; round++) {
            int pid = fork();
            if (pid == 0) {
                pause();
                _exit(0);
            }
            kill(pid, sigs[i]);
            int status = 0;
            waitpid(pid, &status, 0);
            /* Killed by the signal (a core dumped or not). */
            if ((status & 0x7f) != sigs[i]) {
                printf("signal %d: status %#x\n", sigs[i], status);
                return 1;
            }
        }
        printf("signal %d: killed\n", sigs[i]);
    }
    return 0;
}
