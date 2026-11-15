/* A signal sent to a process whose main thread blocks it, waiting in
 * pause(), is taken by another thread that does not block it, waiting in
 * pause() too or sleeping, as Linux hands a process's signal to a thread
 * that can take it.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;
typedef struct { unsigned long bits[16]; } sigset_t;

int fork(void);
int kill(int pid, int sig);
int pause(void);
int usleep(unsigned usec);
int waitpid(int pid, int *status, int options);
int pthread_create(pthread_t *t, const void *attr, void *(*f)(void *), void *arg);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
void (*signal(int sig, void (*handler)(int)))(int);
int printf(const char *format, ...);
int fflush(void *stream);
void _exit(int status);

#define SIGUSR1 10
#define SIGKILL 9
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define WNOHANG 1

static volatile int got;
static void on(int sig) { got = sig; }

static void *waits(void *how) {
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, 0);
    for (;;) {
        if (how) {
            usleep(1000000);
        } else {
            pause();
        }
        if (got) {
            printf("taken by the other thread\n");
            fflush(0);
            _exit(0);
        }
    }
}

int main(int argc, char **argv) {
    (void)argv;
    int pid = fork();
    if (pid == 0) {
        signal(SIGUSR1, on);
        sigset_t usr1;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        pthread_sigmask(SIG_BLOCK, &usr1, 0);
        pthread_t t;
        pthread_create(&t, 0, waits, (void *)(long)(argc > 1));
        for (;;) {
            pause();
        }
    }
    usleep(200000);
    kill(pid, SIGUSR1);
    for (int i = 0; i < 50; i++) {
        int status;
        if (waitpid(pid, &status, WNOHANG) == pid) {
            return 0;
        }
        usleep(100000);
    }
    printf("not taken\n");
    kill(pid, SIGKILL);
    waitpid(pid, 0, 0);
    return 1;
}
