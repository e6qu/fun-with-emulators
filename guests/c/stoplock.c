/* A process stopped (SIGSTOP) while busy with kernel state every process
 * shares stops holding none of it, as Linux stops a task only on its way
 * back to user mode: a child makes and removes files of /dev/shm without
 * end, its parent stops it again and again, and while it is stopped makes
 * and removes one there itself. Several threads in the child make the
 * stop find one of them inside a call. Prints "ok".
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;

int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);
int open(const char *path, int flags, ...);
int close(int fd);
int unlink(const char *path);
int fork(void);
int getpid(void);
int kill(int pid, int sig);
int waitpid(int pid, int *status, int options);
int printf(const char *format, ...);
int snprintf(char *str, unsigned long size, const char *format, ...);
int usleep(unsigned usec);
void _exit(int status);
int *__errno_location(void);

#define O_RDWR 02
#define O_CREAT 0100
#define SIGKILL 9
#define SIGSTOP 19
#define SIGCONT 18
#define WUNTRACED 2
#define WCONTINUED 8
#define THREADS 4
#define ROUNDS 300

static void churn(int tag) {
    char path[64];
    snprintf(path, sizeof path, "/dev/shm/fwe-stoplock-%d-%d", getpid(), tag);
    for (;;) {
        int fd = open(path, O_RDWR | O_CREAT, 0600);
        if (fd >= 0) {
            close(fd);
        }
        unlink(path);
    }
}

static void *thread(void *arg) {
    churn((int)(long)arg);
    return 0;
}

int main(void) {
    int child = fork();
    if (child == 0) {
        pthread_t t;
        for (long i = 1; i < THREADS; i++) {
            pthread_create(&t, 0, thread, (void *)i);
        }
        churn(0);
    }
    char path[64];
    snprintf(path, sizeof path, "/dev/shm/fwe-stoplock-%d", getpid());
    for (int round = 0; round < ROUNDS; round++) {
        usleep(200 + round % 7 * 100);
        kill(child, SIGSTOP);
        int status = 0;
        waitpid(child, &status, WUNTRACED);
        if ((status & 0xff) != 0x7f) {
            printf("round %d: status %#x\n", round, status);
            kill(child, SIGKILL);
            return 1;
        }
        /* The child holds nothing while it is stopped. */
        int fd = open(path, O_RDWR | O_CREAT, 0600);
        if (fd < 0) {
            printf("round %d: open errno %d\n", round, *__errno_location());
            kill(child, SIGKILL);
            return 1;
        }
        close(fd);
        unlink(path);
        kill(child, SIGCONT);
        waitpid(child, &status, WCONTINUED);
    }
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    printf("ok\n");
    return 0;
}
