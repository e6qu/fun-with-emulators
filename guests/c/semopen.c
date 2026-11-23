/* Named POSIX semaphores, as Python's multiprocessing makes its locks:
 * sem_open with O_CREAT | O_EXCL (the C library makes a file in /dev/shm
 * under a temporary name, maps it and links it to its name), made again
 * (EEXIST), opened again by name, posted by a fork child and taken by the
 * parent, then unlinked, after which its name is gone (ENOENT).
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef struct {
    long words[4];
} sem_t;

sem_t *sem_open(const char *name, int oflag, ...);
int sem_close(sem_t *sem);
int sem_unlink(const char *name);
int sem_post(sem_t *sem);
int sem_wait(sem_t *sem);
int sem_getvalue(sem_t *sem, int *value);
int *__errno_location(void);
int fork(void);
int getpid(void);
int waitpid(int pid, int *status, int options);
int printf(const char *format, ...);
int snprintf(char *str, unsigned long size, const char *format, ...);
void _exit(int status);

#define O_CREAT 0100
#define O_EXCL 0200
#define SEM_FAILED ((sem_t *)0)
#define POSTS 2

int main(void) {
    char name[64];
    snprintf(name, sizeof name, "/fwe-sem-%d", getpid());
    sem_t *s = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
    if (s == SEM_FAILED) {
        printf("sem_open: errno %d\n", *__errno_location());
        return 1;
    }
    sem_t *again = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
    int exists = again == SEM_FAILED ? *__errno_location() : 0;
    sem_t *t = sem_open(name, 0);
    if (t == SEM_FAILED) {
        printf("sem_open again: errno %d\n", *__errno_location());
        return 1;
    }
    int pid = fork();
    if (pid == 0) {
        for (int i = 0; i < POSTS; i++) {
            sem_post(t);
        }
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    for (int i = 0; i < POSTS; i++) {
        sem_wait(s);
    }
    int value = -1;
    sem_getvalue(s, &value);
    int unlinked = sem_unlink(name);
    sem_t *gone = sem_open(name, 0);
    int missing = gone == SEM_FAILED ? *__errno_location() : 0;
    sem_close(t);
    sem_close(s);
    printf("made; made again: errno %d; posts of a child taken, left %d; unlinked %d; "
           "opened after: errno %d\n",
           exists, value, unlinked, missing);
    return 0;
}
