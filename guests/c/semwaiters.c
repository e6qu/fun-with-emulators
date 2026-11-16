/* A process that /proc shows sleeping ('S') in a semaphore wait is
 * counted by GETNCNT or GETZCNT, as semctl01 expects: fwe's own work on
 * the way to the wait (its records' files, a page brought in) is not
 * shown as a sleep. Twelve workers at once, each with sets of its own,
 * load the host as a test run does.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;
typedef long ssize_t;

int semget(int key, int nsems, int flags);
int semctl(int id, int num, int cmd, ...);
int semop(int id, void *sops, size_t nsops);
int fork(void);
int kill(int pid, int sig);
int waitpid(int pid, int *status, int options);
void _exit(int status);
int open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t n);
int close(int fd);
int pipe(int fds[2]);
ssize_t write(int fd, const void *buf, size_t n);
int snprintf(char *s, size_t n, const char *format, ...);
int printf(const char *format, ...);
char *strrchr(const char *s, int c);
int sched_yield(void);

#define IPC_PRIVATE 0
#define IPC_CREAT 01000
#define IPC_RMID 0
#define GETNCNT 14
#define GETZCNT 15
#define SETVAL 16
#define SIGKILL 9
#define WORKERS 12
#define ROUNDS 25
#define WAITERS 5

struct sembuf {
    unsigned short num;
    short op, flg;
};

/* The state letter of /proc/<pid>/stat. */
static char state(int pid) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int fd = open(path, 0);
    if (fd < 0)
        return '?';
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return '?';
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    return p ? p[2] : '?';
}

/* One worker's rounds: how many waiters were shown sleeping but not
 * counted. */
static int worker(void) {
    int wrong = 0;
    for (int r = 0; r < ROUNDS; r++) {
        int id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
        if (id < 0)
            return -1;
        int zero = r & 1;
        if (zero)
            semctl(id, 0, SETVAL, 1);
        int pids[WAITERS];
        for (int i = 0; i < WAITERS; i++) {
            int pid = fork();
            if (pid < 0)
                return -1;
            if (pid == 0) {
                struct sembuf s = {0, zero ? 0 : -1, 0};
                semop(id, &s, 1);
                _exit(0);
            }
            pids[i] = pid;
            while (state(pid) != 'S')
                sched_yield();
            if (semctl(id, 0, zero ? GETZCNT : GETNCNT) != i + 1)
                wrong++;
        }
        for (int i = 0; i < WAITERS; i++) {
            kill(pids[i], SIGKILL);
            waitpid(pids[i], 0, 0);
        }
        semctl(id, 0, IPC_RMID);
    }
    return wrong;
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
            int wrong = worker();
            write(fds[1], &wrong, sizeof wrong);
            _exit(0);
        }
    }
    int total = 0, failed = 0;
    for (int w = 0; w < WORKERS; w++) {
        int wrong;
        if (read(fds[0], &wrong, sizeof wrong) != sizeof wrong || wrong < 0)
            failed++;
        else
            total += wrong;
        waitpid(pids[w], 0, 0);
    }
    printf("workers failed: %d, sleeping waiters not counted: %d\n", failed, total);
    return 0;
}
