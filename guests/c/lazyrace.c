/* Threads that first run the same pages of the shared libc at the same
 * moment: with the libc's preparation kept from an earlier run, fwe writes
 * each page of its code as it first runs, and a thread that runs a page
 * while another is writing it must run on, not fault.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. Prints "ok". */

typedef unsigned long size_t;
typedef unsigned long pthread_t;

int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);
int pthread_join(pthread_t thread, void **ret);
char *getcwd(char *buf, size_t size);
int getpid(void);
int snprintf(char *str, size_t size, const char *format, ...);
double strtod(const char *s, char **end);
int puts(const char *s);

#define THREADS 8

static int arrived;

static void *go(void *arg) {
    (void)arg;
    /* All at once: each waits for the others before its first libc call. */
    __atomic_add_fetch(&arrived, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&arrived, __ATOMIC_SEQ_CST) < THREADS) {
    }
    char buf[256];
    getcwd(buf, sizeof buf);
    snprintf(buf, sizeof buf, "%d %f", getpid(), strtod("1.5", 0));
    return 0;
}

int main(void) {
    pthread_t t[THREADS];
    for (int i = 0; i < THREADS; i++) {
        if (pthread_create(&t[i], 0, go, 0) != 0) {
            return 1;
        }
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], 0);
    }
    puts("ok");
    return 0;
}
