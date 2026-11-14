/* A child that asks for its parent many times (fwe then keeps the answer)
 * still sees its parent change once the parent ends: it is reparented.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. Prints from the child,
 * after the parent has gone. */

typedef unsigned int useconds_t;

int fork(void);
int getppid(void);
int pipe(int fds[2]);
long read(int fd, void *buf, unsigned long n);
long write(int fd, const void *buf, unsigned long n);
int usleep(useconds_t us);
int printf(const char *format, ...);
int fflush(void *stream);
void _exit(int status);

int main(void) {
    int ready[2];
    if (pipe(ready) != 0) {
        return 1;
    }
    int pid = fork();
    if (pid < 0) {
        return 1;
    }
    if (pid > 0) {
        /* The parent ends once the child has asked often. */
        char c;
        read(ready[0], &c, 1);
        _exit(0);
    }
    int first = getppid();
    int same = 1;
    for (int i = 0; i < 100; i++) {
        same &= getppid() == first;
    }
    write(ready[1], "x", 1);
    int changed = 0;
    for (int i = 0; i < 400 && !changed; i++) {
        changed = getppid() != first;
        if (!changed) {
            usleep(5000);
        }
    }
    printf("same while it lived: %d, changed once it ended: %d\n", same, changed);
    fflush(0);
    _exit(0);
}
