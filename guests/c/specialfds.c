/* Pipes, eventfds and signalfds as Linux has them. The first argument
 * names the case.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;

int pipe2(int fds[2], int flags);
int eventfd(unsigned initval, int flags);
int *__errno_location(void);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);

#define O_EXCL 0200
#define O_NOTIFICATION_PIPE O_EXCL
#define errno (*__errno_location())

/* Flags Linux does not know are EINVAL; a notification pipe, which needs
 * the watch queue, is ENOPKG. */
static int flags(void) {
    int fds[2];
    int a = pipe2(fds, 01);
    int ea = errno;
    int b = pipe2(fds, O_NOTIFICATION_PIPE);
    int eb = errno;
    int c = eventfd(0, 010);
    int ec = errno;
    printf("pipe2 %d errno %d, notification pipe %d errno %d, eventfd %d errno %d\n", a, ea, b,
           eb, c, ec);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "flags"))
        return flags();
    return 2;
}
