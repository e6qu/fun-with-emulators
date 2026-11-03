/* A vfork child shares its parent's memory until it execs or exits.
 *
 * glibc's posix_spawn runs the child with CLONE_VM | CLONE_VFORK and, when
 * the exec fails, reports the error by writing it into the parent's memory
 * before exiting; posix_spawn then returns it. A plain vfork child's writes
 * to a global and to the parent's stack are seen by the parent too.
 *
 * Prototypes are declared locally so the guest builds with a bare
 * `clang --target=aarch64-linux-gnu` and no Linux/libc headers on the host. */

int printf(const char *fmt, ...);
int posix_spawn(int *pid, const char *path, const void *actions, const void *attr,
                char *const argv[], char *const envp[]);
__attribute__((returns_twice)) int vfork(void);
void _exit(int code);
int waitpid(int pid, int *status, int options);

static volatile int global;

int main(void) {
    char *argv[] = {"missing", 0};
    char *envp[] = {0};
    int pid = 0;
    int r = posix_spawn(&pid, "/no/such/program", 0, 0, argv, envp);
    printf("posix_spawn of a missing program: %d\n", r);

    volatile int local = 0;
    int child = vfork();
    if (child == 0) {
        global = 42;
        local = 7;
        _exit(0);
    }
    int status = -1;
    waitpid(child, &status, 0);
    printf("vfork child's writes seen: %d %d, status %d\n", global, local, status);
    return 0;
}
