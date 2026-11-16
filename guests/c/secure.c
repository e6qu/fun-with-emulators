/* What a program is told of its credentials as it starts: the ids in its
 * auxiliary vector, AT_SECURE, and whether the C library kept
 * LD_LIBRARY_PATH (glibc's dynamic linker removes it, with LD_PRELOAD and
 * the rest, from a program started in secure mode).
 *
 * Prototypes are declared locally so the guest builds with a bare
 * `clang --target=aarch64-linux-gnu` and no Linux/libc headers on the host. */

int printf(const char *fmt, ...);
char *getenv(const char *name);
unsigned long getauxval(unsigned long type);

enum { AT_UID = 11, AT_EUID = 12, AT_GID = 13, AT_EGID = 14, AT_SECURE = 23 };

int main(int argc, char **argv) {
    const char *path = getenv("LD_LIBRARY_PATH");
    printf("%s: uid %lu euid %lu gid %lu egid %lu secure %lu LD_LIBRARY_PATH %s\n",
           argc > 1 ? argv[1] : "?", getauxval(AT_UID), getauxval(AT_EUID), getauxval(AT_GID),
           getauxval(AT_EGID), getauxval(AT_SECURE), path ? path : "(removed)");
    return 0;
}
