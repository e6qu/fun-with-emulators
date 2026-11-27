/* Making a name that exists, in or at a read-only mount: Linux reports
 * EEXIST before EROFS (filename_create looks the name up first), as a
 * sandbox (bwrap) that binds a directory twice relies on; a new name there
 * is EROFS. Run as root, in a mount namespace of its own. */
int unshare(int flags);
int mount(const char *src, const char *target, const char *type, unsigned long flags,
          const void *data);
int mkdir(const char *path, unsigned mode);
int mkdirat(int dirfd, const char *path, unsigned mode);
int mknod(const char *path, unsigned mode, unsigned long dev);
int symlink(const char *target, const char *path);
int link(const char *old, const char *path);
int open(const char *path, int flags, ...);
int close(int fd);
int printf(const char *fmt, ...);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);
int *__errno_location(void);
#define errno (*__errno_location())

static const char *name(int r) {
    if (r == 0) return "made";
    switch (errno) {
    case 17: return "EEXIST";
    case 30: return "EROFS";
    case 18: return "EXDEV";
    case 1: return "EPERM";
    case 2: return "ENOENT";
    default: return "other";
    }
}

static void tries(const char *ro, const char *src) {
    char p[64];
#define AT(n) (snprintf(p, sizeof p, "%s%s", ro, n), p)
    printf("mkdir of the read-only mount's root: %s\n", name(mkdir(AT(""), 0755)));
    printf("mkdir of a directory in it: %s\n", name(mkdir(AT("/dir"), 0755)));
    printf("mkdir of a file in it: %s\n", name(mkdir(AT("/file"), 0755)));
    printf("mkdir of a new name in it: %s\n", name(mkdir(AT("/new"), 0755)));
    printf("mknod of a file in it: %s\n", name(mknod(AT("/file"), 0010644, 0)));
    printf("mknod of a new name in it: %s\n", name(mknod(AT("/new"), 0010644, 0)));
    printf("symlink at a file in it: %s\n", name(symlink("x", AT("/file"))));
    printf("symlink at a new name in it: %s\n", name(symlink("x", AT("/new"))));
    char from[64];
    snprintf(from, sizeof from, "%s/file", src);
    printf("link to a file in it: %s\n", name(link(from, AT("/file"))));
    snprintf(from, sizeof from, "%s/file", ro);
    printf("link to a new name in it: %s\n", name(link(from, AT("/new"))));
}

/* A read-only bind of `src` at `ro`, with a directory and a file in it. */
static void bind_ro(const char *src, const char *ro) {
    char p[64];
    snprintf(p, sizeof p, "%s/dir", src);
    mkdir(src, 0755);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/file", src);
    close(open(p, 0x40 | 1, 0644));
    mkdir(ro, 0755);
    mount(src, ro, 0, 0x1000 /* MS_BIND */, 0);
    mount("none", ro, 0, 0x20 | 0x1000 | 1 /* MS_REMOUNT|MS_BIND|MS_RDONLY */, 0);
}

int main(void) {
    if (unshare(0x20000 /* CLONE_NEWNS */) != 0) { printf("unshare failed\n"); return 1; }
    mount("none", "/", 0, 0x4000 | 0x40000 /* MS_REC|MS_PRIVATE */, 0);
    mkdir("mkexist", 0755);
    if (mount("tmpfs", "mkexist", "tmpfs", 0, 0) != 0) { printf("mount failed\n"); return 1; }
    /* A directory outside the tmpfs bound, as bwrap binds /usr/share. */
    bind_ro("mkexist-a", "mkexist/ro");
    int parent = open("mkexist", 0x200000 | 0x10000 /* O_PATH|O_DIRECTORY */);
    printf("mkdirat of the root from its parent: %s\n", name(mkdirat(parent, "ro", 0755)));
    close(parent);
    tries("mkexist/ro", "mkexist-a");
    /* A tmpfs directory bound. */
    printf("in a tmpfs:\n");
    bind_ro("mkexist/b", "mkexist/rob");
    tries("mkexist/rob", "mkexist/b");
    return 0;
}
