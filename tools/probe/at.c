typedef unsigned long size_t;
int printf(const char *f, ...);
int open(const char *p, int fl, ...);
int close(int fd);
long write(int fd, const void *b, size_t n);
int utimensat(int d, const char *p, const void *t, int fl);
int link(const char *a, const char *b);
int chown(const char *p, unsigned u, unsigned g);
int usleep(unsigned us);
int mount(const char *s, const char *t, const char *f, unsigned long fl, const void *d);
int umount(const char *t);
int mkdir(const char *p, unsigned m);
int symlink(const char *a, const char *b);
int lstat(const char *p, void *st);
int chdir(const char *p);
static void show(const char *what, const char *p) {
    long st[16];
    int r = lstat(p, st);
    printf("%s %s r=%d atime %ld.%09ld mtime %ld.%09ld ctime %ld.%09ld\n", what, p, r, st[9], st[10], st[11], st[12], st[13], st[14]);
}
int main(int argc, char **argv) {
    chdir(argv[1]);
    mkdir("mntpoint", 0777);
    int tm = argc > 2;
    if (tm) printf("mount %d\n", mount("none", "mntpoint", "tmpfs", 0, 0));
    int fd = open("file.txt", 0101, 0777); close(fd);
    utimensat(-100, "file.txt", 0, 0);
    show("touched", "file.txt");
    link("file.txt", "linked_file");
    printf("chown %d\n", chown("file.txt", 1000, 1000));
    show("chowned", "file.txt");
    fd = open("file.txt", 1);
    static char buf[1024];
    for (int i = 0; i < 1024; i++) buf[i] = 'a';
    for (int i = 0; i < 500; i++) write(fd, buf, 1024);
    close(fd);
    show("written", "file.txt");
    usleep(1500000);
    symlink("file.txt", "mntpoint/file_symlink");
    show("file", "file.txt");
    show("symlink", "mntpoint/file_symlink");
    if (tm) umount("mntpoint");
    return 0;
}
