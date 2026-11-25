/* /sys's buses and classes, as a sandbox binds them (bwrap's
 * --ro-bind /sys/bus, /sys/class): /sys lists them; the cpu bus links
 * each CPU's device directory, as many as /sys/devices/system/cpu has. */
typedef struct DIR DIR;
struct dirent {
    unsigned long d_ino;
    long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};
DIR *opendir(const char *path);
struct dirent *readdir(DIR *d);
int closedir(DIR *d);
long readlink(const char *path, char *buf, unsigned long n);
int printf(const char *fmt, ...);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, unsigned long n);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);

static int has(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, name) == 0) found = 1;
    closedir(d);
    return found;
}

static int cpus(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)))
        if (strncmp(e->d_name, "cpu", 3) == 0 && e->d_name[3] >= '0' && e->d_name[3] <= '9') n++;
    closedir(d);
    return n;
}

int main(void) {
    printf("/sys has bus: %d, class: %d, block: %d, dev: %d, devices: %d\n", has("/sys", "bus"),
           has("/sys", "class"), has("/sys", "block"), has("/sys", "dev"), has("/sys", "devices"));
    printf("/sys/bus has cpu: %d; /sys/class has block: %d\n", has("/sys/bus", "cpu"),
           has("/sys/class", "block"));
    char link[256] = {0};
    long n = readlink("/sys/bus/cpu/devices/cpu0", link, sizeof link - 1);
    printf("cpu0 links to: %s\n", n > 0 ? link : "nothing");
    DIR *d = opendir("/sys/bus/cpu/devices/cpu0");
    printf("through it, a directory: %s\n", d ? "yes" : "no");
    if (d) closedir(d);
    int bus = cpus("/sys/bus/cpu/devices"), sys = cpus("/sys/devices/system/cpu");
    printf("the bus lists every CPU: %s\n", bus > 0 && bus == sys ? "yes" : "no");
    return 0;
}
