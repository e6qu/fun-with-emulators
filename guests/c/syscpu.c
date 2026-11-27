/* /sys/devices/system/cpu as programs read it: glibc's sysconf counts its
 * cpu<n> directories and reads cpu0's caches; schedulers read each CPU's
 * topology. Prints what it found, and whether each CPU's masks and lists
 * agree and its cluster and L2 (where the host tells of caches) hold it. */
int printf(const char *fmt, ...);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);
int open(const char *path, int flags, ...);
int close(int fd);
long read(int fd, void *buf, unsigned long n);
long sysconf(int name);
long strtol(const char *s, char **end, int base);
int strcmp(const char *a, const char *b);
char *strchr(const char *s, int c);

#define _SC_NPROCESSORS_CONF 83
#define _SC_NPROCESSORS_ONLN 84

/* The first line of `path`, its newline dropped; "" if there is none. */
static const char *line(const char *path) {
    static char buf[256];
    int fd = open(path, 0);
    if (fd < 0) return "";
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    char *nl = strchr(buf, '\n');
    if (nl) *nl = 0;
    return buf;
}

/* The CPUs a list names ("0-3", "5", "0-1,4"), as a bit set. */
static unsigned long long of_list(const char *s) {
    unsigned long long set = 0;
    while (*s) {
        char *end;
        long a = strtol(s, &end, 10), b = a;
        if (*end == '-') b = strtol(end + 1, &end, 10);
        for (long i = a; i <= b; i++) set |= 1ull << i;
        s = *end == ',' ? end + 1 : end;
        if (end == s && *s) break;
    }
    return set;
}

/* The CPUs a mask names ("f00", "01,00000000" past 64 not needed). */
static unsigned long long of_mask(const char *s) {
    unsigned long long set = 0;
    for (; *s; s++) {
        if (*s == ',') continue;
        int d = *s <= '9' ? *s - '0' : *s - 'a' + 10;
        set = set << 4 | (unsigned)d;
    }
    return set;
}

static const char *at(const char *fmt, int cpu) {
    static char path[160];
    snprintf(path, sizeof path, fmt, cpu);
    return path;
}

int main(void) {
    int n = 0;
    while (line(at("/sys/devices/system/cpu/cpu%d/online", n))[0]) n++;
    printf("cpus: %d\n", n);
    printf("conf: %ld, online: %ld\n", sysconf(_SC_NPROCESSORS_CONF), sysconf(_SC_NPROCESSORS_ONLN));
    /* (One at a time: `line` reads into one buffer.) */
    printf("online list: %s, ", line("/sys/devices/system/cpu/online"));
    printf("present: %s\n", line("/sys/devices/system/cpu/present"));
    printf("L1d: %s, ", line("/sys/devices/system/cpu/cpu0/cache/index0/size"));
    printf("line: %s\n", line("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"));
    int bad = 0;
    for (int c = 0; c < n; c++) {
        unsigned long long me = 1ull << c;
        const char *pairs[][2] = {
            {"/sys/devices/system/cpu/cpu%d/topology/core_cpus", "/sys/devices/system/cpu/cpu%d/topology/core_cpus_list"},
            {"/sys/devices/system/cpu/cpu%d/topology/cluster_cpus", "/sys/devices/system/cpu/cpu%d/topology/cluster_cpus_list"},
            {"/sys/devices/system/cpu/cpu%d/topology/package_cpus", "/sys/devices/system/cpu/cpu%d/topology/package_cpus_list"},
            {"/sys/devices/system/cpu/cpu%d/cache/index2/shared_cpu_map", "/sys/devices/system/cpu/cpu%d/cache/index2/shared_cpu_list"},
        };
        /* The caches, where the host tells of them. */
        int cached = line(at("/sys/devices/system/cpu/cpu%d/cache/index2/level", c))[0] != 0;
        for (unsigned i = 0; i < sizeof pairs / sizeof pairs[0] - !cached; i++) {
            unsigned long long m = of_mask(line(at(pairs[i][0], c)));
            unsigned long long l = of_list(line(at(pairs[i][1], c)));
            if (m != l || !(m & me)) {
                printf("cpu%d: %s disagrees\n", c, pairs[i][0]);
                bad = 1;
            }
        }
        if (of_list(line(at("/sys/devices/system/cpu/cpu%d/topology/core_cpus_list", c))) != me) bad = 1;
        if (cached && strcmp(line(at("/sys/devices/system/cpu/cpu%d/cache/index1/type", c)), "Instruction"))
            bad = 1;
    }
    printf("consistent: %s\n", bad ? "no" : "yes");
    return 0;
}
