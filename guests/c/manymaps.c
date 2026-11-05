/* Many file mappings at once, as compilers and linkers make: fwe's VM
 * backend keeps a descriptor of its own for each, which must never be one
 * the program can name. A vfork child that first takes over the low
 * descriptors (as Go's does, moving its pipes into place) still reaches its
 * parent's memory. A shared mapping of a file opened read-only sees what is
 * written to the file later, and cannot be made writable.
 *
 * Prototypes are declared locally so the guest builds with a bare
 * `clang --target=aarch64-linux-gnu` and no Linux/libc headers on the host. */

int printf(const char *fmt, ...);
int snprintf(char *buf, unsigned long size, const char *fmt, ...);
int open(const char *path, int flags, ...);
int close(int fd);
int unlink(const char *path);
int ftruncate(int fd, long len);
long pwrite(int fd, const void *buf, unsigned long len, long off);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int mprotect(void *addr, unsigned long len, int prot);
int dup2(int from, int to);
int *__errno_location(void);
__attribute__((returns_twice)) int vfork(void);
void _exit(int code);
int waitpid(int pid, int *status, int options);

#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define FILES 300

/* Memory the vfork child reads only after its dup2s. */
static volatile char pages[4 * 4096];

int main(void) {
    char path[64];
    volatile char *maps[FILES];
    int first = -1;
    for (int i = 0; i < FILES; i++) {
        snprintf(path, sizeof path, "/tmp/fwe-manymaps-%d", i);
        int w = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        int r = open(path, O_RDONLY);
        if (w < 0 || r < 0 || ftruncate(w, 4096) != 0 || pwrite(w, "a", 1, 0) != 1) {
            printf("file %d: setup failed\n", i);
            return 1;
        }
        maps[i] = mmap(0, 4096, PROT_READ, MAP_SHARED, r, 0);
        if (maps[i] == (void *)-1) {
            printf("file %d: mmap failed, errno %d\n", i, *__errno_location());
            return 1;
        }
        close(r);
        unlink(path);
        if (i == 0)
            first = w;
        else
            close(w);
    }
    int all = 1;
    for (int i = 0; i < FILES; i++)
        all &= maps[i][0] == 'a';
    pwrite(first, "b", 1, 0);
    printf("%d read-only shared mappings; a later write seen: %d %d\n", FILES, all,
           maps[0][0] == 'b');
    int r = mprotect((void *)maps[0], 4096, PROT_READ | PROT_WRITE);
    printf("made writable: %d, errno %d\n", r, *__errno_location());

    for (int k = 0; k < 4; k++)
        pages[k * 4096] = (char)(k + 1);
    int child = vfork();
    if (child == 0) {
        for (int fd = 3; fd < 400; fd++)
            dup2(2, fd);
        int sum = 0;
        for (int k = 0; k < 4; k++)
            sum += pages[k * 4096];
        _exit(sum);
    }
    int status = -1;
    waitpid(child, &status, 0);
    printf("vfork child after taking descriptors 3-399: exit %d\n", (status >> 8) & 0xff);
    return 0;
}
