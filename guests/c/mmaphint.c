/* mmap with an address hint whose range is free: Linux maps it there (SBCL
 * asks for its spaces so), and a second one hinted just past the first
 * (as Go's heap arenas are) continues it: a read into a buffer across the
 * two is one read. Every line printed is what Linux prints. */
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int pipe(int fd[2]);
long write(int fd, const void *buf, unsigned long n);
long read(int fd, void *buf, unsigned long n);

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MB (1ul << 20)

int main(void) {
    char *want = (char *)0x2f0000000ul;
    char *p = mmap(want, MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *q = mmap(want + MB, MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    p[0] = 7;
    q[MB - 1] = 9;
    printf("hint: %s, %d %d\n", p == want && q == want + MB ? "taken" : "moved", p[0], q[MB - 1]);
    int fds[2];
    pipe(fds);
    write(fds[1], "across", 6);
    long n = read(fds[0], want + MB - 3, 6);
    printf("read across: %ld %.6s\n", n, want + MB - 3);
    return 0;
}
