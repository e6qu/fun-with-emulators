/* mmap with an address hint whose range is free: Linux maps it there (SBCL
 * asks for its spaces so), and a second one hinted just past the first
 * (as Go's heap arenas are) continues it: a read into a buffer across the
 * two is one read. A third, mapped between two others after them, may be
 * backed apart from both: a read or write across its edges is still
 * whole, each made of as many calls as Linux may need (a shorter count is
 * read or written again from where it ended, as programs do). Every line
 * printed is what Linux prints. */
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

    char *x = (char *)0x2f8000000ul;
    char *a = mmap(x, MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *b = mmap(x + 2 * MB, MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *c = mmap(x + MB, MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int whole = a == x && b == x + 2 * MB && c == x + MB;
    for (int edge = 1; edge <= 2; edge++) {
        char *at = x + edge * MB - 3;
        write(fds[1], "seams!", 6);
        long got = 0;
        while (got < 6) {
            long r = read(fds[0], at + got, 6 - got);
            if (r <= 0) {
                break;
            }
            got += r;
        }
        long put = 0;
        while (put < 6) {
            long r = write(fds[1], at + put, 6 - put);
            if (r <= 0) {
                break;
            }
            put += r;
        }
        char back[6];
        long n2 = read(fds[0], back, 6);
        whole = whole && got == 6 && put == 6 && n2 == 6;
        for (int i = 0; i < 6; i++) {
            whole = whole && back[i] == "seams!"[i];
        }
    }
    printf("between: %s\n", whole ? "whole" : "broken");
    return 0;
}
