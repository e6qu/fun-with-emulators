/* mmap with an address hint whose range is free: Linux maps it there (SBCL
 * asks for its spaces so). Every line printed is what Linux prints. */
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

int main(void) {
    char *want = (char *)0x2f0000000ul;
    char *p = mmap(want, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    p[0] = 7;
    p[(1 << 20) - 1] = 9;
    printf("hint: %s, %d %d\n", p == want ? "taken" : "moved", p[0], p[(1 << 20) - 1]);
    return 0;
}
