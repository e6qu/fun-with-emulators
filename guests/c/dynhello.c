/* A normal dynamically linked program: full C runtime startup through musl's
 * crt objects and `__libc_start_main`, then libc services (the heap and
 * buffered stdio) resolved from the shared libc at load time.
 *
 * Prototypes are declared locally so the guest builds with a bare
 * `clang --target=aarch64-linux-gnu` and no Linux/libc headers on the host,
 * exactly like the assembly guests. */

int printf(const char *fmt, ...);
void *malloc(unsigned long size);
void free(void *ptr);
unsigned long strlen(const char *s);
char *strcpy(char *dst, const char *src);

int main(int argc, char **argv) {
    const char *who = argc > 1 ? argv[1] : "world";
    char *buf = malloc(strlen(who) + 1);
    if (!buf) {
        return 1;
    }
    strcpy(buf, who);
    printf("dynamic hello, %s\n", buf);
    free(buf);
    return 0;
}
