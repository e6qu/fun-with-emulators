/* A fault's syndrome in the signal frame, as Linux gives it and as Wine
 * reads it (to tell a write from a read): a read and then a write of a
 * page with no access, each handled, the handler finding the ESR record
 * among the frame's records and making the page accessible. Every line
 * printed is what Linux prints. */
#include <stdint.h>

int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int mprotect(void *addr, unsigned long len, int prot);
struct sigaction {
    void (*sa_sigaction)(int, void *, void *);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
#define SIGSEGV 11
#define SA_SIGINFO 4
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
/* Where a Linux arm64 ucontext's mcontext keeps its records
 * (`__reserved`). */
#define RESERVED_OFF 464

#define ESR_MAGIC 0x45535201u

static volatile char *page;
static volatile int found, wnr, ec;

static void handler(int sig, void *info, void *ctx) {
    (void)sig;
    (void)info;
    uint8_t *rec = (uint8_t *)ctx + RESERVED_OFF;
    found = 0;
    for (;;) {
        uint32_t magic = *(uint32_t *)rec, size = *(uint32_t *)(rec + 4);
        if (magic == 0 || size == 0) break;
        if (magic == ESR_MAGIC) {
            uint64_t esr = *(uint64_t *)(rec + 8);
            found = 1;
            wnr = (esr >> 6) & 1;
            ec = (int)(esr >> 26) & 0x3f;
        }
        rec += size;
    }
    mprotect((void *)page, 4096, PROT_READ | PROT_WRITE);
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    page = mmap(0, 16384, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char c = page[100];
    printf("read: syndrome %s, data abort %s, write %d\n", found ? "found" : "missing",
           ec == 0x24 ? "yes" : "no", wnr);
    mprotect((void *)page, 4096, PROT_NONE);
    page[200] = c + 1;
    printf("write: syndrome %s, data abort %s, write %d\n", found ? "found" : "missing",
           ec == 0x24 ? "yes" : "no", wnr);
    return 0;
}
