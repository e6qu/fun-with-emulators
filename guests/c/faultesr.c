/* A fault's syndrome in the signal frame, as Linux gives it and as Wine
 * reads it (to tell a write from a read): a read and then a write of a
 * page with no access, each handled, the handler finding the ESR record
 * among the frame's records and making the page accessible. Then the
 * signal's code and address, as crash handlers read them: a page with no
 * access (SEGV_ACCERR), one not mapped (SEGV_MAPERR) and a breakpoint
 * (SIGTRAP's TRAP_BRKPT, at the instruction). Every line printed is what
 * Linux prints. */
#include <stdint.h>

int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int mprotect(void *addr, unsigned long len, int prot);
int munmap(void *addr, unsigned long len);
struct sigaction {
    void (*sa_sigaction)(int, void *, void *);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
#define SIGSEGV 11
#define SIGTRAP 5
#define MAP_FIXED 0x10
/* Where a Linux arm64 ucontext keeps the pc. */
#define PC_OFF 440
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
static volatile int found, wnr, ec, code, faults;
static volatile uint64_t addr;

/* A signal's code and address (siginfo's si_code and si_addr). */
static void took(void *info) {
    code = *(int *)((uint8_t *)info + 8);
    addr = *(uint64_t *)((uint8_t *)info + 16);
}

static void trapped(int sig, void *info, void *ctx) {
    (void)sig;
    took(info);
    /* On past the breakpoint. */
    *(uint64_t *)((uint8_t *)ctx + PC_OFF) += 4;
}

static void handler(int sig, void *info, void *ctx) {
    (void)sig;
    faults++;
    took(info);
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
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0)
        mmap((void *)page, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
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
    mprotect((void *)page, 4096, PROT_NONE);
    c = page[300];
    printf("no access: fault %d, code %d, at the address %s\n", faults, code,
           addr == (uint64_t)(page + 300) ? "yes" : "no");
    munmap((void *)page, 16384);
    c = page[400];
    printf("not mapped: fault %d, code %d, at the address %s\n", faults, code,
           addr == (uint64_t)(page + 400) ? "yes" : "no");
    sa.sa_sigaction = trapped;
    sigaction(SIGTRAP, &sa, 0);
    uint64_t at;
    __asm__ volatile("adr %0, 1f\n1: brk #0x3e8" : "=r"(at));
    printf("breakpoint: code %d, at the instruction %s\n", code, addr == at ? "yes" : "no");
    (void)c;
    return 0;
}
