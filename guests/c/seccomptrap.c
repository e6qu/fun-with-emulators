/* SECCOMP_RET_TRAP as sandboxes rely on it (Chromium's and Firefox's
 * check that the SIGSYS's call address is the context's pc): the call is
 * not made; the handler gets the call's number, the filter's data and the
 * address after the svc, which the context's pc also holds, and sets what
 * the call returns. A filter reads the same address
 * (seccomp_data.instruction_pointer). A trapped call is not restarted,
 * even with SA_RESTART: what x0 holds after the handler (its first
 * argument, unless the handler set it) is what it returns, -EINTR too. */
int printf(const char *fmt, ...);
int prctl(int op, ...);
long syscall(long n, ...);
void *memset(void *p, int c, unsigned long n);

struct sock_filter { unsigned short code; unsigned char jt, jf; unsigned k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };
struct siginfo {
    int signo, errno_, code, pad;
    void *call_addr;
    int syscall_, arch;
    char rest[96];
};
struct ucontext {
    unsigned long flags;
    void *link;
    char stack[24];
    char sigmask[128];
    char pad[8];
    unsigned long fault_address, regs[31], sp, pc, pstate;
};
struct sigaction_k { void (*handler)(int, struct siginfo *, void *); unsigned long flags; void (*restorer)(void); unsigned long mask; };

#define PR_SET_NO_NEW_PRIVS 38
#define SYS_seccomp 277
#define SYS_rt_sigaction 134
#define SYS_read 63
#define SYS_getppid 173
#define SYS_sysinfo 179
#define SIGSYS 31
#define SA_SIGINFO 4
#define SA_RESTORER 0x04000000
#define SA_RESTART 0x10000000

static struct siginfo seen;
static unsigned long seen_pc, seen_nr;
static int keep, handled;

static void on_sigsys(int sig, struct siginfo *si, void *ctx) {
    struct ucontext *uc = ctx;
    (void)sig;
    seen = *si;
    seen_pc = uc->pc;
    seen_nr = uc->regs[8];
    handled++;
    if (!keep)
        uc->regs[0] = 42;
}

/* Call `nr`, its first argument `a0`, by a svc of its own; the address
 * after it in `after`. */
static long call(long nr, long a0, unsigned long *after) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    unsigned long at;
    __asm__ volatile("adr %1, 1f\n\tsvc #0\n1:" : "+r"(x0), "=&r"(at) : "r"(x8) : "memory");
    *after = at;
    return x0;
}

extern void restorer(void);
__asm__(".globl restorer\nrestorer:\n\tmov x8, #139\n\tsvc #0\n");

int main(void) {
    struct sock_filter g[] = {
        {0x20, 0, 0, 0},              /* ld [nr] */
        {0x15, 2, 0, SYS_getppid},    /* jeq getppid: trap */
        {0x15, 1, 0, SYS_read},       /* jeq read: trap */
        {0x15, 1, 5, SYS_sysinfo},    /* jeq sysinfo, else allow */
        {0x06, 0, 0, 0x00030000 | 7}, /* ret TRAP | 7 */
        {0x20, 0, 0, 8},              /* ld [instruction_pointer] (low) */
        {0x54, 0, 0, 0xffc},          /* and 0xffc */
        {0x44, 0, 0, 0x00050000},     /* or ERRNO */
        {0x16, 0, 0, 0},              /* ret a */
        {0x06, 0, 0, 0x7fff0000},     /* ret ALLOW */
    };
    struct sock_fprog prog = {sizeof g / sizeof g[0], g};
    struct sigaction_k sa;
    memset(&sa, 0, sizeof sa);
    sa.handler = on_sigsys;
    sa.flags = SA_SIGINFO | SA_RESTORER | SA_RESTART;
    sa.restorer = restorer;
    syscall(SYS_rt_sigaction, SIGSYS, &sa, 0, 8);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    printf("filter: %ld\n", syscall(SYS_seccomp, 1, 0, &prog));
    unsigned long after;
    long r = call(SYS_getppid, 0, &after);
    printf("trapped call returns: %ld\n", r);
    printf("signal %d, code %d, syscall %d, data %d, arch 0x%x\n", seen.signo, seen.code,
           seen.syscall_, seen.errno_, seen.arch);
    printf("call address is after the svc: %s\n", (unsigned long)seen.call_addr == after ? "yes" : "no");
    printf("context pc is after the svc: %s\n", seen_pc == after ? "yes" : "no");
    printf("context x8: %lu\n", seen_nr);
    r = call(SYS_sysinfo, 0, &after);
    printf("filter's instruction pointer is after the svc: %s\n", -r == (long)(after & 0xffc) ? "yes" : "no");
    keep = 1;
    handled = 0;
    r = call(SYS_read, -4, &after);
    printf("a trapped read whose first argument is -EINTR returns: %ld, its handler run %d time(s)\n", r,
           handled);
    return 0;
}
