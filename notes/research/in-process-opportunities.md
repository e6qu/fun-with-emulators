# What fwe could answer in-process instead of asking macOS

Research note, 2026-11-20. Read-only study of the code at `m6-native-speed`
(2298f82b) and of CI benchmark logs; nothing was run. Where a number is
not in the logs or a cited source, it says "not measured".

## Sources and how to read them

Logs of the `Benchmarks (macos-26)` CI job of 2026-11-20, by run id (the
job's log: `gh run view <id> --log`, or the job's logs through the API):

- `bench44742833253.log` (13:29 UTC run, complete, with the summary table
  at lines 1239-1268), called **L1** below;
- `bench44768023445.log` (16:54 UTC run, cut short before Node.js and the
  table), called **L2**;
- `bench-44675279942.log`, `bench-44710157149.log`, `bench44731909274.log`
  (earlier runs of the same day), called **L0a**, **L0b**, **L0c**.

Three kinds of line are used, and they come from three different runs of
each workload (`tools/bench/run.py`):

1. `N system calls under fwe: ...` counts the guest's calls in a run under
   `--strace` (`tools/bench/run.py:725-735`). Tracing slows the program, so
   counts that depend on timing (futex) differ from an untraced run.
2. `fwe's marks: ... exit: N system calls, by number, the longest: NR: count
   (ms)` is an untraced run with `FWE_TIMING=1`: count and summed time per
   Linux call number, measured inside fwe between
   `timing::call_began`/`call_done` (`crates/native/src/trap.rs:456,474`),
   so the gate's entry and exit are not in it and a blocking call's time
   includes its wait. Numbers used: 98 `futex`, 113 `clock_gettime`,
   215 `munmap`, 222 `mmap`, 165 `getrusage`, 67 `pread64`, 25 `fcntl`.
3. `host system calls: ...` is a DTrace run of the same workload
   (`tools/bench/run.py:1120-1190`): count and time of every host system
   call and Mach trap of processes named `fwe`. DTrace's probes add their
   own cost to each call, so the per-call times are upper bounds, good for
   comparing calls with each other, not as absolute costs. Its counts do
   not always match the `--strace` run (SQLite: 286,698 guest `pread64`
   but 319 host `pread` in L2:666), so only ratios within one line are
   used.

The micro-benchmark table (L1:1239-1268) gives absolute costs: `getpid`
48.3 ns under fwe, 139.9 ns on macOS; `open`+`close` 7409 ns against
5750 ns; `fork`+exit+wait 526 µs against 228 µs; a handled `SIGSEGV`
5.27 µs against 1.75 µs.

## Summary, ranked by expected gain on the logged workloads

| # | Candidate | Workload evidence | Kind of saving |
|---|---|---|---|
| 1 | A vDSO: `clock_gettime`, `gettimeofday`, `clock_getres` answered in the guest's own code | JDK: 84,233-87,823 `clock_gettime` per javac run, 26,718-28,321 per java run; Node.js 23,774-30,426 | the gate, the kernel lock and fwe's dispatch, ~85-115k entries per JDK run |
| 2 | Futex queues: hashed buckets, no 20 ms signal polling, no allocation per wait | JDK java (Bank): 46,353-359,626 `futex` per run; waits on the queue table's mutex up to 13.8 ms | host mutex waits (`psynch_mutexwait`) and futile host wake-ups fwe causes |
| 3 | Calls that need no kernel state answered before the kernel lock | `klock::Lock::shared` blocked 5.1 ms, 2.4 ms, 1.4 ms, 1.3 ms behind writers (L1 JDK java) | host mutex waits on the time, id and yield calls |
| 4 | The parked-signal look (`sigpending`) made only when a signal can have been parked | JDK: 3,989-12,088 `sigpending` per program run | one host call per waiting or memory call of a thread that blocks a caught signal |
| 5 | Kept metadata read once per file, for every fwe process | git log -p: 557 `fgetxattr`, 6.7 ms, 18% of its host-call time | up to 4 attribute reads per marked file per process |
| 6 | `open` in two host calls, not four | `open`+`close` micro: 7585 `openat`, 7601 `fstat`, 7577 `ioctl`, 7611 `close`; git 8,447 `openat` | `fstat` + `FIONBIO` per open |
| 7 | `pwrite` without `F_GETFL` | SQLite: 22,198 `pwrite64` per run | one `fcntl` per `pwrite` |
| 8 | `fork`: fwe's own host calls around the host `fork` | per fork+exit+wait: 4 `proc_info`, ~10 `__pthread_sigmask`, 3 `kill`, 3 `ulock_wake` more than native | ~75 µs (DTrace time) of the 300 µs gap |
| 9 | `rt_sigreturn` and signal delivery without a host signal | handled `SIGSEGV` 3.0× macOS; JDK takes 300-400 host signals a run | one host signal and `sigreturn` per handled signal |
| 10 | Smaller ones: `rt_sigprocmask` host mask unchanged, `getrusage(RUSAGE_THREAD)`, waits' wake-pipe read and timer arming, mappings published lazily | hundreds per run, or not in the logged workloads | 1-3 host calls each |

Already answered in-process, nothing to gain: `getpid`, `gettid`, `getuid`
and the other ids (48 ns, 0.3× macOS, L1:1242; glibc stopped caching the
pid in 2.25, so these are real calls on Linux too, O8; gVisor answers them
in the Sentry as fwe does, O8), `getrandom`
(`arc4random_buf`, a user-space generator,
`docs/linux-on-macos.md:1467`), a `FUTEX_WAKE` that finds no waiter (no
host call, `crates/kernel/src/futex.rs:878-886`), and `rt_sigprocmask`
itself (no host call at the call, `docs/linux-on-macos.md:1082`; see 10a).
`sched_yield` must reach the host scheduler (`std::thread::yield_now`,
`crates/kernel/src/syscalls.rs:1107-1110`, the `swtch_pri` trap: 717 calls,
3.4 µs each under DTrace, L2:937); there is nothing to answer in-process.

---

## 1. A vDSO for the clocks

**The call and how often.** Linux programs read the clock through the
vDSO, a small ELF library the kernel maps into every process
(`AT_SYSINFO_EHDR`), which reads the counter and a data page and never
enters the kernel. fwe has none (`docs/linux-on-macos.md:1585-1586`, and
`:309-310`: "With no vDSO, `clock_gettime` and `gettimeofday` are real
system calls"), so every clock read is a system call:

- JDK javac: `113: 86431 (29 ms)` (L1:874), `113: 87823 (196 ms)` (L2:875),
  `113: 84233 (45 ms)`, `85788 (74 ms)`, `86494 (35 ms)` (L0a, L0b, L0c);
- JDK java (words, primes, matrix, bank): `113: 27162 (8 ms)` (L1:874),
  `26870 (59 ms)` (L2:875), 26,718-28,321 in L0a-L0c;
- in the `--strace` run, `clock_gettime` is the JDK's most frequent call:
  110,858 of 166,207 (L1:873) and 114,632 of 192,226 (L2:874);
- Node.js: `113: 28460 (28 ms)`, `23774 (20 ms)` (L1:1078-1079), 30,345 and
  30,426 in L0c; 13,203 of 27,218 calls in the `--strace` run (L1:1020);
- Lua script: 8 (L2:604). Go programs (podman, containerd, Docker) read the
  clock through the vDSO in their runtime's scheduler; no Go program is in
  the benchmarks, so their count is not measured.

**What fwe does now.** The libc's `svc` is rewritten to a branch to the
gate (`crates/native/src/gate.rs:1-23`). `fwe_gate_call`
(`crates/native/src/trap.rs:379-498`) checks seccomp, ptrace and the call
kind, reads the guest mask, runs `reroute_parked` (`trap.rs:448-449`;
clocks are a "glance", so it looks at the host at most every 100 µs,
`trap.rs:119-131,195`), then `KERNEL.syscall`, which takes the kernel
lock's shared side (`crates/kernel/src/klock.rs:211-222`, `166-188`) and
runs `dispatch_shared` (`crates/kernel/src/syscalls.rs:996-1030`): it
checks the reaper watcher and Landlock, publishes the process's mappings if
they changed since the last non-memory call (`maps::flush_before`,
`crates/kernel/src/maps.rs:812-842`), then `sys_clock_gettime`
(`syscalls.rs:2672-2691`) maps the clock (`crates/kernel/src/host.rs:155-170`:
`CLOCK_MONOTONIC`, `_COARSE`, `BOOTTIME` all to macOS's `CLOCK_MONOTONIC`),
calls the host libc's `clock_gettime` into fwe's memory and copies the
result out with the checked copy. Then the gate compares 30 registers and
returns.

**What it costs now.** No host system call (macOS's libc reads the time
from the commpage; `clock_gettime` never appears in the DTrace lines), but
fwe's own path: the marks give 335 ns a call in L1 (29 ms / 86,431), 2.2 µs
in L2 (196 ms / 87,823), 0.5-0.9 µs in L0a-L0c, against 48 ns for a whole
`getpid` through the gate (L1:1242). Per JDK run that is 29-196 ms of
thread time for javac and 8-59 ms for java; javac alone took 1.14 s under
fwe against 0.56 s natively in L1:1013 and 2.12 s against 0.75 s in
L2:1014. The spread between runs, with the same call count, points at
waits rather than work: the shared side of the kernel lock steps back and
takes the writers' mutex whenever an exclusive call (an `mmap`, `munmap`,
`mprotect`) is in progress (`klock.rs:175-187`), and L1 shows gate calls
blocked there for 5,128 µs, 2,365 µs, 1,366 µs and 1,335 µs ("JDK java:
into __psynch_mutexwait 5128 us: ... klock ... Lock ... shared+0xb0 <
fwe`fwe_gate_call+0x620", after L1:937). Which call each wait was is not
in the log; a clock read is the most frequent call that takes that path.
A first `clock_gettime` after an `mmap` also pays for publishing every
mapping record (`maps.rs:832-842`; `maps::publish_now` and
`maps::snapshot` 0.9-1.8% of a JDK thread's samples, L1 "JDK javac: thread
108940/108941").

macOS's own `CLOCK_MONOTONIC` is not Linux's either: see the outside facts
below (microsecond steps, sleep included, O1).

**How it could be done in-process.** Map a vDSO image into each guest (as
fwe already maps its `rt_sigreturn` trampoline page,
`crates/native/src/lib.rs:914-945,1268-1288`), put `AT_SYSINFO_EHDR` in the
auxiliary vector, and list it as `[vdso]` in `/proc/<pid>/maps`. It
exports what Linux's arm64 vDSO exports (`__kernel_clock_gettime`,
`__kernel_gettimeofday`, `__kernel_clock_getres`, `__kernel_rt_sigreturn`,
version `LINUX_2.6.39`), which glibc, musl and Go look up by name. Two
sound ways to compute the time, both coherent with the host by
construction because they read what the host kernel itself keeps current:

- **(a) The guest's vDSO reads what macOS's libc reads.** `CNTVCT_EL0`
  (readable at EL0 on macOS: fwe already reads it, `trap.rs:186-194`) plus
  the commpage's timebase offsets gives `mach_absolute_time` (stops in
  sleep: Linux's `CLOCK_MONOTONIC`) and `mach_continuous_time` (counts
  sleep: Linux's `CLOCK_BOOTTIME`); the commpage's time-of-day record,
  read under its generation count as macOS's `gettimeofday` does, gives
  `CLOCK_REALTIME`. The host kernel rewrites these when the clock is set or
  slewed, so an answer cannot be stale; the generation check retries a read
  that raced an update, as Linux's vDSO retries on its sequence count.
  macOS's own reader also gives up when the record is older than a second
  or its counter mode is not one it reads (O2-O4); the vDSO must make the
  system call in those cases too, and read the counter the commpage's mode
  byte names (`CNTVCT_EL0` after `isb`, `CNTVCTSS_EL0` or `ACNTVCT_EL0`). The
  commpage layout is not API: fwe would check the commpage version at start
  and map no vDSO for a layout it does not know (programs then fall back to
  the system call, as without a vDSO today).
- **(b) The vDSO branches to fwe's own code**, which calls the public
  `mach_absolute_time`, `mach_continuous_time` and
  `clock_gettime_nsec_np(CLOCK_REALTIME)` and returns, without saving the
  guest's state, taking no lock and making no system call. No layout
  dependence, a few more nanoseconds. A signal landing in it lands as in
  guest code (the code is reentrant and async-signal-safe, as Linux's
  vDSO is).

In both, the CPU-time clocks (`CLOCK_PROCESS_CPUTIME_ID`,
`CLOCK_THREAD_CPUTIME_ID`, the negative per-thread ids) and unknown ids fall
back to the system call, as Linux's vDSO does; that fallback `svc` is fwe's
own and calls the gate directly. What must stay coherent beyond the time
itself: `/proc/<pid>/maps` and core dumps list `[vdso]`; `execve` maps it
again; a fork child keeps it at the same address; the JIT treats calls into
it as calls into prepared code (`docs/jit.md`); glibc's arm64 signal
return then comes from the vDSO's `__kernel_rt_sigreturn` as on Linux
(glibc sets no restorer of its own, O7), which can replace fwe's trampoline
page (`crates/kernel/src/signal.rs:739-742`); seccomp and `--strace` do
not see vDSO reads, which is Linux's behaviour too. Time namespaces are not
planned (ROADMAP.md "Not planned"), so the vDSO needs no per-namespace
offset.

**Prior art.** gVisor's Sentry maps a vDSO of its own that answers
`REALTIME`, `MONOTONIC`, their coarse forms, `MONOTONIC_RAW` and `BOOTTIME`
from `CNTVCT_EL0` and a parameter page the Sentry rewrites under a
sequence count once a second (O9-O12): way (a) with fwe's own parameters
instead of the host's. FEX's guest vDSO forwards the clock calls to the
host's vDSO in-process (O14): way (b). Wine answers
`NtQueryPerformanceCounter` in-process from `mach_continuous_time` on macOS
(O17). QEMU user mode's arm64 vDSO only makes the system call (O13), so it
saves nothing; WSL1 had a vDSO, how it computed the time was not found
(O15); Darling, macOS on Linux, leaves the commpage's time empty so macOS
programs fall back to the system call (O16): the opposite of what is
proposed here.

**Expected gain and risk.** Removes 85-115k gate entries per JDK run and
24-30k per Node.js run, and with them the kernel lock and the waits behind
writers seen above: 29-196 ms of thread time per javac run, 8-59 ms per
java run, 20-33 ms per Node.js run. A vDSO read on Linux arm64 costs tens
of nanoseconds (not measured here; a micro benchmark `clock_gettime (ns)`
should be added to the table, under fwe, macOS and Linux). Bonus: Linux's
clock meanings (`MONOTONIC` without sleep, `BOOTTIME` with it, nanosecond
steps) instead of macOS's. Risks: (a) depends on a private layout, guarded
by the version check; (b) runs host libc code on the guest's stack (a few
hundred bytes; macOS's time functions use no TLS beyond `errno`, which they
do not set on success). Either needs the fault and signal handlers to treat
the vDSO's pages as guest code.

## 2. Futex queues

**The call and how often.** Futex counts depend on contention, so they vary
from run to run: the JDK java program (its Bank part uses `ReentrantLock`,
`tools/bench/workloads/jdk/Bank.java:13`, so `LockSupport.park`/`unpark`
and so `futex`) made `98: 172903 (21852 ms)` (L1:874), `233742 (41588
ms)` (L2:875), 359,626, 294,266 and 46,353 (L0a-L0c); javac 6,784-9,939.
The summed time includes the waits. The host saw far fewer sleeps:
`ulock_wait2 2862x` and `ulock_wake 2257x` for JDK java (L2:937), so most
futex calls are wakes and waits that do not sleep on the host. Bank: 866 ms
under fwe against 746 ms natively (L1:1016-1017), 1240 ms against 1577 ms
in L2:1017-1018.

**What fwe does now.** Private futexes are in-process
(`crates/kernel/src/futex.rs:1-13`): one table for the whole process, a
`Mutex<HashMap<u64, VecDeque<Arc<Waiter>>>>` (`futex.rs:127-141`), locked
by every wait and wake (`futex.rs:730-732`, `878-886`) through `shortlock`,
which spins 20 µs and then sleeps on a host mutex
(`crates/kernel/src/shortlock.rs:11-27`). Rust's `std::sync::Mutex` is a
pthread mutex on macOS (Rust's `library/std/src/sys/sync/mutex/mod.rs`, the
`target_family = "unix"` arm), so a contended lock is a `psynch_mutexwait`
host call. A wait allocates two `Arc`s and asks for its thread's wake pipe
(`futex.rs:740-742`, `44-50`). A sleeping waiter wakes every 20 ms
(`SIGNAL_CHECK`, `futex.rs:721`, `770-774`) to look for a signal, re-taking
the table lock each time (`futex.rs:784-786`). A waiter that leaves early
walks every queue of the process (`leave`, `futex.rs:810-820`).

**What it costs now.** L2's JDK java (L2:969-980) shows threads blocked on
the table's mutex for 13,796 µs and 7,817 µs in `wait_private_bits`
(+0x6e4 is the re-lock after a sleep, +0x48 the first lock) and 4,781 µs in
`wake_private_bits`; L1 shows 4,444 µs, 3,254 µs and 1,306 µs (after
L1:937). Over the whole javac run fwe's process spent `psynch_mutexwait
1869x 670.2 ms` (L2:876) and `670x 72.4 ms` (L1:875), against `527x 101.3
ms` and `423x 65.4 ms` for the native JVM (L2:910, L1:909); those totals
include the JIT's lock (`jit::lock_state`, a separate subject, see
`docs/jit.md`) and the kernel lock (3). How much of the futex time is the
20 ms polls is not measured; an idle JVM has a dozen or more threads parked
for the whole run (GC, compiler, reference handler, timers), each woken 50
times a second, each wake a host `ulock_wait2` return, a context switch
and a table lock taken against the busy threads.

**How it could be done in-process.** Hash the address into a fixed array
of buckets, each with its own lock and waiters, as gVisor's Sentry does
with 1024 buckets keyed by the address alone for private futexes (O18), and
Linux does; give each bucket an atomic count of its waiters so a wake that
finds 0 returns without any lock, as Linux's `futex_hb_waiters_pending`
does (`kernel/futex/`, O19; gVisor has no such shortcut, O18). Give each thread one waiter record,
made once, instead of two allocations per wait. Replace the 20 ms poll by a
wake from the signal side: a signal recorded for a thread (or for the
process, to every thread that does not block it) sets the waiter's park
word and wakes it (`ulock_wake` on that word), as Linux's
`signal_wake_up` wakes an interruptible sleeper (O19). The public form of
the host primitive is `os_sync_wait_on_address`/`os_sync_wake_by_address_*`
(macOS 14.4, O22), which fwe's private `__ulock_*` calls could become. Nothing here talks to the host beyond
the sleeps and wakes themselves; what must stay coherent is the order
between the word's value and the queue, which bucket locks keep exactly as
the one table lock does now (compare under the lock the waker takes,
`futex.rs:733-739`). A requeue between two buckets takes both, in address
order.

**Expected gain and risk.** Not measured: add a futex micro benchmark (a
wake with no waiter; two threads passing a lock back and forth; N idle
waiters plus a contended pair) and count, per run, the table-lock waits
and the 20 ms poll wake-ups. The upper bound visible in the logs is the
`psynch_mutexwait` excess of fwe over the native JVM (up to ~570 ms per
javac run in L2, shared with the other locks). Risk: futexes are where
lost wake-ups hide; the signal-wake path must cover every way a signal is
recorded (host signal, `tgkill`, mailbox, timers) or a waiter sleeps
through it, so the 20 ms poll should go only once a test proves each path
wakes the sleeper.

## 3. The id, time and yield calls without the kernel lock

**The call and how often.** Every call `shares` names
(`crates/kernel/src/syscalls.rs:139-175`) takes the kernel lock's shared
side, including those that read no kernel state: the clocks (1), `getpid`,
`gettid`, `getppid`, `getuid` and the other ids, `sched_yield`, `getcpu`,
`getrandom`, `rt_sigprocmask`, `sigaltstack`. JDK: ~113k such calls per run
(1); Node.js `getpid` 285 (L1:1020); SQLite `getpid` 6.

**What fwe does now.** The shared side costs one counter of the thread's
own while no writer is in (`klock.rs:166-177`). When a writer is in or
waiting (any exclusive call: `mmap`, `munmap`, `mprotect`, `openat`,
`close` ...), the reader steps back and queues on the writers' pthread
mutex (`klock.rs:178-187`), and the writer spins for every reader to drain
(`klock.rs:130-160`).

**What it costs now.** L1's JDK java samples show gate calls stuck there for
1.3-5.1 ms (see 1). The id calls themselves cost 48 ns when not blocked.

**How it could be done in-process.** Answer in the gate's Rust half, before
`KERNEL.syscall`, every call that reads only thread-locals and the
process's published identity: time (when no vDSO is used: raw `svc` in
static programs, or old libcs), ids (fwe already keeps them outside the
kernel: `thread::tid`, `thread::tgid`), `sched_yield`, `getrandom`,
`getcpu`. The values they return are already kept where readers need no
lock. What must stay coherent: a pid namespace change (`unshare`/`setns`
of a pid namespace affects children only, so the caller's own ids do not
change), credentials (`getuid` and friends read `creds`, published by
exclusive calls through `creds::publish`, `crates/kernel/src/creds.rs:212`,
already readable without the kernel lock), and seccomp, ptrace and
`--strace`, which still see every call because the gate checks them first
(`trap.rs:423-427`). `maps::flush_before` need not run for these calls:
they do not let another process observe mappings.

**Expected gain and risk.** Removes the multi-millisecond stalls behind
writers for these calls; it is also a precondition for keeping
`clock_gettime` cheap for programs that do not use the vDSO. Low risk: these
calls read nothing the exclusive side changes under them.

## 4. The parked-signal look

**The call and how often.** Host `sigpending`: JDK javac `3989x 3.2 ms (795
ns)` (L1:875), `10807x 14.3 ms` (L2:876); JDK java `6984x 8.6 ms` (L1:936),
`12088x 12.7 ms` (L2:937). Not in the top twelve host calls of the other
workloads.

**What fwe does now.** At each gate call, if the thread's guest mask blocks
a signal the guest catches, `reroute_parked` (`trap.rs:178-220`) asks the
host which signals are pending (`host::pending_signals`,
`crates/kernel/src/host.rs:679-693`). A "glance" (ids, clocks, futex wakes,
`trap.rs:119-131`) looks at most every 100 µs (`trap.rs:114,195`); every
other call (a futex wait, `mmap`, `read` ...) looks every time. The reason
(`trap.rs:150-177`, `docs/architecture.md:658-664`): macOS parks a
process-wide signal on one thread for good when every thread blocks it,
which happens only while every thread is in fwe's handlers.

**How it could be done in-process.** The look is needed only if a signal
can have arrived while every thread blocked it. fwe's handlers start and
end with every signal blocked (`docs/architecture.md:654-656`), so fwe can
count, in one process-wide atomic, the threads inside its handlers against
the number of threads; when a handler entry makes the two equal it bumps a
"may be parked" generation. A thread looks only when that generation
changed since its last look (one atomic load in the common case). What must
stay coherent: thread creation and exit change the thread count (counted
under the same atomic), and a thread parked in the pool with all signals
blocked (`docs/architecture.md:398-401`) counts as blocking.

**Prior art.** QEMU user mode keeps the guest mask in-process and blocks
host signals only around its own critical sections, delivering a queued
signal before the guest runs again (O24); gVisor stores the mask in an
atomic of the task with no host call (O23). Neither has macOS's parking
behaviour to work around.

**Expected gain and risk.** 4-12k host calls per JDK program run, 3-14 ms
of DTrace time. Risk: a signal kept parked is a hang; the counting must be
exact around thread start and exit. A test that sends a process-wide
signal while all threads are in handlers already has to exist for the
current design; it would judge this one.

## 5. Kept metadata read once per file, shared across processes

**The call and how often.** Host `fgetxattr`: git log -p `557x 6.7 ms
(12046 ns)` of 36.5 ms host time (L2:771), git status `285x 2.7 ms (9648
ns)` (L2:694), git commit `336x 2.6 ms (7778 ns)` (L2:722), clang -c
`187x 1.3 ms (6735 ns)` (L2:547). Native git makes none (L2:750).

**What fwe does now.** A file whose host flags mark kept metadata
(`modes::marked`, `crates/kernel/src/modes.rs:252-254`: a mode that denies
the owner, such as git's read-only objects, an owner other than the user,
set-ID bits) has its guest mode, owner and flags in extended attributes,
one each: `org.fwe.mode`, the owner, `org.fwe.nodump`, `org.fwe.noatime`
(`modes.rs:578`, `crates/kernel/src/owners.rs:183-189`, `modes.rs:384-389`).
A `stat` or `open` of such a file reads up to four of them
(`modes::nodump_fd`, `modes.rs:287-293`). The answers are cached per
process, keyed by device, inode and change time, 4096 files at most
(`modes.rs:196-235`), so each new process (git runs many) reads them again.

**How it could be done in-process.** Keep the cache in the process store
every fwe process maps (as the prepared-image and translation caches are
shared), under the same key. The key includes `st_ctime`, which the host
updates when an attribute is set or removed (to be verified on APFS with a
unit test before relying on it), so a cached answer cannot outlive a
change: the `stat` that fetches the key is already made for the call. And
read the four in one attribute (or one `flistxattr` plus one read), for
files fwe marks from now on.

**Expected gain and risk.** git log -p: most of 6.7 ms of 36.5 ms host time;
git status and commit about 2.6 ms each. Risk: low with the change time in
the key; a writer outside fwe that changes the attribute without changing
`ctime` is not possible on the host's own filesystems (to verify).

## 6. `open` in two host calls

**The call and how often.** `open`+`close` micro: `openat 7585x (6962 ns),
fstat64 7601x (915 ns), close 7611x (758 ns), ioctl 7577x (751 ns)` (L2:441);
7409 ns under fwe against 5750 ns on macOS (L1:1250). git: 8,447 `openat`
(L2:689); clang -c: 666 host `openat` (L2:547).

**What fwe does now.** The one-call open of a path to read
(`crates/kernel/src/fs.rs:3299-3328`) opens with `O_NONBLOCK` (so a FIFO
does not block the open), `fstat`s the descriptor to see it is a plain
file, then clears `O_NONBLOCK` with `ioctl(FIONBIO)`.

**How it could be done in-process.** For a regular file or a directory,
`O_NONBLOCK` changes nothing on the host's reads and writes; keep it on the
host descriptor and report the guest's own flags from fwe's descriptor
record (`F_GETFL` answers the guest's flags, `F_SETFL` changes the record
and the host only where it matters). The `fstat` stays while nothing else
knows the file's type; with the directory cache of ROADMAP M6 PR 3 the
type of a cached name is known and the `fstat` can go too, its result made
when the guest asks for it (`fstat` after `open` is common: Python, git).
What must stay coherent: a descriptor passed to a host process that is not
fwe (`SCM_RIGHTS` to a macOS program) would carry `O_NONBLOCK`; for
regular files and directories macOS ignores it (to be verified for network
filesystems, where a client may not).

**Expected gain and risk.** One host call per open (`ioctl`), two with the
directory cache; the micro's `ioctl` and `fstat` are 18% of its DTrace
host time. ROADMAP M6 PR 3 already sets the target (`open`+`close` at 1.1×
macOS); this is one concrete step. Risk: low for local files.

## 7. `pwrite` without `F_GETFL`

**The call and how often.** SQLite: `22198 pwrite64` per run (L2:661),
`fcntl 9455x 4.1 ms (430 ns)` among its host calls (L2:666), 22,307 of them
the guest's own lock calls.

**What fwe does now.** Every `pwrite64` to a file with no tmpfs size limit
asks the host for the descriptor's status flags to honour Linux's
`O_APPEND` rule (`crates/kernel/src/lib.rs:2313-2315`); `tmpfs::room` and
`memfd::grow_refused` do the same on their paths
(`crates/kernel/src/tmpfs.rs:354`, `crates/kernel/src/memfd.rs:171`).

**How it could be done in-process.** Keep `O_APPEND` per open file in
fwe's descriptor record, set at `open`, `F_SETFL` and on adoption (a
descriptor inherited at start or received over `SCM_RIGHTS` is asked once).
What can make it stale: another process that shares the open file
description changing `O_APPEND` with `F_SETFL`; a shared generation in the
process store, bumped by `F_SETFL` of a shared description, lets the
reader re-ask when it moved.

**Expected gain and risk.** One host call per `pwrite` (~22k per SQLite
run, at most ~9 ms of DTrace time). Low risk.

## 8. `fork`: fwe's own host calls

**The call and how often.** `fork`+exit+wait micro: 526 µs under fwe,
228 µs on macOS (L1:1247). xz: 17 forks per run, git status 12, git commit
6 (L2:800, 694, 722).

**What fwe does now and what it costs.** The host `fork` itself costs more
in fwe's process (`fork 570x 452.2 ms (793364 ns)` against `817x 314.9 ms
(385464 ns)` natively, L2:491, 517), which ROADMAP M6 PR 4 ("fewer mappings
to fork") addresses. Beside it, per fork+exit+wait the fwe run makes host
calls the native run does not (L2:491 against L2:517, divided by 570 and
817 forks): `proc_info` 4.0 per fork (2289x, 4.0 µs each), `__pthread_sigmask`
10.0 (5716x, 1.3 µs), `kill` 3.0 (1715x, 3.0 µs), `ulock_wake` 3.0
(1716x, 6.8 µs), `read` 1.0 (575x, 16 µs): about 75 µs of DTrace time per
fork, of a 300 µs gap. One `proc_info` is `host::only_thread`
(`crates/kernel/src/lib.rs:1446`, `host.rs:2350-2365`); the others are not
attributed in the log.

**How it could be done in-process.** Answer from fwe's records what the host
is asked: whether the process has one host thread (fwe knows its own
threads; host threads it did not make, a framework's, would have to be
counted when made), whether a child is alive (`procreg::alive`,
`crates/kernel/src/procreg.rs:1608-1640`, asked of the host by
`proc_pidinfo`; fwe's own child-exit notification can answer for its
children); and send the mask once rather than around each step.
Attribution first: count host calls by fwe function around a fork (the
DTrace run already has user stacks for `psynch_mutexwait`; the same for
`proc_info`, `kill`, `__pthread_sigmask`).

**Expected gain and risk.** Up to ~75 µs per fork (DTrace time; real time
not measured). Risk: liveness answered from fwe's records must not report
a process that the host has already ended.

## 9. Signal delivery and return without host signals

**The call and how often.** A handled `SIGSEGV`: 5.27 µs under fwe, 1.75 µs
on macOS (L1:1252). JDK: host signals `4: 2, 5: 193, 10: 97, 11: 10` per
program run (L1:874); 300-400 a run, about 2 ms at 5 µs each. Not a
dominant cost in the logged workloads; it matters for runtimes that take
faults on purpose (a JVM's safepoint polls and null checks, garbage
collectors' barriers), not measured.

**What fwe does now.** A guest handler is entered from a host signal; it
returns through `rt_sigreturn` from the restorer or fwe's trampoline
(`crates/native/src/lib.rs:914-945`, `crates/kernel/src/signal.rs:739-741`),
whose `svc` is a trap, so the return is a second host signal (`SIGTRAP`),
its handler and a host `sigreturn`. Any gate call that changes more than
`x0`, or has a signal to deliver, also takes the trap
(`gate.rs:12-17`, `trap.rs:486-497`).

**How it could be done in-process.** ROADMAP M6 PR 4 plans `rt_sigreturn`
through the gate. The gate already restores a full register state for the
exit gate's way into translations (`gate.rs`, `fwe_exit_gate`); the same
restore, with the signal mask set from the frame (one `pthread_sigmask`
only when the host mask changes, see 10a), serves `rt_sigreturn` and
delivery at a call's return. For synchronous faults the host signal stays
(the hardware fault is the host's), so a handled fault drops from two host
signals to one.

**Prior art.** gVisor builds and reads the signal frame in guest memory and
returns through its vDSO's `rt_sigreturn` as an ordinary system call to the
Sentry (O23); QEMU user mode restores registers and mask from the guest
frame in-process (O24). Published macOS signal-delivery costs: not found;
the 1.75 µs macOS figure above is fwe's own micro benchmark.

**Expected gain and risk.** About half of the 3.5 µs gap per handled signal
(one host signal and `sigreturn`, ~1.75 µs by the macOS figure). Small on
the logged workloads.

## 10. Smaller items

**10a. `rt_sigprocmask` when the host mask does not change.** After a call
that changes the guest mask, the gate sets the host mask
(`trap.rs:478-482`, `apply_guest_mask` at `trap.rs:241-246`), one
`pthread_sigmask` (1.3 µs under DTrace, L2:491). The host mask is the guest
mask minus the signals the guest catches (`host::host_mask_for`,
`host.rs:602-604`), so a program that blocks only signals it catches (a
runtime around a critical section) changes the guest mask but not the host
one. Keep the last host mask applied in a thread-local and skip the call
when equal. JDK 426-429 calls a run (L1:873, L2:874), xz 170, Python 11:
under 1 ms per run.

**10b. `getrusage(RUSAGE_THREAD)`.** fwe calls the host's
`getrusage(RUSAGE_SELF)` (which sums every thread of the task) for the
largest resident size, then `thread_info` through `pthread_mach_thread_np`
for the thread's times (`syscalls.rs:1113-1149`, `host.rs:180-208`).
JDK: 770-1,212 a run (marks, `165:`). Only `ru_maxrss` needs the first
call; `proc_pid_rusage` or `task_info` give it for the task alone; whether
cheaper is not measured.

**10c. Waits.** Every sleep, `poll`, `select`, `epoll` wait and near-deadline
futex nap (`crates/kernel/src/thread.rs:219-285`, `306-332`) reads its
wake pipe once (a host `read` that usually returns nothing), arms its
kqueue timer (`kevent`, `thread.rs:334`) and `poll`s: three host calls
where Linux makes one. A thread-local "poked" counter, bumped before a
signal or wake writes the pipe, lets the wait skip the `read` when
unchanged; the timer could be one change in the same `kevent` call that
waits, if the wait were a `kevent` on the thread's kqueue holding the pipe
and the guest's descriptors (for `epoll`, which is a kqueue already,
`crates/kernel/src/epoll.rs:1-24`). JDK `poll` 24-42 a run (L1:875, 936):
small here; event loops (Node.js, lighttpd) are where it would count, not
measured.

**10d. Mappings published when someone asks.** After a run of mapping calls
the next non-memory call publishes the whole mapping list to the process
store (`maps.rs:795-842`), for another process's `/proc/<pid>/maps`. No host
call, but CPU on a hot path (0.9-1.8% of a JDK thread's samples, L1 "thread
108940/108941"). A generation number in the store, bumped by the mapping
calls, would let a reader ask the owner to publish (wake signal) only when
it reads. Not a host round trip.

**10e. Gate traffic from instruction-cache flushes.** The JDK's generated
code flushes 60,699-124,868 cache lines per program run (L1:874, L2:875),
each a gate entry that takes the JIT's state lock (`trap.rs:398-409`,
`crates/native/src/jit.rs:1579-1588`): more gate entries than
`clock_gettime`. No host call; it belongs to the JIT's work
(`docs/jit.md`), named here because it is the largest gate traffic in the
logs.

## macOS slow paths fwe meets without asking for them

- **Contended pthread mutexes.** Rust's `Mutex` is a pthread mutex on macOS
  (Rust std `library/std/src/sys/sync/mutex/mod.rs`); contention becomes
  `psynch_mutexwait`/`psynch_mutexdrop` host calls, from either of
  libpthread's policies, first-fit (the default) or fair-share (O20, O21) (javac: 1869 waits,
  670.2 ms, L2:876). The stacks name three of fwe's locks: the kernel
  lock's writers' mutex, the futex table, the JIT state (L1 after 937, L2:969-980).
  Spinning first (`shortlock`) helps short holds; sharding (2) and lock-free
  readers (3) remove the waits.
- **macOS's `CLOCK_MONOTONIC` is not Linux's.** See O1:
  libc computes it from the time of day and the boot time, at microsecond
  resolution, counting sleep; fwe maps Linux `CLOCK_MONOTONIC` and
  `CLOCK_MONOTONIC_COARSE` to it (`host.rs:161-164`). Linux programs get
  microsecond steps from a clock whose `clock_getres` fwe reports as 1 ns
  (`syscalls.rs:2704-2730`).
- **CPU-time clocks are host calls.** macOS's libc reads
  `CLOCK_PROCESS_CPUTIME_ID` with `getrusage` and `CLOCK_THREAD_CPUTIME_ID`
  with the private `__thread_selfusage` (O4); fwe's per-thread ids
  (`pthread_getcpuclockid`'s) call `thread_info`, a Mach message
  (`host.rs:180-208`). JDK's `mach_msg2_trap` counts (2433-3873 a run,
  L1:936, L2:876) may include these; not attributed.
- **Sandbox checks on every open.** The open+close micro's kernel samples
  include the sandbox policy evaluated on each open
  (`com.apple.security.sandbox` `eval` under `mac_vnode_check_open`,
  1.0-1.3% each, L1:451-453); native git's stacks show it too (L1:766).
  Every lookup or open fwe answers from a cache (ROADMAP M6 PR 3) also
  skips this.
- **Slow `ioctl`s outside fwe.** A few host `ioctl`s take 0.1-8 ms in both
  fwe and native runs (`ioctl 2x 15.7 ms` in the stat micro, L2:419; native
  JDK `ioctl 10x 10.7 ms`, L2:910; native git commit `52x 22.1 ms`,
  L2:750). Which requests they are is not in the logs; they are the
  runner's or the host libraries', not fwe's.

## Measurements to add before building any of this

PLAN.md's "Counted, not assumed" asks for the counts first:

- micro: `clock_gettime(CLOCK_MONOTONIC)` and `(CLOCK_REALTIME)`;
  `futex` wake with no waiter; a two-thread lock hand-off; `pwrite` 4 KiB;
- counts in the marks: futex by operation (wait, wake, woken, `EAGAIN`,
  timeouts, 20 ms poll returns); kernel-lock and futex-table waits (count
  and time); `sigpending` looks and how many found a parked signal;
  `fgetxattr` per marked file;
- DTrace: user stacks for `proc_info`, `kill`, `__pthread_sigmask` and
  `ulock_wake` in the fork micro, as are already taken for
  `psynch_mutexwait`.

## Outside facts

Gathered from the web for this note; "not found" where no source was found.

- O1. Apple Libc `clock_gettime`: `CLOCK_REALTIME` is `gettimeofday`;
  `CLOCK_MONOTONIC` is `gettimeofday` minus `mach_boottime_usec()` (falling
  back to the `kern.boottime` sysctl), so 1 µs resolution and it counts
  sleep; `clock_getres` reports 1000 ns for it; `CLOCK_MONOTONIC_RAW` is
  `mach_continuous_time`, `CLOCK_UPTIME_RAW` `mach_absolute_time`.
  https://github.com/apple-oss-distributions/Libc/blob/main/gen/clock_gettime.c
- O2. `gettimeofday` tries `__commpage_gettimeofday` first, the system call
  only if that fails:
  https://github.com/apple-oss-distributions/Libc/blob/main/sys/gettimeofday.c ;
  the commpage reader retries while `TimeStamp_tick` changes and fails when
  the tick is 0, the stamp is over a second old, or seconds would overflow:
  https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/__commpage_gettimeofday.c ;
  the record (`new_commpage_timeofday_data_t`: `TimeStamp_tick`, `_sec`,
  `_frac`, `Ticks_scale`, `Ticks_per_sec`):
  https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/commpage.h
- O3. `mach_absolute_time` on arm64 reads the commpage's
  `_COMM_PAGE_USER_TIMEBASE` mode and then `CNTVCT_EL0` (after `isb`),
  `CNTVCTSS_EL0` or `ACNTVCT_EL0`, plus `_COMM_PAGE_TIMEBASE_OFFSET`; with
  mode 0 it traps:
  https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/mach_absolute_time.s ;
  `mach_continuous_time` adds `_COMM_PAGE_CONT_TIMEBASE` (or uses the
  continuous hardware clock):
  https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/mach_continuous_time.c
- O4. Commpage base on arm64 `0x0000000FFFFFC000`; offsets
  `TIMEBASE_OFFSET` +0x88, `USER_TIMEBASE` +0x90, `CONT_HWCLOCK` +0x91,
  `CONT_TIMEBASE` +0x98, `BOOTTIME_USEC` +0xA0, `CONT_HW_TIMEBASE` +0xA8,
  `NEWTIMEOFDAY_DATA` +0x120:
  https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/arm/cpu_capabilities.h .
  `CLOCK_THREAD_CPUTIME_ID` uses `__thread_selfusage`,
  `CLOCK_PROCESS_CPUTIME_ID` `getrusage` (O1's file).
- O5. Apple Silicon timebase 125/3 (41.67 ns a tick):
  https://eclecticlight.co/2020/11/27/inside-m1-macs-time-and-logs/
- O6. Linux arm64 vDSO exports `__kernel_rt_sigreturn`,
  `__kernel_gettimeofday`, `__kernel_clock_gettime`,
  `__kernel_clock_getres` and `__kernel_getrandom`, version
  `LINUX_2.6.39`:
  https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/vdso/vdso.lds.S ;
  data page layout (sequence count, `cycle_last`, `mult`, `shift`, base time
  per clock): https://github.com/torvalds/linux/blob/master/include/vdso/datapage.h
- O7. musl finds the vDSO by `AT_SYSINFO_EHDR` and looks up
  `__kernel_clock_gettime@LINUX_2.6.39` on aarch64, falling back to the
  system call:
  https://git.musl-libc.org/cgit/musl/plain/src/internal/vdso.c ,
  https://git.musl-libc.org/cgit/musl/plain/arch/aarch64/syscall_arch.h ,
  https://git.musl-libc.org/cgit/musl/plain/src/time/clock_gettime.c ;
  glibc's aarch64 vDSO names:
  https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/aarch64/sysdep.h ;
  Linux returns to `sa_restorer` with `SA_RESTORER`, else the vDSO
  trampoline: https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/signal.c ;
  glibc aarch64 sets no restorer of its own:
  https://github.com/bminor/glibc/blob/master/sysdeps/unix/sysv/linux/aarch64/libc_sigaction.c ;
  musl always sets its own `__restore_rt`:
  https://git.musl-libc.org/cgit/musl/plain/src/signal/sigaction.c
- O8. glibc 2.25 removed the pid cache:
  https://man7.org/linux/man-pages/man2/getpid.2.html ; gVisor's
  `Getpid`/`Gettid` are Sentry handlers:
  https://github.com/google/gvisor/blob/master/pkg/sentry/syscalls/linux/sys_thread.go
- O9. gVisor's vDSO (clocks served, others to the system call):
  https://github.com/google/gvisor/blob/master/vdso/vdso.cc ; reads
  `CNTVCT_EL0`: https://github.com/google/gvisor/blob/master/vdso/cycle_clock.h
- O10. Its parameter page sits before the vDSO, read under a sequence count:
  https://github.com/google/gvisor/blob/master/vdso/vdso_time.cc
- O11. The Sentry writes it (`VDSOParamPage.Write`):
  https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/vdso.go ,
  from the timekeeper's updater:
  https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/timekeeper.go
- O12. Update interval 1 s:
  https://github.com/google/gvisor/blob/master/pkg/sentry/time/parameters.go
- O13. QEMU linux-user's aarch64 vDSO makes the system call in each entry:
  https://gitlab.com/qemu-project/qemu/-/raw/master/linux-user/aarch64/vdso.S
- O14. FEX's guest vDSO thunks the clock calls to the host's vDSO:
  https://github.com/FEX-Emu/FEX/blob/main/Source/Tools/LinuxEmulation/VDSO_Emulation.cpp
- O15. WSL1: every system call goes to the pico provider
  (https://learn.microsoft.com/en-us/archive/blogs/wsl/pico-process-overview);
  it had a vDSO (https://bugs.archlinux.org/task/71024); how it computed
  the time: not found.
- O16. Darling fills no time in its commpage:
  https://github.com/darlinghq/darling/blob/master/src/startup/mldr/commpage.c ,
  https://docs.darlinghq.org/internals/macos-specifics/commpage.html .
  Noah (https://github.com/linux-noah/noah): whether it has a vDSO, not found.
- O17. Wine on macOS: `NtQueryPerformanceCounter` from
  `mach_continuous_time`: https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unix/sync.c ;
  `KUSER_SHARED_DATA`'s time written by wineserver after each wake:
  https://github.com/wine-mirror/wine/blob/master/server/fd.c
- O18. gVisor futexes: 1024 buckets, private keys by address, a wake always
  locks its bucket:
  https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/futex/futex.go
- O19. Linux: futex hash buckets and the waiters count
  (https://github.com/torvalds/linux/tree/master/kernel/futex), signal
  wake-up of interruptible sleepers (`signal_wake_up_state`,
  https://github.com/torvalds/linux/blob/master/kernel/signal.c); named from
  the source tree, not re-read for this note.
- O20. libpthread waits in `__psynch_mutexwait` under contention with both
  policies; the default can be changed by `PTHREAD_MUTEX_DEFAULT_POLICY`:
  https://github.com/apple-oss-distributions/libpthread/blob/main/src/pthread_mutex.c
- O21. First-fit against fair-share throughput (Mozilla, 10 threads):
  https://blog.mozilla.org/nfroyd/2017/03/29/on-mutex-performance-part-1/ ;
  `os_unfair_lock` waits in the kernel on contention, no spinning:
  https://developer.apple.com/documentation/os/os_unfair_lock_lock
- O22. `os_sync_wait_on_address` (macOS 14.4):
  https://developer.apple.com/tutorials/data/documentation/macos-release-notes/macos-14_4-release-notes.md ,
  https://github.com/apple-oss-distributions/libplatform/blob/a00a4cc36da2110578bcf3b8eeeeb93dcc7f4e11/docs/expose-futex-style-api.md
- O23. gVisor keeps the signal mask in an atomic of the task, and returns
  through its vDSO's `rt_sigreturn`:
  https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/task_signals.go ,
  https://github.com/google/gvisor/blob/master/pkg/sentry/arch/signal_arm64.go
- O24. QEMU linux-user: guest mask in `ts->signal_mask`, host signals
  blocked around its own work, pending signals delivered before the guest
  resumes; aarch64 `rt_sigreturn` restored in-process:
  https://gitlab.com/qemu-project/qemu/-/raw/master/linux-user/signal.c ,
  https://gitlab.com/qemu-project/qemu/-/raw/master/linux-user/aarch64/signal.c
- O25. Open's MACF hooks (`mac_vnode_check_open` and kauth):
  https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_subr.c .
  Measured costs of the sandbox hook, `fstatat`, `proc_pidinfo`, `sysctl`,
  `kevent` against `poll`, ulock and psynch: not found. Published macOS
  system-call latency on Apple Silicon: not found from a reliable source
  (fwe's own table: `getpid` 139.9 ns on macOS, L1:1242). A per-map-entry
  cost of macOS `fork`: not found.
- O26. Rosetta: `mach_absolute_time` differs between native and translated
  processes:
  https://developer.apple.com/documentation/apple-silicon/addressing-architectural-differences-in-your-macos-code ;
  how Rosetta handles system calls or time: not found.
