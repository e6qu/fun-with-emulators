# Architecture

## Components

```
fwe (crates/fwe)            the command line; end-to-end tests
 ├── native backend (crates/native)
 │    ├── loader       ELF image → host mappings at the guest's addresses
 │    ├── rewrite      in-place patching: svc #0 → brk; sites that need stubs
 │    ├── decode       just enough AArch64 decoding to rewrite x18 uses
 │    ├── prepare      applies rewrite to guest memory, places stubs, flushes caches
 │    ├── stack        the Linux initial stack: argc, argv, envp, auxv
 │    ├── trap         SIGTRAP/fault/signal handlers → kernel → resume guest
 │    ├── threads      clone: a host thread per guest thread
 │    ├── process      fork and vfork, execve, wait4, waitid
 │    ├── hwcap        AT_HWCAP/AT_HWCAP2 from the host CPU
 │    └── hv           the hypervisor backend feasibility spike
 ├── kernel layer (crates/kernel)
 │    Linux system call semantics on top of the host, behind `Platform`
 ├── elf (crates/elf)   ELF64 parsing and load planning, host-independent
 └── abi (crates/abi)   Linux arm64 ABI numbers and layouts (partly generated)
```

The kernel layer does not depend on how guest code runs. An execution backend
traps guest system calls, calls `Kernel::enter_syscall` with the guest's
register file, and provides the few services the kernel needs through the
`fwe_kernel::Platform` trait (preparing code for execution, ending a thread
or the process, setting how the host treats a signal). Two backends share
it:

- The **native backend** runs guest code in-process, directly on the CPU,
  after rewriting the instructions macOS cannot let a Linux process execute
  unchanged. It carries every position-independent binary.
- The **hypervisor backend** (a feasibility spike today, see
  [hypervisor-spike.md](hypervisor-spike.md)) runs the guest in a
  Hypervisor.framework VM. It exists only for non-PIE executables linked
  into the low 4 GiB that macOS reserves, which the native backend cannot
  map. A full virtual machine with its own Linux kernel is a non-goal.

## Hosts

The kernel, ELF and ABI crates build on any Unix host; the `libc` crate
supplies host values, and on a Linux host most translations are the identity
(system calls that take the same arguments pass straight through). CI runs
the unit tests on Linux as well as macOS. The native backend, and so the
`fwe` command, runs only on macOS on Apple Silicon.

## Memory model

Guest addresses are host addresses. The native backend maps guest memory at
the guest's own virtual addresses inside the `fwe` process, so guest pointers
are used directly and, where layouts match, handed straight to macOS system
calls, which validate them.

Whatever the kernel layer reads or writes of guest memory itself goes
through `crates/kernel/src/uaccess.rs`: typed reads and writes, strings and
string arrays, raw byte ranges. The copies run in a small assembly routine;
when one of its accesses faults, the backend's fault handler resumes it at a
recovery point (the scheme Linux's exception tables use), and the system
call fails with `EFAULT` instead of crashing fwe. A pointer handed straight
to a host system call is checked by the host. A few macOS C library
functions do their work in user space (`clock_gettime`, `gettimeofday`,
`nanosleep`), so those results go through fwe's memory and the checked
copies too.

The guest sees the host page size (16 KiB on Apple Silicon) through
`AT_PAGESZ`, which the arm64 Linux ABI permits.

Every range of guest memory — the loaded images and their code stubs, the
stack, the break reservation and whatever the guest maps — is recorded
(`fwe_kernel::mm::track`), and removed when the guest unmaps it. fwe's own
memory (its heap, thread and signal stacks, the `rt_sigreturn` trampoline)
never is, so `execve` can discard exactly the old program.

macOS gives every arm64 process a mandatory 4 GiB `__PAGEZERO`; on Apple
Silicon the kernel refuses to launch a process with a smaller one.
Position-independent executables are loaded anywhere, and `ET_EXEC` images
linked above 4 GiB at their own addresses. An `ET_EXEC` image linked below
4 GiB (non-PIE C and Rust at `0x200000` or `0x400000`, Go at `0x10000`,
Debian's `python3.11` at `0x400000`) cannot be mapped at its address
in-process, and carries no relocation information to move elsewhere. The
loader rejects it with a clear error; the hypervisor backend is the path for
it.

## Loading

The loader parses the ELF image, plans each `PT_LOAD` segment onto host pages
and maps them at the guest's addresses (a PIE at a base the host picks). Code
is mapped writable first, rewritten (below), and then given its final
protections. Space for out-of-line stubs is reserved right after the image,
within branch range of it.

A dynamically linked executable names an interpreter in `PT_INTERP`
(`/lib/ld-linux-aarch64.so.1` for glibc, `/lib/ld-musl-aarch64.so.1` for
musl). The path is resolved through the rootfs, the interpreter is loaded
too, and the guest starts at the interpreter's entry. The auxiliary vector
carries `AT_BASE` (the interpreter's load base), `AT_ENTRY` (the executable's
entry) and `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`, as Linux provides them, plus
`AT_HWCAP`/`AT_HWCAP2` from the host CPU, `AT_PAGESZ`, `AT_RANDOM`, the ids
and `AT_MINSIGSTKSZ`. The interpreter maps the program's shared libraries
itself through our `openat` and file-backed `mmap`, and self-relocates,
resolves relocations and sets up the thread pointer exactly as on Linux. This
runs real, unmodified glibc and musl: musl's linker is itself the libc, one
object; glibc's `ld-linux-aarch64.so.1` is separate and maps `libc.so.6` at
run time.

The initial stack is laid out as the Linux kernel does at `execve`: the
strings, the random bytes, the auxiliary vector, `envp`, `argv` and `argc`,
16-byte aligned, on a fresh 8 MiB stack with a guard page.

## Rewriting guest code

Before any guest code becomes executable — the loader's images, and every
`mmap`/`mprotect` with `PROT_EXEC` — the native backend rewrites three
things. arm64 instructions are 4-byte aligned words, so scanning aligned
words finds every instruction exactly.

- **`svc #0`** (a Linux system call) would enter the macOS kernel. It becomes
  `brk #0x4c58`, whose `SIGTRAP` our handler services.
- **`mrs`/`msr` of `TPIDR_EL0`** (the Linux thread pointer): macOS keeps
  its own per-thread data there and does not preserve it for user code. Each
  access becomes a branch to a short stub that reads or writes the guest
  thread pointer in a slot of the host thread's TSD, located through
  `TPIDRRO_EL0` (per-thread and read-only to user code).
- **Any instruction naming `x18`.** Linux treats `x18` as a scratch
  register; macOS reserves it and clears it on every exception return,
  including involuntary preemption, which nothing can intercept. So guest
  state must never live in the hardware `x18` between instructions. Each
  such instruction is redirected to a stub that keeps the guest's `x18` in a
  per-thread TSD slot: the stub saves two scratch registers below `sp`
  (Linux arm64 has no red zone), reads the slot into one, runs the
  instruction with `x18` replaced by that scratch, writes the slot back if
  the instruction wrote `x18`, restores the scratch registers and branches
  back. macOS preserves every other register across preemption, so an
  ordinary scratch register is safe.

  `crates/native/src/decode.rs` decides which instructions are covered:
  the register-only data-processing classes (move wide, add/sub in the
  immediate, shifted- and extended-register and with-carry forms, logical,
  bitfield, extract, conditional select and compare, one-, two- and
  three-source), the floating-point↔integer moves and conversions, all the
  load/store forms (unsigned and unscaled immediate, register offset, pre-
  and post-index, pair, the sign-extending loads, with general-purpose and
  SIMD transfer registers), the exclusive, acquire/release, compare-and-swap
  and LSE atomic memory instructions, the PC-relative forms (`adr`, `adrp`,
  `ldr` literal, where the stub materialises the value computed from the
  original pc), the compare- and test-branches (`cbz`/`cbnz`/`tbz`/`tbnz`,
  which get a branch stub that tests the preserved value and takes a
  full-range branch to the real target or the fall-through) and indirect
  branches (`br`/`blr`/`ret` through `x18`, which load the target into
  `x16`/`x17`, dead at any branch). A stack spill of `x18` through `sp`, and
  `add`/`sub` of an immediate to `sp` into `x18` (`mov x18, sp`), have the
  immediate adjusted by the 32 bytes the stub pushed. What is still left
  alone: a load/store with writeback onto `sp` or a register offset from
  `sp`, flag-setting, shifted-immediate or extended-register arithmetic
  from `sp`, `casp` and the pointer-authenticated loads. Scanning the
  vendored glibc, bash, coreutils and the Rust/musl test programs with the
  disassembler finds none of these; `--strace` reports, per prepared range,
  exactly how many `x18` uses were left (a count of real register operands,
  not of bit patterns).

  The backend keeps the slot and the kernel's register view in step: a trap
  reads the guest's `x18` from the slot into `Regs` and writes it back on
  return, so a signal frame carries the real value and `rt_sigreturn`
  restores it, and a cloned thread starts with its parent's.

  The macOS custom x18 ABI (`<os/arch/arm64.h>`, macOS 26.4 and later) and
  `fwe --host-info` remain only as host probes; correctness no longer
  depends on the host preserving `x18`.

Only executable code is scanned, since a data word that happens to encode a
rewritten instruction would otherwise be patched too. `Elf::exec_ranges`
reports the `SHF_EXECINSTR` sections from the section headers, so the
symbol, string, hash and relocation tables that share an executable segment
with the code — the whole R-X segment of musl's `ld-musl`, the code segment
of glibc's `libc.so.6` — are never scanned. For a file-backed `mmap` the
kernel reads the backing file's section headers (`Elf::exec_file_ranges`)
and translates only its executable sections. Within a code section, literal
pools (the targets of `ldr` literal) are detected and skipped. Two gaps
remain: inline data in a code section that is not a literal pool (a jump
table), and a binary fully stripped of section headers, where the scan falls
back to the whole executable segment. Recursive descent over reachable code
is the general fix for both.

Stubs are placed in regions within `b` range (128 MiB) of their sites: the
arena reserved after the loaded image, or, for code mapped later, regions
found by probing near the code.

## System call path

1. The guest executes a rewritten `brk`. macOS delivers `SIGTRAP` on the
   thread's dedicated signal stack.
2. The handler checks that the trapping instruction is ours, copies the
   saved thread state into a `Regs` value (the kernel's view of the guest
   register file), and dispatches on the number in `x8`.
3. Calls that can block — `futex`, the sleeps, `epoll_pwait`, `ppoll`,
   `rt_sigsuspend`, `rt_sigtimedwait`, `wait4`, `waitid`, the blocking
   socket calls, and `read`/`write` with their vectored and positioned forms
   (a pipe or socket blocks until another thread acts) — run **without** the
   kernel lock, so a waiting thread never stalls the threads meant to wake
   it; `clone`, `execve` and `exit` are handled by the backend for the same
   reason. Everything else runs under the single kernel lock through
   `Kernel::enter_syscall`. While a call runs, the thread's guest signal
   mask is in force on the host, so a signal the guest takes interrupts a
   blocking host call (`EINTR`).
4. The result goes into `x0`, `pc` advances past the `brk`, a pending signal
   is delivered if one is ready, and returning from the handler resumes the
   guest. All other registers are preserved. A call the host interrupted is
   finished as Linux would: it runs again if the interrupting signal has no
   guest handler waiting (it was blocked for a `signalfd`, or ignored), or
   if the handler has `SA_RESTART` and the call is one Linux restarts (I/O,
   `wait4`/`waitid`, `accept`, `openat`, `ioctl`, `flock`/`fcntl`, a futex
   wait without a timeout); otherwise it fails with `EINTR` once the handler
   returns.

`--strace` prints each call with its arguments and result, plus the
backend's notes (what was loaded and prepared), to standard error.

## Filesystem

The guest sees a filesystem rooted at a host directory, set with
`fwe --root DIR`; with no `--root` the root is the host `/`. Guest paths are
resolved under the root in `crates/kernel/src/fs.rs` one component at a time,
following symlinks ourselves and clamping `..` so a path can never escape the
root — the containment `openat2(RESOLVE_IN_ROOT)` gives on Linux, done by
hand so it works on macOS too. Absolute symlink targets re-root at the
rootfs. `*at` calls resolve relative to their directory descriptor.

Guest file descriptors are host file descriptors: an opened file's host fd is
returned to the guest unchanged, so `read`, `write`, `lseek`, `fstat` and the
rest act on it directly. The descriptors fwe keeps for itself (the rootfs
handle, the write ends of the pipes behind the emulated event descriptors,
the pipe a `vfork` parent waits on) live in a reserved range at the top of
the host's descriptor space (`crates/kernel/src/fdtable.rs`). At startup fwe
raises its host soft limit as far as macOS allows and gives the guest a
virtual `RLIMIT_NOFILE` whose hard limit ends 64 descriptors short of it
(soft 1024, as on Linux). A guest that closes everything up to its limit,
calls `close_range(3, ~0)` or walks `/proc/self/fd` never reaches fwe's
descriptors, and a system call that names one fails with `EBADF`, as for a
descriptor that is not open; `dup2` onto one fails the same way, and the
limit cannot be raised into the range. `stat` results are translated into the arm64 Linux
layout (`statx` too); `getdents64` is built from `getdirentries` on macOS, re-reading from the
directory position when the translated entries outgrow the guest's buffer.
Creation modes have the umask applied by the kernel. `fcntl` translates the
descriptor and status flags; `ioctl` covers the terminal, pty and `FIO*`
requests.

## Synthetic /proc and /sys

The rootfs has no real `/proc` or `/sys`, so the filesystem layer consults
`crates/kernel/src/procfs.rs` before the host rootfs and generates what
programs read at startup: `/proc/self/exe` (a symlink),
`/proc/self/cmdline`, `/proc/self/fd`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat`,
`/proc/uptime`, `/proc/loadavg`, `/proc/sys/kernel/{ostype,osrelease,
version,hostname,pid_max}`, `/proc/sys/vm/{overcommit_memory,mmap_min_addr}`
and `/sys/devices/system/cpu/{online,possible}`. File content is served from
an anonymous, seekable fd. The per-process values (exe, cmdline, cpu count,
host name) are set at program load and `execve`. The directories can be
opened and listed: `crates/kernel/src/synthdir.rs` serves `getdents64`,
`lseek`, `fstat` and `close` on an opened synthetic directory from an
in-memory entry list. `/proc/self/fd` lists the guest's open descriptors
(including the one listing it); each entry links to the file's guest path,
or to `pipe:[ino]`, `socket:[ino]` or `anon_inode:[eventfd]` and the like,
and opening one reopens the file or, for an object with no path,
duplicates the descriptor. An unknown path under `/proc` or `/sys` is
`ENOENT`.

## Processes

`execve` first checks the new program (an arm64 ELF executable that fits the
address space, with a dynamic linker that exists), so a bad one fails with
the caller intact. Past that point it unmaps all tracked guest memory, loads
the new program with the same `load_image` the startup path uses, and
returns from the trap handler into it with every register zero. A program
can therefore exec one linked at the addresses it occupies itself — the same
binary, as `std::process::Command` and `posix_spawn` users often do.
Descriptors marked close-on-exec are closed; handled signals return to their
default action while ignored ones stay ignored, and the blocked mask and
pending signals are kept, as on Linux.

`fork` (a `clone` without `CLONE_THREAD`) duplicates the process with host
`fork`. In a multithreaded guest the kernel lock and every kernel registry
lock are held across it, so the child — which, as on Linux, has only the
forking thread — cannot inherit a lock another thread held. The child cannot
return through the trap handler frame it inherited (macOS does not restore
the signal mask from a frame the process did not take), so it installs a
signal stack of its own and enters the guest directly with `x0` = 0. The
`vfork` form, `CLONE_VM | CLONE_VFORK`, which `posix_spawn`, `vfork` and Go's
`os/exec` use, runs as a fork: the child gets a copy of the address space,
not a share of it, and the parent waits until the child has exec'd or exited
(it holds the write end of a close-on-exec pipe). Spawn helpers only exec or
exit in the child, so this matches; a child that writes to memory the parent
reads afterwards (glibc's `posix_spawn` reporting an exec failure) is not
seen by the parent.

`wait4` reaps a child through the host, translating the status into the
Linux encoding and the resource usage into Linux units (`ru_maxrss` in KiB);
`waitid` reports the same as a `siginfo_t` (its `rusage` is zero-filled: the
host's `waitid` has none). `getrusage` translates likewise. `getpid` is the
main thread's tid; child pids are host pids, so `kill`, `setpgid` and `wait`
on them act on the real processes.

## Threads and concurrency

A guest thread is a host thread running guest code directly; all threads
share the single global kernel, so each trap briefly locks it. `clone` with
the pthread flag set (`CLONE_THREAD | CLONE_VM | …`) spawns a detached host
thread that enters the guest with the parent's registers, `x0` = 0 and its
own stack; `CLONE_SETTLS` sets the new thread's pointer in its TSD slot, and
`CLONE_PARENT_SETTID`/`CLONE_CHILD_SETTID`/`CLONE_CHILD_CLEARTID` update the
tid words. The thread id, the `set_tid_address` word and the robust list live
in host thread-locals. A thread's `exit` clears and wakes its
`clear_child_tid` futex (so `pthread_join` completes) and ends that host
thread; the last thread, or `exit_group`, ends the process. A new thread
inherits its creator's signal mask and starts with no alternate stack.

The futex wait queues are a process-global structure operating on raw guest
memory, outside the kernel lock, so `FUTEX_WAIT` blocks without holding it.
A host condition variable is not interrupted by signals, so a waiter checks
every 20 ms for a signal it should take, and returns `EINTR` for it.
`clone3` is not implemented (glibc falls back to `clone`).

## Signals

Dispositions are process-wide and live in the kernel; the blocked mask, the
alternate stack and the pending set are per thread (`crates/kernel/src/thread.rs`).

Guest signals travel as host signals wherever the host has an equivalent.
`kill` sends the host signal to whatever the pid names — another process, a
process group, the caller itself — and `tgkill` sends it to that guest
thread's host thread. The backend mirrors each disposition onto the host:
a signal with a guest handler, or one a `signalfd` reads, is caught by the
backend; `SIG_DFL` and `SIG_IGN` become the host's, whose default actions
match Linux's (terminate, ignore, stop, continue), so a child killed by a
signal shows the right status to its parent. At startup a signal fwe
inherited as ignored stays ignored in the guest (`nohup`, a shell's
background jobs). Each guest thread runs under a host mask that mirrors its
guest mask, so the host routes a process-wide signal to a thread that
accepts it and keeps a blocked one pending, and a signal from anywhere — a
child exiting (`SIGCHLD`), the terminal, a timer (`setitimer`), another
process — reaches the guest as it would on Linux. Every fwe handler starts
and ends with all signals blocked, so the backend always knows whether it
interrupted guest code or its own.

The backend's handler records the signal pending against the thread it
landed on, with the sender, code and status from the host's `siginfo`. If it
interrupted guest code, it delivers the signal at once by rewriting the
interrupted context, as Linux does on the way back to user space; if it
interrupted a system call, the call (interrupted itself, if it was blocking)
delivers it as it returns. The real-time signals, which the host lacks, are
kept pending in the kernel and only travel within the process; the target
thread (or, for the process, every thread) is woken with a host signal no
Linux signal maps to. The fault signals (`SIGTRAP`, `SIGSEGV`, `SIGBUS`,
`SIGILL`, `SIGFPE`) are handled the same way when a process sends them to
itself, because macOS's `siginfo` cannot tell a sent one from a fault. A
waiting call that takes a mask (`ppoll`, `epoll_pwait`) runs under it, as
`rt_sigsuspend` does. Before a handler returns to guest code it delivers
anything that became pending while it ran.
`rt_sigsuspend`, `rt_sigtimedwait` (which has the host catch the awaited
signals while it waits, so one taken is never handled) and `rt_sigpending`
work on the same state.

Synchronous faults (`SIGSEGV`, `SIGBUS`, `SIGILL`) are offered to a
handler at the point of the fault, and take the default action (the process
dies with that signal, after a register and code dump under `--strace`) if
none is installed. Delivery builds an arm64 `rt_sigframe` on the guest stack
(or the alternate stack under `SA_ONSTACK`), points the registers at the
handler with `x0`/`x1`/`x2` set per `SA_SIGINFO`, and sets the return
address to the handler's `sa_restorer` or, lacking one, an `rt_sigreturn`
trampoline the backend maps at startup. `rt_sigreturn` restores the saved
registers, mask and alternate stack. The frame uses the kernel's own
`ucontext`/`sigcontext` layout, so a handler that reads or patches
`uc_mcontext` (an unwinder, a fault handler that skips an instruction) sees
the right fields. A handler already running on the alternate stack keeps
using it from its current `sp`. The frame carries the floating-point and
SIMD registers in an `fpsimd_context` record, restored by `rt_sigreturn`, so
a handler may use them freely.

## Event descriptors

`epoll_create1`, `epoll_ctl` and `epoll_pwait` (`crates/kernel/src/epoll.rs`)
pass through on Linux and are translated to `kqueue` on macOS: the epoll
descriptor is a kqueue, each watched fd becomes an `EVFILT_READ` filter for
`EPOLLIN` and an `EVFILT_WRITE` filter for `EPOLLOUT`, `EPOLLET` maps to
`EV_CLEAR` and `EPOLLONESHOT` to `EV_ONESHOT`, and the caller's data word
rides in the kevent `udata`. `epoll_pwait` writes the packed 12-byte arm64
`epoll_event` array in place. The `EEXIST`/`ENOENT` edge cases of redundant
`ADD`/`MOD` are not emulated precisely on macOS.

`eventfd` and `timerfd` (`crates/kernel/src/specialfd.rs`) have no macOS
equivalent and are emulated in a process-global registry keyed by descriptor,
which `read`, `write` and `close` consult first. An eventfd is a pipe plus a
64-bit counter: the pipe holds one byte exactly while the counter is
non-zero, so the read end handed to the guest is readable, and pollable by
`kqueue` and hence by our `epoll`, precisely when a read would succeed. A
timerfd is a `kqueue` holding one `EVFILT_TIMER`, with millisecond
resolution; a periodic timer's distinct initial `it_value` and the
realtime/monotonic distinction are not modelled.

`signalfd` (`crates/kernel/src/signalfd.rs`) has no macOS equivalent and is
emulated: each signalfd is a readiness pipe plus a queue of
`signalfd_siginfo` records. The host never blocks a watched signal, so it
reaches the backend's handler and is recorded pending; a pending signal that
the thread blocks and some signalfd watches is moved onto that signalfd
instead (including the `SIGCHLD` of a child exiting), and a call it
interrupted runs again.

## Sockets

Socket calls (`crates/kernel/src/net.rs`) pass through on Linux. macOS has
the BSD socket API, close but not identical, so the module translates:
address families (`AF_INET6` is 10 on Linux, 30 on macOS), the `sockaddr`
header (Linux leads with a 2-byte family, macOS with a length byte and a
family byte; the port and address that follow are identical, so it is an
in-place header fix-up), the `SOCK_NONBLOCK`/`SOCK_CLOEXEC` type flags
(applied with `fcntl`), `setsockopt` levels and the common option numbers,
and the `send`/`recv` flags. `MSG_NOSIGNAL` has no macOS equivalent, so every
socket gets `SO_NOSIGPIPE` and a broken pipe returns `EPIPE`.

`AF_UNIX` socket paths are rooted under the rootfs like every other path, and
abstract-namespace names (a leading NUL) map to files under a per-host
temporary directory, since macOS has no abstract namespace. `SCM_RIGHTS`
ancillary data is re-encoded, since `cmsg_len` is 64-bit on Linux and 32-bit
on macOS; the passed descriptors are host descriptors and work in the
receiver directly. DNS needs no special support: the guest's resolver reads
`/etc/resolv.conf` and `/etc/hosts` from the rootfs and talks to nameservers
over these sockets. `AF_NETLINK` and raw sockets are M4.

## Terminals and job control

Terminal `ioctl`s are handled in `crates/kernel/src/syscalls.rs`, with the
`termios` translation in `crates/kernel/src/term.rs`. On macOS the structure
differs — `tcflag_t` is 64-bit, the control characters are ordered
differently, and almost every flag sits in a different bit — so each field is
translated through per-field bit tables and a control-character index map.
Baud is reported as a fixed `B38400`. `TIOCGWINSZ`/`TIOCSWINSZ` share a layout
and pass through; `TIOCGPGRP`/`TIOCSPGRP` map to `tcgetpgrp`/`tcsetpgrp`;
`TIOCSCTTY`/`TIOCNOTTY` pass through. `setpgid`, `getpgid`, `setsid` and
`getsid` act on host process groups and sessions.

Pty allocation (`crates/kernel/src/pty.rs`): opening `/dev/ptmx` allocates a
master with `posix_openpt`/`grantpt`/`unlockpt` and remembers a guest-facing
slave number; `TIOCGPTN` returns it, `TIOCSPTLCK` is accepted, and opening
`/dev/pts/<n>` maps that number to the host slave device.

## Credentials

The guest has a virtual user and group identity (`crates/kernel/src/creds.rs`)
independent of the host process, since changing the host's real credentials
would be wrong (one host process backs the guest) and would need root. The
`get*id`/`set*id` family, `getgroups`/`setgroups` and `getresuid`/`getresgid`
act on it with Linux permission semantics. The default is root (uid 0), the
usual identity inside a container image; a program that drops privileges
cannot regain them. `chown` as virtual root is accepted but does not change
host ownership (shadow ownership is not tracked), and `access` under a
virtual root bypasses the permission bits as Linux root does.

## Translation

Linux numbers (errno, flags, clock ids, signals, rlimits, ioctls) are
translated to host values in `crates/kernel/src/host.rs`, using the `libc`
crate. `crates/abi` holds the Linux side; syscall numbers and errno values are
generated from the Linux UAPI headers by `tools/gen-abi.py`.

## Known limitations

Each of these is on the [roadmap](../ROADMAP.md); this is the detail behind
those items.

- **Execution:** a non-PIE executable linked below 4 GiB cannot run
  in-process (the mandatory `__PAGEZERO`); the hypervisor backend is the path
  for it, and exists as a spike. A few rare `x18` forms are left
  unrewritten (see Rewriting guest code; `--strace` counts them). Code
  discovery relies on section
  headers; a stripped binary has its whole executable segment scanned, and
  an inline jump table in a code section could be patched.
- **Processes:** `vfork` copies the address space instead of sharing it
  (see Processes); `execve` from a process with other live threads,
  `execveat` and `clone3` are not implemented; `waitid` reports no
  `rusage`.
- **Descriptors:** the guest's `RLIMIT_NOFILE` is not enforced: a guest
  that opens more descriptors than its limit gets numbers in fwe's range,
  which it cannot use, rather than `EMFILE`; a reopened
  `/proc/self/fd` entry for a pipe or socket shares the original's file
  description rather than getting a new one.
- **Memory:** `MADV_DONTNEED` on a private file mapping keeps modified pages
  where Linux would restore the file's.
- **Signals:** a real-time signal (`SIGRTMIN` and up, which the host lacks)
  can only be sent within the process; standard signals are not queued
  (one pending per signal, as Linux does for them); a signal left pending
  while blocked loses its sender on macOS, so `rt_sigtimedwait` then
  reports `si_pid` 0; `rt_sigqueueinfo` is not implemented; a signal that
  arrives between a blocking call's start and its host wait can be noticed
  only when the call ends, except for `rt_sigsuspend`, `rt_sigtimedwait`
  and the masked waits, which close that window; a futex wait notices a
  signal within 20 ms; a call rerun after an interruption the guest does
  not see starts its timeout over; a fault signal sent by another process
  is treated as a fault; a process killed by a real-time signal exits with
  status 128 + the signal, since the host cannot report one it lacks.
- **Event descriptors:** `epoll` `EEXIST`/`ENOENT` edge cases; `timerfd`
  resolution and clock distinctions.
- **Not implemented:** `rseq`, `membarrier` (optional for libc), and any
  system call not listed in `crates/kernel/src/syscalls.rs` returns `ENOSYS`
  and is noted under `--strace`.
