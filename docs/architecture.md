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
 │    ├── trap         SIGTRAP/fault handlers → kernel → resume guest
 │    ├── threads      clone: a host thread per guest thread
 │    ├── process      fork, execve, wait4
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
or the process). Two backends share it:

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
calls, which validate them. The hypervisor backend keeps this property by
mapping the VM's memory at the same addresses in the host process.

The guest sees the host page size (16 KiB on Apple Silicon) through
`AT_PAGESZ`, which the arm64 Linux ABI permits.

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
  `x16`/`x17`, dead at any branch). A stack spill of `x18` through `sp` has
  its offset bumped by the 32 bytes the stub pushed. What is still left
  alone, and reported under `--strace` as left unrewritten: a load/store
  with writeback onto `sp` or a register offset from `sp`, a data-processing
  form whose operand is `sp` rather than `xzr`, `casp` and the
  pointer-authenticated loads. These are rare for a caller-saved register
  and have not appeared in the binaries run so far.

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
   `wait4`, the blocking socket calls, and `read`/`write` with their vectored
   and positioned forms (a pipe or socket blocks until another thread acts)
   — run **without** the kernel lock, so a waiting thread never stalls the
   threads meant to wake it; `clone`, `execve` and `exit` are handled by the
   backend for the same reason. Everything else runs under the single kernel lock
   through `Kernel::enter_syscall`.
4. The result goes into `x0`, `pc` advances past the `brk`, a pending signal
   is delivered if one is ready, and returning from the handler resumes the
   guest. All other registers are preserved.

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
rest act on it directly. The few descriptors fwe keeps for itself (the rootfs
handle, the write ends of the pipes behind the emulated event descriptors)
share that table, so a guest that closes every descriptor it did not open can
take them away; see the limitations. `stat` results are translated into the arm64 Linux
layout (`statx` too); `getdents64` is built from `getdirentries` on macOS, re-reading from the
directory position when the translated entries outgrow the guest's buffer.
Creation modes have the umask applied by the kernel. `fcntl` translates the
descriptor and status flags; `ioctl` covers the terminal, pty and `FIO*`
requests.

## Synthetic /proc and /sys

The rootfs has no real `/proc` or `/sys`, so the filesystem layer consults
`crates/kernel/src/procfs.rs` before the host rootfs and generates what
programs read at startup: `/proc/self/exe` (a symlink) and
`/proc/self/cmdline`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat`,
`/proc/uptime`, `/proc/loadavg`, `/proc/sys/kernel/{ostype,osrelease,
version,hostname,pid_max}`, `/proc/sys/vm/{overcommit_memory,mmap_min_addr}`
and `/sys/devices/system/cpu/{online,possible}`. File content is served from
an anonymous, seekable fd. The per-process values (exe, cmdline, cpu count,
host name) are set at program load and `execve`. The directories can be
opened and listed: `crates/kernel/src/synthdir.rs` serves `getdents64`,
`lseek`, `fstat` and `close` on an opened synthetic directory from an
in-memory entry list. An unknown path under `/proc` or `/sys` is `ENOENT`.

## Processes

`execve` loads the new program with the same `load_image` the startup path
uses and enters it with a fresh register set, after closing the descriptors
marked close-on-exec and resetting the signal dispositions, the alternate
stack and the per-thread words (the blocked mask is kept, as on Linux). The
old image's mappings are not reclaimed yet, so this suits fork-then-exec and
exec chains. `fork` (a `clone` without
`CLONE_THREAD`) duplicates the process with host `fork`; the child
re-initialises its thread state and enters the guest with `x0` = 0. It is
supported for single-threaded guests only, since another thread could hold
a lock across the fork. `wait4` reaps a child through the host and
translates the status into the Linux encoding (and queues `SIGCHLD` to a
watching `signalfd`); `rusage` is zero-filled. `getpid` is the main thread's
tid; child pids are host pids, so `setpgid(child, …)` works. Sending a
signal to another process is not implemented: `kill` of any pid but the
caller's own returns `ESRCH`.

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
thread; the last thread, or `exit_group`, ends the process.

The futex wait queues are a process-global structure operating on raw guest
memory, outside the kernel lock, so `FUTEX_WAIT` blocks without holding it.
`clone3` is not implemented (glibc falls back to `clone`).

## Signals

The kernel stores each signal's `sigaction`, the blocked mask and the
alternate stack. A signal the guest raises against itself (`kill`, `tkill`,
`tgkill`) is marked pending and delivered on the way back to the guest;
synchronous faults (`SIGSEGV`, `SIGBUS`, `SIGILL`) are offered to a
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
using it from its current `sp`. Only the general-purpose registers, `sp`,
`pc` and `pstate` are saved across a handler; the signal mask and alternate
stack are process-wide rather than per thread.

## Event descriptors

`epoll_create1`, `epoll_ctl` and `epoll_pwait` (`crates/kernel/src/epoll.rs`)
pass through on Linux and are translated to `kqueue` on macOS: the epoll
descriptor is a kqueue, each watched fd becomes an `EVFILT_READ` filter for
`EPOLLIN` and an `EVFILT_WRITE` filter for `EPOLLOUT`, `EPOLLET` maps to
`EV_CLEAR` and `EPOLLONESHOT` to `EV_ONESHOT`, and the caller's data word
rides in the kevent `udata`. `epoll_pwait` writes the packed 12-byte arm64
`epoll_event` array in place. The `EEXIST`/`ENOENT` edge cases of redundant
`ADD`/`MOD` and the signal mask are not emulated precisely on macOS.

`eventfd` and `timerfd` (`crates/kernel/src/specialfd.rs`) have no macOS
equivalent and are emulated in a process-global registry keyed by descriptor,
which `read`, `write` and `close` consult first. An eventfd is a pipe plus a
64-bit counter: the pipe holds one byte exactly while the counter is
non-zero, so the read end handed to the guest is readable, and pollable by
`kqueue` and hence by our `epoll`, precisely when a read would succeed. A
timerfd is a `kqueue` holding one `EVFILT_TIMER`, with millisecond
resolution; a periodic timer's distinct initial `it_value` and the
realtime/monotonic distinction are not modelled.

`signalfd` (`crates/kernel/src/signalfd.rs`) is emulated on both hosts, since
the guest's signals are virtual: each signalfd is a readiness pipe plus a
queue of `signalfd_siginfo` records. When the guest raises a signal that is
blocked and some signalfd watches it, the record is queued there instead of
leaving the signal pending; a reaped child queues `SIGCHLD` likewise.

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
  for it, and exists as a spike. `x18` in a load/store with writeback onto
  `sp` or a register offset from `sp`, in a data-processing form whose
  operand is `sp`, in `casp` and in the pointer-authenticated loads is left
  unrewritten (reported under `--strace`). Code discovery relies on section
  headers; a stripped binary has its whole executable segment scanned, and
  an inline jump table in a code section could be patched.
- **Processes:** `execve` does not reclaim the old address space; `fork` is
  single-threaded only; `vfork`, `waitid`, `execveat` and `clone3` are not
  implemented; `rusage` is zero-filled.
- **Descriptors:** fwe's own descriptors (the rootfs handle, the pipe ends
  behind eventfd and signalfd) live in the guest's table; a guest that closes
  every descriptor from 3 up, as daemons and `subprocess` do, breaks path
  resolution. A guest↔host descriptor map is the fix.
- **Memory:** `MADV_DONTNEED` on a private file mapping keeps modified pages
  where Linux would restore the file's. Guest pointers the kernel reads
  itself are not fault-checked; a bad pointer crashes `fwe` instead of
  returning `EFAULT`.
- **Signals:** `kill` reaches only the calling process (another pid gets
  `ESRCH`), so a shell cannot signal its children; the mask and alternate
  stack are process-wide, not per thread; floating-point and vector
  registers are not saved across a handler.
- **Event descriptors:** `epoll` `EEXIST`/`ENOENT` edge cases and the
  `epoll_pwait` signal mask; `timerfd` resolution and clock distinctions.
- **Not implemented:** `rseq`, `membarrier` (optional for libc), and any
  system call not listed in `crates/kernel/src/syscalls.rs` returns `ENOSYS`
  and is noted under `--strace`.
