# Architecture

## Components

```
fwe (CLI)
 └── native backend (crates/native)
      ├── loader      ELF image → host mappings at guest addresses
      ├── rewrite     svc #0 → brk #0x4c58 before code becomes executable
      ├── stack       Linux initial stack: argc, argv, envp, auxv
      └── trap        SIGTRAP handler → kernel → resume guest
 └── kernel layer (crates/kernel)
      Linux system call semantics on top of macOS, behind a Platform trait
 └── ABI (crates/abi), ELF (crates/elf)
```

The kernel layer does not depend on how guest code runs; it sits behind the
`fwe_kernel::Platform` trait. Guest code runs **in-process and natively** by
default: instructions macOS cannot let a Linux process run as-is are rewritten
before execution (see below), not trapped by a VM. The one class the
in-process path cannot handle — a non-PIE `ET_EXEC` linked into the low 4 GiB
macOS reserves — is served by a second `Platform` implementation, a
minimalistic Hypervisor.framework backend (see PLAN.md and
`docs/hypervisor-spike.md`); the same kernel layer sits behind both. A full
virtual machine with its own Linux kernel remains a non-goal.

## Memory model

Guest addresses are host addresses. The native backend maps guest memory at
the guest's own virtual addresses inside the `fwe` process, so guest pointers
are used directly. Where layouts match, they are passed straight to macOS
system calls, which validate them. Future backends keep this property.

The guest sees the host page size (16K on Apple Silicon) through `AT_PAGESZ`,
which the arm64 Linux ABI permits.

macOS reserves the low 4 GiB of every arm64 process with a mandatory 4 GiB
`__PAGEZERO`; on Apple Silicon the kernel refuses to launch a process with a
smaller one. Position-independent executables (the norm for distribution
packages) are loaded anywhere, and ET_EXEC images linked above 4 GiB at their
addresses. ET_EXEC images linked *below* 4 GiB (non-PIE C and Rust at 0x200000
or 0x400000, Go at 0x10000, Debian's `python3.11` at 0x400000) cannot be
mapped at their own addresses in-process, and a non-PIE image carries no
relocation information to move elsewhere. These run on the hypervisor backend
instead, whose guest address space has no `__PAGEZERO` (see
`docs/hypervisor-spike.md`).

## System call path

1. The loader, and `mmap`/`mprotect` with `PROT_EXEC`, map code writable
   first and call `Platform::prepare_exec`, which rewrites every aligned
   `svc #0` into `brk #0x4c58` and flushes the instruction cache. Then the
   final protections are applied.
2. The guest executes the `brk`. macOS delivers `SIGTRAP` on a dedicated
   signal stack.
3. The handler checks that the trapping instruction is ours, reads the
   system call number from `x8` and arguments from `x0`–`x5`, and calls
   `Kernel::syscall`.
4. The result goes into `x0`, `pc` advances past the `brk`, and returning
   from the handler resumes the guest. All other registers are preserved.

## Registers macOS treats differently

- **TPIDR_EL0** holds the Linux thread pointer, but macOS does not preserve
  it for user code (it stores per-CPU data there). Every `mrs`/`msr` of
  `TPIDR_EL0` is rewritten into a branch to a stub that reads or writes a
  slot in the host thread's TSD instead, located through `TPIDRRO_EL0`
  (per-thread, read-only to user code). Stubs live in space reserved right
  after the image, within branch range.
- **x18** is a scratch register for Linux code, but macOS reserves it and
  clears it on every exception return (system calls, page faults, and — the
  case nothing can intercept — involuntary preemption). So guest state must
  never live in the hardware `x18` between instructions. Each instruction that
  names `x18` is redirected to a stub (the same out-of-line mechanism as
  `TPIDR_EL0`) that keeps the guest's `x18` in a per-thread TSD slot: the stub
  saves two scratch registers below `sp` (Linux arm64 has no red zone), reads
  the slot into one of them, runs the instruction with `x18` replaced by that
  scratch, writes the slot back if the instruction wrote `x18`, restores the
  scratch registers and branches back. Because macOS preserves every register
  *except* `x18` across preemption, an ordinary scratch register is safe.
  `crates/native/src/decode.rs` decides which instructions this covers: the
  register-only data-processing classes (moves, logical and add/sub, bitfield,
  extract, conditional select/compare, one-/two-/three-source) and all the
  load/store forms — unsigned immediate, unscaled, register offset, pre/post
  index, and pair — for both general-purpose and (for the base register) SIMD
  variants. An `sp` base, a stack spill of `x18`, is handled by bumping the
  access offset by the 32 bytes the stub pushes (`sp_fixup`), in whichever
  immediate the addressing form uses; writeback onto `sp` and register-offset
  onto `sp` cannot be compensated and are deferred. Compare- and test-branches
  that read `x18` (`cbz`/`cbnz`/`tbz`/`tbnz`) cannot simply move to a stub
  (their branch target is PC-relative), so they get a branch stub: it loads
  `x18` into a scratch, runs the branch against the scratch to a local label,
  then restores the scratch down both the taken and not-taken paths and uses a
  full-range branch to the real target or the fall-through. For an `sp` base the stub adds the 32
  bytes it pushed to the access's immediate so it still reaches the caller's
  slot. Pair, pre/post-index and register-offset loads, PC-relative forms,
  branches, and `sp` forms of the data-processing classes are left for a later
  pass (counted, not rewritten). Literal pools are excluded from the scan
  (below), so constants are never mistaken for `x18` instructions.
  The custom x18 ABI (`<os/arch/arm64.h>`, macOS 26.4+) and `fwe --host-info`
  remain only as a host probe; correctness no longer depends on the host
  preserving `x18`.

## Filesystem

The guest sees a filesystem rooted at a host directory (the rootfs), set with
`fwe --root DIR`; with no `--root` the root is the host `/`, reproducing
pass-through behaviour. Guest paths are resolved under the root in
`crates/kernel/src/fs.rs`, one component at a time, following symlinks
ourselves and clamping `..` so a path can never escape the root — the
containment `openat2(RESOLVE_IN_ROOT)` gives on Linux, done by hand so it
works on macOS too. Absolute symlink targets re-root at the rootfs rather
than the host `/`.

Guest file descriptors are host file descriptors: an opened file's host fd is
returned to the guest unchanged, so `read`, `write`, `lseek`, `fstat` and the
rest act on it directly. `getdents64` passes through on a Linux host (the
kernel already produces the arm64 layout) and is translated from
`getdirentries` on macOS. Creation modes have the umask applied by the kernel.

## Dynamic linking

A dynamically linked executable names an interpreter (the dynamic linker,
e.g. `/lib/ld-linux-aarch64.so.1` or `/lib/ld-musl-aarch64.so.1`) in a
`PT_INTERP` segment. The loader maps the executable, then resolves the
interpreter path **through the rootfs**, maps it too (it is a PIE, loaded at
an arbitrary base), and starts the guest at the interpreter's entry point
rather than the executable's. The auxiliary vector carries `AT_BASE` (the
interpreter's load base), `AT_ENTRY` (the executable's entry), and
`AT_PHDR`/`AT_PHENT`/`AT_PHNUM` for the executable, as Linux provides them.
The interpreter maps the executable's shared libraries itself through our
`openat` and file-backed `mmap`; each executable region it maps (or turns
executable with `mprotect`) is translated by the same `PROT_EXEC` path as the
initial image, so the dynamic linker's own code and every library it loads get
the `x18`/`svc`/`TPIDR_EL0` rewrite. For a file-backed mapping the kernel reads
the backing file's section headers and translates only its executable
sections, so a library whose code segment also carries its symbol and string
tables — as glibc's `libc.so.6` does — keeps those tables intact (the same
protection the loader applies to the initial image, here driven from the file
rather than the in-memory image).

This runs real, unmodified musl and glibc. The end-to-end tests load the
genuine dynamic linker, which self-relocates, resolves the program's
`R_AARCH64_JUMP_SLOT`/`R_AARCH64_RELATIVE` relocations against the shared libc,
installs the thread pointer and starts the program. musl's linker is itself the
libc, one self-contained object; glibc's `ld-linux-aarch64.so.1` is separate
and maps `libc.so.6` at run time, exercising the file-backed translation path.
The tests cover a minimal program with its own `_start`, a `_exit`-only program
that forces the glibc shared-libc mapping without needing C runtime startup,
and a normal program that starts through the libc's crt objects and
`__libc_start_main` and then uses the heap and stdio.

## Processes

`execve` loads a new program with the shared `load_image` and enters it with
a fresh register set, resetting signal and per-thread state; the old image's
mappings are not reclaimed yet, so it suits fork-then-exec and exec chains.
`fork` (a `clone` without `CLONE_THREAD`) duplicates the process with host
`fork` and is supported for single-threaded guests only, since another
thread could hold a lock across the fork. `wait4` reaps a child through the
host and translates the status into the Linux encoding. `execve`, `fork` and
`wait4` all run without the kernel lock.

## Signals

The kernel stores each signal's `sigaction`, the blocked mask and the
alternate stack. When a guest raises a signal against itself (`kill`,
`tgkill`, `raise`) it is marked pending and delivered on return to the guest;
synchronous faults (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`) are offered to a
handler at the point of the fault. Delivery builds an arm64 `rt_sigframe` on
the guest stack (or the alternate stack under `SA_ONSTACK`), points the
registers at the handler with `x0`/`x1`/`x2` set per `SA_SIGINFO`, and sets
the return address to the handler's `sa_restorer` or, lacking one, a
`rt_sigreturn` trampoline the backend maps at startup. `rt_sigreturn`
restores the saved registers, mask and alternate stack. The backend exposes
the guest register file to the kernel for the duration of a trap as a
`Regs` value (copied from and back to the host signal context), which the
coming thread support reuses. Floating-point and vector state is not yet
saved across a handler.

## Threads and concurrency

A guest thread is a host thread running guest code directly; all threads
share the single global kernel, so each trap briefly locks it. `clone` with
the pthread flag set (`CLONE_THREAD | CLONE_VM | ...`) spawns a detached host
thread that enters the guest with the parent's registers, `x0` = 0 and its
own stack; `CLONE_SETTLS` sets the new thread's pointer in its TSD slot, and
`CLONE_PARENT_SETTID`/`CLONE_CHILD_SETTID`/`CLONE_CHILD_CLEARTID` update the
tid words. Thread id, the `set_tid_address` word and the robust-list live in
host thread-locals. A thread's `exit` clears and wakes its `clear_child_tid`
futex (so `pthread_join` completes) and ends that host thread; the last
thread, or `exit_group`, ends the process. `fork`, `execve` and `wait` are
not implemented yet.

Blocking system calls — `futex`, `nanosleep`, `clock_nanosleep` — must not
hold the kernel lock while they block, or a waiting thread would stall the
threads meant to wake it. The backend runs them outside the lock (the futex
wait queues are a separate process-global structure operating on raw guest
memory), then re-locks only to record the result and deliver a pending
signal. Per-thread signal masks and alternate stacks are not yet separated
(the mask and altstack are process-wide).

## Synthetic /proc and /sys

The guest rootfs has no real `/proc` or `/sys`, so the filesystem layer
checks `crates/kernel/src/procfs.rs` before the host rootfs and generates the
entries programs read at startup: `/proc/self/exe` (a symlink) and
`/proc/self/cmdline`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat`,
`/proc/uptime`, `/proc/loadavg`, `/proc/sys/kernel/*`, `/proc/sys/vm/*` and
`/sys/devices/system/cpu/*`. File content is served from an anonymous,
seekable fd (an immediately-unlinked temp file). The per-process values
(exe, cmdline, cpu count, host name) are set at program load and `execve`.
An unknown path under `/proc` or `/sys` is `ENOENT`. The directories
themselves can be opened and listed: `crates/kernel/src/synthdir.rs` tracks an
opened synthetic directory fd and serves `getdents64`, `lseek`, `fstat` and
`close` from an in-memory entry list (the tree in `procfs::children`), so
`opendir`/`readdir` over `/proc`, `/proc/self`, `/proc/sys`, `/sys` and their
synthetic subdirectories work.

## epoll

`epoll_create1`, `epoll_ctl` and `epoll_pwait` live in
`crates/kernel/src/epoll.rs`. On Linux they pass straight through to the host
kernel, which already speaks the arm64 Linux ABI. On macOS they are translated
to `kqueue`: the epoll descriptor is a kqueue fd, each watched fd becomes an
`EVFILT_READ` filter for `EPOLLIN` and an `EVFILT_WRITE` filter for `EPOLLOUT`,
`EPOLLET` maps to `EV_CLEAR` and `EPOLLONESHOT` to `EV_ONESHOT`, and the
caller's `epoll_event.data` word rides in the kevent `udata`. A control change
uses `EV_RECEIPT` so registration errors surface without reporting readiness;
`epoll_pwait` translates returned kevents back into the packed 12-byte arm64
`epoll_event` array in place. `epoll_pwait` can block, so the backend runs it
outside the kernel lock like `futex` and the sleeps. Readiness edge cases
(`EEXIST`/`ENOENT` for redundant `ADD`/`MOD`, and the signal mask) are not yet
emulated precisely on macOS.

## eventfd and timerfd

`eventfd` and `timerfd` live in `crates/kernel/src/specialfd.rs`. On Linux they
pass through to the host kernel. macOS has neither, so they are emulated and
tracked in a process-global registry keyed by descriptor, which `read`, `write`
and `close` consult:

- **eventfd** is a pipe plus a 64-bit counter. The pipe holds exactly one byte
  while the counter is non-zero, so the read end — the fd handed to the guest —
  is readable, and pollable by `kqueue` (hence by our `epoll`), precisely when a
  read would succeed. `read` returns and clears the counter (or returns 1 and
  decrements it under `EFD_SEMAPHORE`); `write` adds to it.
- **timerfd** is a `kqueue` holding one `EVFILT_TIMER`; `read` collects the
  expiration count with `kevent`, and the kqueue fd is pollable by our `epoll`.
  Millisecond resolution; a periodic timer's distinct initial `it_value` and
  the realtime/monotonic clock distinction are not modelled.

`read` and `write` can block, so the backend routes every `read`/`write`
through the lock-free `blocking_syscall` path first: a consumer blocking under
the kernel lock while the producer needs that same lock to post would deadlock.
The registry returns "not mine" for ordinary descriptors, which fall back to the
normal host `read`/`write`.

## signalfd

`signalfd` lives in `crates/kernel/src/signalfd.rs`. The guest's signals are
virtual — the kernel tracks them itself rather than as host signals — so
`signalfd` is emulated on both hosts rather than delegated. Each signalfd is a
readiness pipe (so it is pollable by `epoll`) plus a queue of
`signalfd_siginfo` records and the set of signals it watches. When the guest
raises a signal that is blocked and some signalfd watches it, the kernel queues
a record on that descriptor instead of leaving the signal pending; a reaped
child likewise queues a `SIGCHLD` record. `read` returns the queued records and
blocks lock-free like the other event descriptors.

## Credentials

The guest has a virtual user and group identity in `crates/kernel/src/creds.rs`,
independent of the host process. Changing the host process's real credentials
would be wrong (one host process backs the guest) and would fail unless `fwe`
ran as root, so `getuid`/`geteuid`/`getgid`/`getegid`, the `set*uid`/`set*gid`
family (`setresuid`, `setreuid`, `setfsuid` and the group equivalents) and
`getgroups`/`setgroups` act on this identity with Linux permission semantics.
The default is root (uid 0), the usual identity inside a container image, so a
program that drops privileges can do so and cannot regain them. Because the
identity is virtual, `chown` as root is accepted but does not change host file
ownership (shadow ownership is not tracked), and `access` under a virtual root
bypasses the permission bits as Linux root does.

## Sockets

Socket calls live in `crates/kernel/src/net.rs`. On Linux they pass through to
the host kernel, whose ABI the guest already speaks. macOS has the BSD socket
API, close but not identical, so the module translates:

- **address families:** `AF_INET6` is 10 on Linux but 30 on macOS; `AF_INET`
  and `AF_UNIX` match.
- **`sockaddr` layout:** Linux leads with a 2-byte `sa_family`; macOS leads
  with a 1-byte length and a 1-byte family. The port and address that follow
  are identical, so the conversion is a small header fix-up, done in place on
  the guest buffer's bytes.
- **socket type flags:** Linux packs `SOCK_NONBLOCK`/`SOCK_CLOEXEC` into the
  `type` argument; macOS has no such bits, so they are stripped and applied
  with `fcntl`.
- **`setsockopt`:** `SOL_SOCKET` is 1 on Linux, `0xffff` on macOS, and the
  option numbers differ; a table maps the common ones, and `TCP_NODELAY`.
- **`send`/`recv` flags:** reordered bits, mapped individually. `MSG_NOSIGNAL`
  has no macOS equivalent, so every socket gets `SO_NOSIGPIPE` and a broken
  pipe returns `EPIPE` rather than raising a signal.

Guest file descriptors are host socket descriptors, as everywhere else. The
calls that can block — `connect`, `accept`, `recvfrom`, `recvmsg`, `sendto`,
`sendmsg` — run outside the kernel lock through `blocking_syscall`, so a thread
waiting in `accept` or `recv` does not stall the threads meant to feed it. DNS
needs no special support: the guest's resolver reads `/etc/resolv.conf` and
`/etc/hosts` from the rootfs and talks to nameservers over these sockets.

`AF_UNIX` is fully handled: socket paths are rooted under the rootfs like every
other path, and abstract-namespace names (a leading NUL) are mapped to files
under a per-host temporary directory, since macOS has no abstract namespace.
`SCM_RIGHTS` ancillary data (file-descriptor passing over `AF_UNIX`) is
translated too — on macOS the control-message layout differs (`cmsg_len` is
64-bit on Linux, 32-bit on macOS), so `sendmsg`/`recvmsg` re-encode it. The
passed descriptors are host descriptors, so they work in the receiver directly.
`AF_NETLINK` and raw sockets are deferred to M4.

## Terminals and job control

Terminal `ioctl`s are handled in `crates/kernel/src/syscalls.rs`, with the
`termios` translation in `crates/kernel/src/term.rs`. On Linux `TCGETS`/`TCSETS`
pass through, since the guest `termios` is the host's. On macOS the structure
differs — `tcflag_t` is 64-bit, the control characters are ordered differently,
and almost every flag sits in a different bit — so each field is translated with
`tcgetattr`/`tcsetattr` through per-field bit tables and a control-character
index map. Baud is reported as a fixed `B38400`; a pty has no meaningful line
rate. `TIOCGWINSZ`/`TIOCSWINSZ` share a layout and pass through; `TIOCGPGRP`/
`TIOCSPGRP` map to `tcgetpgrp`/`tcsetpgrp`, and `TIOCSCTTY`/`TIOCNOTTY` pass
through.

`setpgid`, `getpgid`, `setsid` and `getsid` act on host process groups and
sessions. A guest "pid" argument of 0 (self) always works, and child pids
returned by `fork` are host pids, so `setpgid(child, …)` works too; passing a
guest's virtual `getpid` value for another process does not.

Pty allocation is handled in `crates/kernel/src/pty.rs`. Opening `/dev/ptmx`
allocates a master with `posix_openpt`/`grantpt`/`unlockpt` (available on both
hosts) and remembers a guest-facing slave number; `TIOCGPTN` returns it,
`TIOCSPTLCK` is accepted, and opening `/dev/pts/<n>` maps that number to the
host slave device (`/dev/pts/<n>` on Linux, `/dev/ttys<nnn>` on macOS). So a
guest can allocate and drive its own pty.

## Translation

Linux numbers (errno, flags, clock ids, signals, rlimits, ioctls) are
translated to macOS values in `crates/kernel/src/host.rs`, using the `libc`
crate for host values. `crates/abi` holds the Linux side. Syscall numbers and
errno values are generated from the Linux UAPI headers by `tools/gen-abi.py`.

## Known limitations in M0

These are tracked on the roadmap:

- `fork` is single-threaded only; `vfork`, `waitid` and `execveat` are not
  implemented; `execve` does not reclaim the old address space.
- Signal mask and alternate stack are process-wide, not per thread.
- Floating-point/vector registers are not saved across a signal handler.
- Non-PIE executables linked below 4 GiB cannot run in-process (the mandatory
  `__PAGEZERO`); the minimalistic hypervisor backend (see above and
  `docs/hypervisor-spike.md`) is the path for them, not load-time relocation.
- Guest uses of `x18` across the data-processing and load/store classes are
  rewritten to a per-thread slot (see above) and survive preemption, which is
  enough to run a compiled Rust/musl binary unmodified, including the
  compare/test branches (`cbz`/`cbnz`/`tbz`/`tbnz`) that read `x18` and the
  floating-point↔integer conversions (`fmov`/`fcvt*`/`scvtf`/`ucvtf`), the
  PC-relative forms (`adr`/`adrp` and `ldr`-literal into `x18`, where the stub
  materializes the value computed from the original pc), and indirect branches
  through `x18` (`br`/`blr`/`ret x18`, where the stub loads the target from the
  slot into the `x16`/`x17` scratch registers — dead at any branch — and jumps,
  setting the link register for `blr`). The only `x18` forms still deferred are
  `sp`-writeback and `sp`-register-offset loads (a prologue spilling `x18`
  through `sp` with writeback), which are rare for a caller-saved register.
- The rewrite pass scans aligned words and patches instructions, so a data
  word that happens to encode a rewritten instruction would be patched too.
  The scan is therefore confined to the executable code: `Elf::exec_ranges`
  reports the `SHF_EXECINSTR` sections from the section headers, so symbol,
  string, hash and relocation tables that share an executable segment with the
  code — as the whole R-X segment of musl's `ld-musl` does — are never
  scanned. Within a code section, literal pools (the targets of `ldr`-literal)
  are detected and skipped. Two gaps remain: inline data in a code section
  other than a literal pool (e.g. a jump table), and a binary fully stripped of
  its section headers, where the scan falls back to the whole executable
  segment. Recursive descent over reachable code only is the planned general
  fix for both.
- Guest pointers the kernel reads itself are not yet fault-checked; a bad
  pointer crashes `fwe` instead of returning `EFAULT`.
