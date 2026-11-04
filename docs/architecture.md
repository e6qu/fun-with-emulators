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
 │    └── hv           the hypervisor backend: VM, vCPU loop, loader
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
- The **hypervisor backend** ([hypervisor.md](hypervisor.md)) runs the
  guest at EL0 in a Hypervisor.framework VM, under a minimal EL1 that only
  bounces exceptions back to fwe. It exists for non-PIE executables linked
  into the low 4 GiB that macOS reserves, which the native backend cannot
  map, and fwe picks it automatically for them. The kernel layer is the same;
  the executable's image is the one range of guest memory not at the same
  address in the host, and the kernel translates pointers into it. A full
  virtual machine with its own Linux kernel is a non-goal.

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
  three-source), the floating-point↔integer moves and conversions, the moves
  between a general register and a vector element (`dup`, `ins`, `smov`,
  `umov`), all the
  load/store forms (unsigned and unscaled immediate, register offset, pre-
  and post-index, pair, the sign-extending loads, with general-purpose and
  SIMD transfer registers, and the SIMD structure loads and stores, `ld1`
  to `ld4r` and `st1` to `st4`, through an `x18` base), the exclusive, acquire/release, compare-and-swap
  and LSE atomic memory instructions, the PC-relative forms (`adr`, `adrp`,
  `ldr` literal, where the stub materialises the value computed from the
  original pc), the compare- and test-branches (`cbz`/`cbnz`/`tbz`/`tbnz`,
  which get a branch stub that tests the preserved value and takes a
  full-range branch to the real target or the fall-through) and indirect
  branches (`br`/`blr`/`ret` through `x18`, which load the target into
  `x16`/`x17`, dead at any branch). A stack spill of `x18` through `sp`, and
  `add`/`sub` of an immediate to `sp` into `x18` (`mov x18, sp`), have the
  immediate adjusted by the 32 bytes the stub pushed. Where no immediate can
  absorb the push — extended-register `add`/`sub` from `sp` (`add x1, sp,
  x18`, of which Node's library has hundreds), flag-setting or shifted
  immediates from `sp`, a register offset from `sp`, an offset the push
  would move out of range — the stub saves a third scratch register, sets it
  to `sp` as it was on entry and runs the instruction with that register in
  place of `sp`. What is still left alone: a load/store with writeback onto
  `sp`, an instruction that writes `sp`, `casp` and the pointer-authenticated
  loads. `--strace` reports, per prepared image, exactly how many `x18`
  uses were left (a count of real register operands, not of bit patterns).

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
kernel maps the backing file for a moment to read its section headers
(`Elf::exec_file_ranges`) and translates only its executable sections. Code sections still hold data:
the constant tables of hand-written assembly (OpenSSL keeps SHA-256's and
SHA-512's round constants, and many more, in `.text`, and over a thousand of
`libcrypto`'s data words decode as instructions naming `x18`). An image's
unwind table tells the two apart: every function a compiler emits has a
frame description entry in `.eh_frame` giving the addresses it covers, and
hand-written assembly with CFI directives does too
(`crates/elf/src/unwind.rs`). Where an image has one, `x18` is rewritten
only inside the ranges it covers — in glibc, libstdc++, ICU, git, bash,
SQLite, lighttpd and PCRE2 every `x18` use lies inside them — and only a
literal load that is itself code marks its target as a literal pool (a data
word decoding as one had hidden an `x18` use in OpenSSL's MD5 from the
rewrite). System calls and thread-pointer accesses are rewritten throughout
the executable sections, as before. Without a usable unwind table the whole
of each executable section counts as code. Two gaps remain: inline data in
code an unwind table covers (a jump table), and a binary fully stripped of
section headers, where the scan falls back to the whole executable segment.

Code a guest makes executable after mapping it — a JIT compiler's, through
`mprotect` or writable and executable memory (below) — has no unwind table,
and its pages hold data among the code (V8's constant pools and metadata);
JIT compilers for Linux arm64 leave `x18` alone (V8 reserves it). So there
only system calls and thread-pointer accesses are rewritten.

Stubs are placed in regions within `b` range (128 MiB) of their sites: the
arena reserved after the loaded image, or, for code mapped later, regions
found by probing near the code.

Memory the guest maps both writable and executable — what a JIT compiler
writes its code into, such as PCRE2's in `git grep` — macOS never maps so
(it refuses `PROT_WRITE | PROT_EXEC` without `MAP_JIT`). The kernel keeps
such memory writable only and records it (`crates/kernel/src/mm.rs`). In
the native backend the guest's first instruction fetch from a page faults:
the page's code is prepared as any guest code is and the page becomes
read-execute; a later write to it faults and makes it read-write again,
and so on. Preparing code twice is harmless (a rewritten site no longer
matches), and the guest's own cache maintenance, which EL0 may do on macOS
as on Linux, makes what it wrote visible. A write fwe makes for the guest
(a `read` into such a page, say) switches the page in the same way. In the
hypervisor backend the VM maps the memory writable and executable at stage
2, so nothing faults.

`mrs <Xt>, ctr_el0`, the cache type register that code flushing the caches
reads (git's own copy of the compiler runtime's cache flush, for one), is
allowed at EL0 on Linux and trapped on macOS. The native backend emulates
it in its `SIGILL` handler, reporting Apple Silicon's value as Linux shows
it there without the bits that allow skipping cache maintenance
(`crates/native/src/hwcap.rs`).

## System call path

1. The guest executes a rewritten `brk`. macOS delivers `SIGTRAP` on the
   thread's dedicated signal stack.
2. The handler checks that the trapping instruction is ours, copies the
   saved thread state into a `Regs` value (the kernel's view of the guest
   register file), and dispatches on the number in `x8`.
3. Calls that can block — `futex`, the sleeps, `epoll_pwait`, `ppoll`,
   `pselect6`, `rt_sigsuspend`, `rt_sigtimedwait`, `wait4`, `waitid`, the blocking
   socket calls, `flock` and `fcntl`'s `F_SETLKW`, and `read`/`write` with their vectored and positioned forms
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
Creation modes have the umask applied by the kernel. An `O_CREAT` open
that macOS fails with `ENOENT` because another process is unlinking the
name at that moment is retried, as Linux would have created the file. `fcntl` translates the
descriptor and status flags, and record locks (`F_GETLK`, `F_SETLK`,
`F_SETLKW`: the arm64 `struct flock` and its lock types differ from the
host's); `flock` passes through. Both kinds of lock are the host's, so they
hold between guest processes and against host ones. `ioctl` covers the
terminal, pty and `FIO*` requests.

## Synthetic /proc and /sys

The rootfs has no real `/proc` or `/sys`, so the filesystem layer consults
`crates/kernel/src/procfs.rs` before the host rootfs and generates what
programs read at startup: `/proc/self/exe` (a symlink),
`/proc/self/cmdline`, `/proc/self/fd`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat`,
`/proc/uptime` and `/proc/loadavg` (the host's uptime and load, which
`sysinfo` reports too, with the same fixed memory figures as
`/proc/meminfo`), `/proc/sys/kernel/{ostype,osrelease,
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

`/dev` is the rootfs's, except for what Linux always mounts there: `null`,
`zero`, `random`, `urandom` and `tty` resolve to the host's own nodes
(`crates/kernel/src/fs.rs`; a rootfs unpacked without privileges has no
device nodes), and `/dev/fd`, `/dev/stdin`, `/dev/stdout` and `/dev/stderr`
are links into `/proc/self/fd`.

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

Two kinds of `execve` instead re-execute fwe on the new program: one of a
program only the hypervisor backend can run (linked below 4 GiB), and one
from a process with other live threads, which Linux ends. The host's own
exec then does the work: the pid, descriptors not marked close-on-exec, the
signal mask, pending signals and ignored dispositions survive it as Linux
requires, and fwe passes on the root filesystem, the working directory, the
guest's `argv[0]` and `--strace` (`--guest-path`, `--cwd`, `--argv0`), and
what only the kernel layer holds — the virtual credentials, the
`RLIMIT_NOFILE` and the umask — as one encoded `--exec-state`
(`Kernel::exec_state`); the new fwe picks the backend. The hypervisor
backend's `execve` always works this way. As on Linux, the saved user and
group IDs become the effective ones across an `execve`.

`execveat` turns its `dirfd`, path and flags into a guest path and then is
`execve` (`Kernel::execveat_path`): a relative path is taken from the
directory `dirfd` is open on, `AT_EMPTY_PATH` runs the file `dirfd` itself
names, and `AT_SYMLINK_NOFOLLOW` refuses a final symbolic link with
`ELOOP`. The descriptor is turned into the path of its file, so a file
renamed or deleted after it was opened is not found.

`fork` (a `clone` without `CLONE_THREAD`) duplicates the process with host
`fork`. In a multithreaded guest the kernel lock and every kernel registry
lock are held across it, so the child — which, as on Linux, has only the
forking thread — cannot inherit a lock another thread held. A host fork
copies memory while the other threads run, so a child could see one
thread's writes torn across pages; instead the threads running guest code
are suspended for the fork (`crates/native/src/quiesce.rs`). Only those:
guest code holds none of fwe's or the host libraries' locks, while a thread
suspended in fwe's code (inside `malloc`, say) could deadlock the fork. A
thread in fwe's code runs on, and waits before going back into guest code
until the fork is done. The child cannot
return through the trap handler frame it inherited (macOS does not restore
the signal mask from a frame the process did not take), so it installs a
signal stack of its own and enters the guest directly with `x0` = 0. The
`vfork` form, `CLONE_VM | CLONE_VFORK`, which `posix_spawn`, `vfork` and Go's
`os/exec` use, is a fork whose child shares the guest's memory: for that
fork the private guest memory is set to be inherited by sharing
(`minherit`), then back to being copied, in both processes. The parent waits
until the child has exec'd or exited (it holds the write end of a
close-on-exec pipe), and sees what the child wrote meanwhile — glibc's
`posix_spawn` reports an exec failure that way. fwe's own memory is not
shared, so the child's kernel state is its own, and so are its mappings: an
`mmap` or `munmap` in a `vfork` child does not reach the parent. A host fork child does not inherit kqueues (their
descriptors are closed in it), so the kqueues behind the guest's `epoll` and
`timerfd` descriptors are recorded before the fork and rebuilt in the child
at the same numbers (see Event descriptors).

In the hypervisor backend a host fork is impossible, since a child cannot use
its parent's VM, so `fork` and `vfork` start a fresh fwe process instead
(`crates/native/src/hv/fork.rs`, [hypervisor.md](hypervisor.md)). All guest
memory there lives in one reserved host address window (512–960 GiB). With
the kernel lock held and every other vCPU stopped, the parent takes a Mach
memory entry for each region of it — a copy-on-write snapshot
(`MAP_MEM_VM_COPY`) of private memory, a share (`MAP_MEM_VM_SHARE`) of
`MAP_SHARED` memory — and encodes the kernel's state
(`Kernel::save_for_fork`, `crates/kernel/src/snapshot.rs`): signal
dispositions, the forking thread's mask and alternate stack, the break,
filesystem view, credentials, descriptor limits and every descriptor
registry, then the backend's own (registers, thread pointer, the VM's
mappings). It `posix_spawn`s `fwe --hv-fork-child` with all of its
descriptors (close-on-exec ones too, the flag cleared for the spawn and set
back on both sides; kqueues never pass and are rebuilt), and a receive right
of its own as the child's bootstrap port. The child asks there for its
state; the answer carries the memory entries, the real bootstrap port and
the state. The child reserves the window, maps each entry at the parent's
address, restores the kernel, creates its own VM over the same mappings and
resumes the guest after the `svc` with `x0` = 0. The parent returns once the
child is about to run; a `vfork` parent waits on until the child execs or
exits, and a `vfork` child is given shares of private memory as well, so its
writes reach the parent. Neither side pays for memory until it writes to a page. A guest that
has placed a `MAP_FIXED` mapping outside the window cannot fork (`EAGAIN`).

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
`clone3` reads the guest's `struct clone_args` and then goes the way of the
`clone` it describes (`crates/kernel/src/cloneargs.rs`): the stack is the
top of the range given, and the child's other registers are the parent's.
What fwe has no notion of — a pidfd, chosen tids, a cgroup, clearing the
handlers — fails with `ENOSYS`, which C libraries take as "use `clone`".

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
process — reaches the guest as it would on Linux. One difference is made
up for: a process-wide signal that arrives while every thread blocks it
stays pending for the process on Linux, for whichever thread unblocks it
first, while macOS parks it on one thread. In the native backend a thread
entering a system call with such a signal parked on it, one the guest
catches, takes it off the host and records it against the process, and
the other threads are woken to take it. Every fwe handler starts
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
waiting call that takes a mask (`ppoll`, `pselect6`, `epoll_pwait`) runs
under it, as
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
rides in the kevent `udata`. `epoll_pwait` writes the arm64 `epoll_event`
array in place: 16 bytes each, `data` at offset 8 (only x86-64 packs it).
The `EEXIST`/`ENOENT` edge cases of redundant `ADD`/`MOD` are not emulated
precisely on macOS.

`eventfd` and `timerfd` (`crates/kernel/src/specialfd.rs`) have no macOS
equivalent and are emulated in a process-global registry keyed by descriptor,
which `read`, `write` and `close` consult first. An eventfd is a pipe plus a
64-bit counter: the pipe holds one byte exactly while the counter is
non-zero, so the read end handed to the guest is readable, and pollable by
`kqueue` and hence by our `epoll`, precisely when a read would succeed. A
timerfd is a `kqueue` holding one `EVFILT_TIMER`, with millisecond
resolution; a periodic timer's distinct initial `it_value` and the
realtime/monotonic distinction are not modelled.

A kqueue cannot be passed to a child process, so each epoll descriptor's
interest list is also recorded (and kept up to date by `epoll_ctl` and
`close`), as is how each timerfd is armed; a fork child rebuilds both at the
same descriptor numbers. A timer's expirations not yet read when the process
forks are not carried over.

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
`/dev/pts/<n>` maps that number to the host slave device. Closing a master
keeps the number mapped: another process may still hold the master, as a
fork child closing its copy does before it opens the slave (apt runs dpkg
on a pty that way).

`pselect6` (what `select` is on arm64) turns its descriptor sets into a
`poll` and back. `statfs` and `fstatfs` report the host filesystem's sizes
and counts with ext4's type, and `msync` is the host's. `prctl` keeps a
thread name (`PR_SET_NAME`/`PR_GET_NAME`), reports the virtual root's full
capability bounding set, and records `no_new_privs`, dumpability and a
parent-death signal; other options fail with `EINVAL`.

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

Host user and group ids the guest sees — a file's owner from `stat`, a
signal's sender, a child in `waitid` — are mapped as a rootless container's
user namespace maps them (`host::uid_to_linux`): the host user fwe runs as
is root (0), and every other id is the overflow id 65534 (`nobody`). So a
guest running as its default root owns the files it creates, which is what
git's check that a repository belongs to its user relies on.

## Translation

Linux numbers (errno, flags, clock ids, signals, rlimits, ioctls) are
translated to host values in `crates/kernel/src/host.rs`, using the `libc`
crate. `crates/abi` holds the Linux side; syscall numbers and errno values are
generated from the Linux UAPI headers by `tools/gen-abi.py`.

## Known limitations

Each of these is on the [roadmap](../ROADMAP.md); this is the detail behind
those items.

- **Execution:** a non-PIE executable linked below 4 GiB runs only in the
  hypervisor backend, which needs `fwe` signed with the hypervisor
  entitlement and a bare-metal Apple Silicon Mac (Debian's GCC, clang and
  Python are such executables). A few rare `x18` forms are left unrewritten
  (see Rewriting guest code; `--strace` counts them), and so is any `x18`
  use in JIT code. Code discovery relies on section headers and the unwind
  table; a stripped binary has its whole executable segment scanned, and an
  inline jump table in code the unwind table covers could be patched.
- **Processes:** a `vfork` child shares the guest's memory but not its
  mappings (an `mmap` or `munmap` in it stays in the child); a fork child
  of a timerfd loses the expirations not yet read; in the native backend a
  thread inside fwe's code during a `fork` (in a system call) is not
  stopped, so a write it makes to guest memory then, such as a `read`
  completing into a buffer, may or may not reach the child; in a fork
  child, an epoll or timerfd descriptor
  duplicated with `dup` is gone (only the original number is rebuilt), a
  periodic timerfd restarts its period, and eventfd counters and signalfd
  queues are the child's own copies while their readiness pipes are shared;
  a VM fork that fails after spawning its child can have that child reaped
  by another thread's `wait4(-1)`; `execveat` of a descriptor finds its
  file by path (not one renamed or deleted since it was opened); `clone3`
  has no pidfds, chosen tids or cgroups (`ENOSYS`); `waitid` reports no
  `rusage`.
- **Locks:** open-file-description locks (`F_OFD_SETLK` and the like)
  fail with `EINVAL`, as on a kernel before 3.15, so a program falls back
  to process locks.
- **Sockets:** an `AF_UNIX` path that, rooted under the rootfs, is longer
  than the host's 103 bytes fails with `ENAMETOOLONG`.
- **Descriptors:** the guest's `RLIMIT_NOFILE` is not enforced: a guest
  that opens more descriptors than its limit gets numbers in fwe's range,
  which it cannot use, rather than `EMFILE`; a reopened
  `/proc/self/fd` entry for a pipe or socket shares the original's file
  description rather than getting a new one.
- **Memory:** `MADV_DONTNEED` on a private file mapping keeps modified pages
  where Linux would restore the file's. In the native backend, writable and
  executable memory takes a fault each time a page goes from being written
  to being run or back, which is slow for code that does both to one page
  often; a host system call writing into such a page while it is
  executable (a `read` into it, for one) fails with `EFAULT`.
- **Filesystem:** of `/dev`, only `null`, `zero`, `random`, `urandom`,
  `tty` and the `/proc/self/fd` links are provided; their `stat` reports
  the host's device numbers. File owners other than fwe's own user read as
  65534, and a `chown` does not show in a later `stat`.
- **Signals:** a real-time signal (`SIGRTMIN` and up, which the host lacks)
  can only be sent within the process; standard signals are not queued
  (one pending per signal, as Linux does for them); a signal left pending
  while blocked loses its sender on macOS, so `rt_sigtimedwait` then
  reports `si_pid` 0 (except `SIGCHLD`, whose child fwe looks up with a
  `waitid` that does not reap it); `rt_sigqueueinfo` is not implemented; a signal that
  arrives between a blocking call's start and its host wait can be noticed
  only when the call ends, except for `rt_sigsuspend`, `rt_sigtimedwait`
  and the masked waits, which close that window; a futex wait notices a
  signal within 20 ms; a call rerun after an interruption the guest does
  not see starts its timeout over; a fault signal sent by another process
  is treated as a fault; a process killed by a real-time signal exits with
  status 128 + the signal, since the host cannot report one it lacks; a
  process-wide signal left at its default action and sent while every
  thread blocked it stays with the thread macOS parked it on, rather than
  acting when another thread unblocks it (one the guest catches is
  handed on), and in the VM a caught one is not handed on either.
- **Event descriptors:** `epoll` `EEXIST`/`ENOENT` edge cases; `timerfd`
  resolution and clock distinctions; `pselect6` does not write back the
  time left.
- **Process control:** a parent-death signal (`PR_SET_PDEATHSIG`) is
  recorded but never sent, and a new thread does not inherit its creator's
  name.
- **Not implemented:** `rseq`, `membarrier` (optional for libc), and any
  system call not listed in `crates/kernel/src/syscalls.rs` returns `ENOSYS`
  and is noted under `--strace`.
