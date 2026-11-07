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
 │    └── hv           the hypervisor backend: VM, vCPU loop, loader, and a
 │                     software stand-in for Hypervisor.framework
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

In the native backend the guest sees the host page size (16 KiB on Apple
Silicon) through `AT_PAGESZ`, which the arm64 Linux ABI permits; in the
hypervisor backend, whose guest has page tables of its own, it sees Linux's
usual 4 KiB.

Every range of guest memory — the loaded images and their code stubs, the
stack, the break reservation and whatever the guest maps — is recorded
(`fwe_kernel::mm::track`), and removed when the guest unmaps it. fwe's own
memory (its heap, thread and signal stacks, the `rt_sigreturn` trampoline)
never is, so `execve` can discard exactly the old program.

The guest's mappings as Linux keeps them are recorded too
(`crates/kernel/src/maps.rs`), for `/proc/self/maps`, `/proc/self/smaps`
and `PROCMAP_QUERY`: each memory system call that succeeds, whichever
backend carried it out, with the protections and sharing the guest asked
for (memory mapped writable and executable is one or the other at a time
on macOS) and the file it maps, from which offset; the loaders add the
program, its dynamic linker (each segment the file's as far as the file
has contents, zeroed memory beyond) and the stack, and the break is the
heap. Memory the native backend maps for the guest that the guest did not
ask for (code stubs, a stack's guard page) is listed as anonymous memory
with the host's protections, so a program looking for free address space
in the list does not pick it. Locking (`mlock`, `mlock2`, `mlockall`,
`MAP_LOCKED`) brings the memory in and marks it locked, which `smaps`,
`VmLck` in `/proc/self/status` and the next lock's `RLIMIT_MEMLOCK` check
count; the host is not asked to wire it. `mincore` reports the host's
residency of each page.

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
  depends on the host preserving `x18`, and guest code runs without the
  mode (switching it at every trap cost two host calls, and one of them
  could hang).

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
Path and name arguments are shown as strings.
`--strace=failures` prints only the calls that fail, and the notes. That is
cheap enough to leave a run's timing much as it is, for a failure that
full tracing hides. A failed code preparation is noted with its reason,
for example no room for stubs near the code, while the guest gets
`ENOMEM`. Both modes are passed on across `execve` and `fork`.
`--strace-file=PATH` writes the trace to `PATH` instead, appended to by
every process of the run (each line naming its process), so a run of many
programs whose standard error is not the terminal's, as a container
engine's helpers are, is traced whole.

## Filesystem

The guest sees a filesystem rooted at a host directory, set with
`fwe --root DIR`; with no `--root` the root is the host `/`. What is mounted
on it is its mount namespace's mount table (see Containers): the rootfs at
`/`, and `/proc`, `/sys`, `/sys/fs/cgroup`, `/dev/pts`, `/dev/mqueue` and
`/dev/shm` as Linux always has them. Guest paths are resolved in
`crates/kernel/src/fs.rs` one component at a time, following symlinks
ourselves, entering a mount where one is attached to the directory reached,
and clamping `..` at the process's root, so a path can never escape it — the
containment `openat2(RESOLVE_IN_ROOT)` gives on Linux, done by hand so it
works on macOS too. Absolute symlink targets re-root at the process's root.
`*at` calls resolve relative to their directory descriptor, placed in the
namespace by where it was opened.

Guest file descriptors are host file descriptors: an opened file's host fd is
returned to the guest unchanged, so `read`, `write`, `lseek`, `fstat` and the
rest act on it directly. The descriptors fwe keeps for itself (the rootfs
handle, the write ends of the pipes behind the emulated event descriptors,
the pipe a `vfork` parent waits on) live in a reserved range at the top of
the host's descriptor space (`crates/kernel/src/fdtable.rs`). At startup fwe
raises its host soft limit as far as macOS allows and gives the guest a
virtual `RLIMIT_NOFILE` whose hard limit leaves fwe a quarter of the host's
descriptors (at least 64; soft 1024, as on Linux): besides the few above,
the VM backend keeps the file of every file mapping. A descriptor of fwe's
never goes below the range: when it is full, what needed one fails as Linux
would fail it (`EMFILE` for an `eventfd`, `ENOMEM` for an `mmap`, `EAGAIN`
for a `fork`). A guest that closes everything up to its limit,
calls `close_range(3, ~0)` or walks `/proc/self/fd` never reaches fwe's
descriptors, and a system call that names one fails with `EBADF`, as for a
descriptor that is not open; `dup2` onto one fails the same way, and the
limit cannot be raised into the range. The soft limit holds as on Linux: a
call that would make a descriptor numbered at or above it fails with
`EMFILE` (the descriptor closed again, with what fwe keeps for it), `dup3`
onto one with `EBADF` and `F_DUPFD` from one with `EINVAL`. A new
descriptor is the lowest free number, as on Linux (a daemon that closes
0 to 2 counts on the files it opens next taking them): the directory a
path resolves to, which fwe holds while the call runs, is moved into the
reserved range first. `stat` results are translated into the arm64 Linux
layout (`statx` too); `getdents64` is built from `getdirentries` on macOS, re-reading from the
directory position when the translated entries outgrow the guest's buffer.
Creation modes have the umask applied by the kernel. An `O_CREAT` open
that macOS fails with `ENOENT` because another process is unlinking the
name at that moment is retried, as Linux would have created the file. `fcntl` translates the
descriptor and status flags, and record locks (`F_GETLK`, `F_SETLK`,
`F_SETLKW`: the arm64 `struct flock` and its lock types differ from the
host's); `flock` passes through. The owner `SIGIO` goes to (`F_SETOWN`,
`F_SETOWN_EX`) is the host's; what Linux keeps on an open file and the
host has no place for — an owner that is a thread, the signal `F_SETSIG`
names, a lease, a pipe's capacity (`F_SETPIPE_SZ`) — is kept by fwe
(`crates/kernel/src/fdstate.rs`), read back as set and checked as Linux
checks it, without effect on the host (no lease is broken, and a pipe holds
what the host's does). Both kinds of lock are the host's, so they
hold between guest processes and against host ones. `ioctl` covers the
terminal, pty and `FIO*` requests, and the network interface ones
(`SIOCGIFFLAGS` and the like).

Each open file remembers the mount it was opened through
(`crates/kernel/src/fdmarks.rs`), as Linux's open files do: `fstatfs`
reports that mount's type and flags, `/proc/self/fd` its path, and a
`/proc/self/fd/N` link names that file to `chmod`, `mount` and the like,
even after the mount is detached or the path removed. The record follows
the descriptor through `dup`, `close`, `fork` and `execve`, and one whose
descriptor no longer names the same file is never trusted. Writes on a
read-only mount fail with `EROFS`, a rename or link across mounts with
`EXDEV`, and the removal of a mount's root with `EBUSY`. `sendfile` and
`copy_file_range` copy between descriptors.

Extended attributes (`crates/kernel/src/xattr.rs`) are the host's of the
same name: a Linux name is always in one of Linux's namespaces (`user.`,
`trusted.`, `security.`, `system.`), so it meets neither the host's own
nor fwe's (`org.fwe.`), and a list shows only those. Linux's rules apply:
`user.` attributes are for regular files and directories, `trusted.` ones
need `CAP_SYS_ADMIN` (and are hidden from others), writing a `security.`
one needs `CAP_SYS_ADMIN` (`CAP_SETFCAP` for `security.capability`), and
`system.` (ACLs) is not kept.

Every guest file is the host user's, so the host checks its owner's bits
on every access, where Linux's root passes them (`CAP_DAC_OVERRIDE`) and
container tools count on it (a layer directory made `0555`, then filled).
So a mode that denies its owner something is kept apart
(`crates/kernel/src/modes.rs`): on the host the file keeps the owner's read
and write (and search, for a directory), and the guest's mode is in an
attribute, the file flagged (`UF_NODUMP`) so that a `stat` shows at once
whether to look for it. `stat` reports the kept mode; a caller without the
capabilities is held to the owner's bits of it by fwe; and a file the host
refuses root, made by something else, is converted the first time.

A memfd (`memfd_create`, `crates/kernel/src/memfd.rs`) is a file in fwe's
private directory, unlinked as soon as it is made, with its name and its
seals in extended attributes, so every process that holds it sees the
same ones. `/proc/self/fd` names it `/memfd:<name> (deleted)`. The resize
seals are checked by `ftruncate` and `fallocate`. `F_SEAL_WRITE` clones
the file and replaces each of this process's descriptors of it with a
read-only one of the clone, keeping offsets, flags and shared open file
descriptions. The host then refuses writes and writable shared mappings,
and they fail with `EPERM`. A program run through a descriptor, as crun
runs its sealed copy of itself (`execveat(fd, "", AT_EMPTY_PATH)`, under
the name Linux gives it, `/dev/fd/N`, or a `/proc/self/fd` path), is read
through it, whatever has become of its path. fwe keeps a descriptor of
the program, which `/proc/self/exe` opens, and hands it on by number
(`--exe-fd`) when it re-executes itself.

## Synthetic /proc and /sys

`proc` and `sysfs` are filesystems of fwe's own: a path in a mount of
one is answered by `crates/kernel/src/procfs.rs` (and `procpid.rs` for
another process's `/proc/<pid>`) instead of a host directory, which
generates what programs read: `/proc/self/exe` (a link that opens the
program itself), `/proc/self/{cmdline,stat,status,cgroup,mountinfo,mounts,
uid_map,gid_map,setgroups,maps,smaps}`, `/proc/self/fd`, `/proc/self/ns`,
`/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat`,
`/proc/uptime` and `/proc/loadavg` (the host's uptime and load, which
`sysinfo` reports too, with the same fixed memory figures as
`/proc/meminfo`), `/proc/sys/kernel/{ostype,osrelease,
version,hostname,domainname,pid_max,cap_last_cap,ngroups_max,overflowuid,
overflowgid,threads-max,tainted}`, `/proc/sys/fs/{nr_open,file-max,pipe-max-size,
lease-break-time}`, `/proc/cmdline`,
`/proc/sys/vm/{overcommit_memory,mmap_min_addr}`, `/sys/fs/cgroup` (a
mount point) and `/sys/devices/system/cpu/{online,possible}`.
`/proc/self/auxv` is the auxiliary vector the program started with, and
`/proc/stat` the host's CPU times and boot time. `/proc/config.gz` is the
kernel configuration fwe presents: the options of what it implements, so
a program or test suite that checks the kernel's configuration finds what
fwe has (and takes an option not listed as not set). `/proc/self/task`
lists the process's threads; each `task/<tid>` has the thread's `stat`
(its own state and CPU time), `status` and `comm`. A process's state in
`stat` is its main thread's, as on Linux: `S` while it waits in a system
call, which programs wait to see (and while it waits for one of fwe's own
locks, where Linux would show it running). A network namespace of
fwe's has sysctls of its own (`crates/kernel/src/sysctl.rs`:
`net/ipv4/ping_group_range`, `ip_unprivileged_port_start` and the like),
kept in its record, written with Linux's checks; the initial namespace's
are Linux's defaults. `/proc/self/fd/N`, `/proc/self/cwd` and
`/proc/self/root` lead out of `/proc` in the middle of a path, as Linux's
magic links do (a program that binds a socket at
`/proc/self/fd/N/name`, to keep the path short). File content is served from
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
are links into `/proc/self/fd`. `/dev/shm`, the tmpfs Linux mounts there
for POSIX shared memory and semaphores (`shm_open`, `sem_open`, Python's
`multiprocessing` locks), is a directory of fwe's for each rootfs, shared
by every fwe process running on that root and private to the user:
`fwe-<uid>/shm-<hash of the root's host path>` in the user's temporary
directory. The resolver treats it as a mount point — reached by any path
that leads to `/dev/shm`, symlinks included, whether or not the rootfs has
a `/dev`, with `..` from it the root's `/dev` — and a descriptor of a file
in it reports its `/dev/shm` path.

A program given to fwe by a host path inside the rootfs gets that file's
guest path as its `argv[0]` and `AT_EXECFN`, as it would have been named in
the guest (Python finds its installation from `argv[0]`); `--argv0` still
sets one of its own.

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
`RLIMIT_NOFILE`, the resource limits fwe keeps and the umask — as one
encoded `--exec-state`
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
(`crates/native/src/hv/fork.rs`, [hypervisor.md](hypervisor.md#fork)). With
the kernel lock held and every other vCPU stopped, the parent encodes the
kernel's state (`Kernel::save_for_fork`, `crates/kernel/src/snapshot.rs`):
signal dispositions, the forking thread's mask and alternate stack, the
break, filesystem view, credentials, descriptor limits and every descriptor
registry, the translated guest ranges, then the backend's own (registers,
thread pointer and pointer-authentication keys, the guest's mapping records
and the slab's use). It `posix_spawn`s `fwe --hv-fork-child` with all of its
descriptors (close-on-exec ones too, the flag cleared for the spawn and set
back on both sides; kqueues never pass and are rebuilt), a socket pair for
the memory, and a receive right of its own as the child's bootstrap port.
The child asks there for its state; the answer carries the real bootstrap
port and the state. A `fork` child receives a copy of the parent's memory; a
`vfork` child fetches it as it goes and sends back what it changed before
the parent resumes. The parent returns once the child is about to run; a
`vfork` parent waits on until the child execs or exits.

`wait4` reaps a child through the host, translating the status into the
Linux encoding and the resource usage into Linux units (`ru_maxrss` in KiB);
`waitid` reports the same as a `siginfo_t` (its `rusage` is zero-filled: the
host's `waitid` has none). `getrusage` translates likewise. `getpid` is the
main thread's tid; child pids are host pids, so `kill`, `setpgid` and `wait`
on them act on the real processes.

A process's nice value (`setpriority`, `getpriority`) is in its record
(`crates/kernel/src/procreg.rs`), inherited by its children and shown in
`/proc/<pid>/stat`, set with Linux's checks (another user's process, or a
lower value than `RLIMIT_NICE` allows, takes `CAP_SYS_NICE`); the host's
scheduling is untouched. The resource limits the host has no counterpart
of, and `RLIMIT_MEMLOCK` (fwe wires no memory: `mlock` and its family
check the range and the limit, as Linux does, and lock nothing on the
host), are fwe's (`crates/kernel/src/rlimits.rs`), set as Linux sets them;
the others are the host's. The interval timers are the host's, but one
longer than the host takes (100,000,000 seconds) is given the host's
longest and reads back as asked. A thread's or process's CPU-time clock
(the clock ids `pthread_getcpuclockid` and `clock_getcpuclockid` make) is
the host thread's or process's CPU time.

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

Futexes (`crates/kernel/src/futex.rs`) block outside the kernel lock, so
`FUTEX_WAIT` waits without holding it. A wake takes its waiters off the
futex's queue, oldest first, and marks each woken, whatever the word holds,
so it reports how many it woke, as Linux does (test harnesses count on it);
`FUTEX_WAIT_BITSET`/`FUTEX_WAKE_BITSET` match waiters by their bits, and
`FUTEX_CMP_REQUEUE` moves waiters from one futex to another. A private
futex (`FUTEX_PRIVATE_FLAG`) is the process's: its queues live in the
process. A shared one may be woken from another process that maps the
same memory (a process-shared lock, condition or semaphore), so its
waiters are in a table every fwe process maps
(`crates/kernel/src/sharedfutex.rs`), keyed as Linux keys a shared futex:
by the memory object and offset Mach reports for shared memory (the same
in every process that maps it, wherever), by process and address for
private memory. A waiter sleeps on its slot's own word, a host shared
address wait (`__ulock_wait2`), which a wake changes and wakes; the
host's own address waits cannot say whom they woke. Waiters check every
20 ms for a signal they should take (a host condition variable is not
interrupted by signals), and return `EINTR` for it.
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
process group, the caller itself — when the caller may signal it, as Linux
checks (`CAP_KILL`, or its real or effective user is the target's real or
saved one, or `SIGCONT` within its session; a process fwe did not start
counts as root's). `kill(-1)` reaches every other process of the caller's
pid namespace, or outside one, of its run of fwe (the processes started,
one from another, from the same first fwe process, `procreg::run`): never
the host's other processes. `tgkill` sends it to that guest thread's
host thread, except a signal the backend catches, which is recorded
against that thread directly and the thread woken.

Each disposition is passed to the host. The backend catches a signal with
a guest handler, one a `signalfd` or `rt_sigtimedwait` reads, and one whose
default action ends or stops the process, which fwe then takes itself: it
ends the process with that signal, or stops it with that signal, so the
parent sees the status Linux gives. The host takes the remaining defaults,
ignoring a signal or continuing the process, and `SIG_IGN`. At startup a
signal fwe inherited as ignored stays ignored in the guest (`nohup`, a
shell's background jobs). A signal from anywhere — a child exiting
(`SIGCHLD`), the terminal, a timer (`setitimer`), another process —
reaches the guest as it would on Linux.

The host never blocks a signal the backend catches, whatever the guest's
mask: macOS forgets the sender of a signal it holds blocked, and Linux
keeps it. The handler records each one as it arrives, with its sender,
code and status, and fwe keeps it pending while the guest blocks it. A
signal that lands on a thread whose guest mask blocks it is the process's,
as Linux keeps it, for whichever thread accepts it first, and the other
threads are woken to take it. The exception is `SIGPIPE` and `SIGXFSZ`,
which the host directs at the thread whose write caused them. Each thread
runs under a host mask that blocks only the guest-blocked signals the host
acts on itself, so the host keeps those pending. Before a host `execve`
that re-executes fwe, the whole guest mask goes on the host, and the
signals fwe holds pending that the guest blocks go to the host, pending on
the thread, which `execve` keeps.

A standard signal already pending keeps the `siginfo` it was first raised
with, as Linux drops a later instance. An adopted orphan's `SIGCHLD` comes
before its former parent's, as Linux sends them when the parent ends: it
takes the place of the parent's while that is pending, and absorbs one that
comes after it. fwe's own handlers run with every signal blocked, so a
signal arriving during one (a child's `SIGUSR1`, then its `SIGCHLD`) is
taken after it with the `siginfo` macOS emptied; an fwe process that sends
another a signal leaves a note of itself in the target's mailbox, beside
its process record, which the target's handler reads then
(`crates/kernel/src/signote.rs`). The parent
of a `fork` holds every signal blocked across the host call, so a child
goes on only once its parent has unblocked them: a signal it sent sooner
would lose its sender.

A process-wide signal the host holds can still be parked on one thread,
which never takes it, while the thread runs fwe's handlers with every
signal blocked. In the native backend a thread entering a system call
with such a signal parked on it, one the guest catches, takes it off the
host and records it against the process, and the other threads are woken
to take it. Every fwe handler starts
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
itself, because macOS's `siginfo` cannot tell a sent one from a fault (it
gives a sent one the thread's last fault). One another fwe process sent is
told apart by the sender's note: the fault handler takes a fault signal
with a fresh note as a signal for the guest, whether it interrupted guest
code or fwe's (a genuine fault coinciding with a note faults again). A
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

## System V IPC

Shared memory segments, semaphore sets and message queues
(`crates/kernel/src/sysvipc.rs`, the calls in `crates/kernel/src/ipcops.rs`)
are an IPC namespace's: its record holds every object's key, owner,
permissions and times, a set's values and `SEM_UNDO` adjustments, a queue's
messages, and the namespace's limits (`kernel.shmmax`, `kernel.sem`,
`kernel.msgmni` and the rest, which root may change through `/proc/sys`).
The initial namespace's record is the host boot's, so its objects last
until the machine restarts, as Linux's do. A segment's memory is a file
beside the record, which `shmat` maps shared (at an address rounded to
`SHMLBA` with `SHM_RND`, over a mapping only with `SHM_REMAP`); a fork child
counts its parent's attachments, and `execve` and the process's end detach
them. Each operation is one change of the record under its lock, so
`semop`'s operations happen all at once or not at all across processes;
one that must wait (a semaphore that would go below zero or is not yet
zero, a full or empty queue) waits, without the kernel lock, for the record
to change, and tries again (`EINTR` for a signal, `EIDRM` if the object
goes, `EAGAIN` at `semtimedop`'s timeout). A process is known by pid and
start time: what one that has gone leaves — attachments, undo adjustments,
which are applied — is cleaned up by the next process that looks, so even
one killed outright gives its semaphores back. `/proc/sysvipc/{shm,sem,msg}`
list the namespace's objects.

## Event descriptors

`epoll_create1`, `epoll_ctl` and `epoll_pwait` (`crates/kernel/src/epoll.rs`)
pass through on Linux and are translated to `kqueue` on macOS: the epoll
descriptor is a kqueue, each watched fd becomes an `EVFILT_READ` filter for
`EPOLLIN` and an `EVFILT_WRITE` filter for `EPOLLOUT`, `EPOLLET` maps to
`EV_CLEAR` and `EPOLLONESHOT` to `EV_ONESHOT`, and the caller's data word
rides in the kevent `udata`. `epoll_pwait` writes the arm64 `epoll_event`
array in place: 16 bytes each, `data` at offset 8 (only x86-64 packs it).
Events are reported as Linux reports them: a socket whose reading side is
shut is `EPOLLIN | EPOLLRDHUP` (a socket watched for `EPOLLRDHUP` alone has
a read filter at a low-water mark no read reaches, so only the end fires),
`EPOLLHUP` is a pipe whose writers have gone or a socket shut both ways,
a pipe with no reader left is `EPOLLERR` to its writer, and only the
events asked for are reported, with `EPOLLERR` and `EPOLLHUP` always.
`epoll_ctl` checks as Linux does, in its order: a file or directory cannot
be watched (`EPERM`), the set must be one (`EINVAL`), an entry added twice
is `EEXIST` and one not there `ENOENT`, and a set watching a set may not
watch itself through others nor nest deeper than Linux's limit (`ELOOP`).

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
same descriptor numbers. A one-shot timer that expired before the fork, its
expiration unread, is readable in the child at once; a periodic timer's
expirations not yet read are not carried over.

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

`AF_UNIX` socket paths are resolved as file paths are, in the guest's
filesystem (`fs::resolve_host`; the socket calls run without the kernel
lock, so the process's root and working directory are published for them):
a relative path from the working directory, `..` kept inside the root,
symlinks followed inside it, `/dev/shm` included. `bind` follows no final
symlink and takes a name that exists as in use (`EADDRINUSE`), as Linux
does; macOS's would follow it. Abstract-namespace names (a leading NUL) map to files under a per-host
temporary directory, since macOS has no abstract namespace. `SCM_RIGHTS`
ancillary data is re-encoded, since `cmsg_len` is 64-bit on Linux and 32-bit
on macOS; the passed descriptors are host descriptors and work in the
receiver directly. macOS limits a socket path to 104 bytes, which a short
guest path under a long root can pass: such a socket is bound or connected
by its name from its directory, the calling thread's alone
(`pthread_fchdir_np`). A socket's node has the socket's mode less the
umask: every bit, or what `fchmod` gave the socket before it was bound.

macOS has no `SOCK_SEQPACKET` Unix sockets, so fwe makes one of a stream
socket (`crates/kernel/src/seqpacket.rs`): each message is framed on the
stream, its length first, and a receive takes one whole message, cut to
the buffer (`MSG_TRUNC`) with the rest dropped, so boundaries are kept;
a send is whole or, without blocking, `EAGAIN`. The rest is the stream's
own, so it can listen, connect and accept, and a peer's close is
end-of-file to `read`, `poll` and `epoll` alike. Its buffers hold two of
the largest messages, and their odd size marks it, so a process that
receives one with `SCM_RIGHTS` knows it for what it is. A message is sent
or taken under the socket's lock for that way, which the threads of a
process share as a mutex and processes as a byte-range lock on a file of
fwe's, so neither threads nor processes interleave or split one.

`SO_PEERCRED` names a Unix socket's peer (its pid in the caller's pid
namespace, its ids as the guest sees the host's), and `shutdown` of a Unix
socket whose peer has gone succeeds, as on Linux.

In a network namespace of fwe's, an `AF_NETLINK` socket of the
`NETLINK_ROUTE` family (`crates/kernel/src/netlink.rs`) answers what a
container runtime asks of its loopback: `RTM_GETLINK` describes `lo`,
`RTM_NEWLINK` brings it up or down, `RTM_GETADDR` lists its addresses once
up, anything else is answered with `EOPNOTSUPP`. The guest's descriptor is
one end of a host datagram pair, fwe writing each reply to the other, so
receiving and `epoll` are the host's own. In the initial namespace, whose
interfaces are the host's, there is no netlink socket (`EAFNOSUPPORT`).

DNS needs no special support: the guest's resolver reads
`/etc/resolv.conf` and `/etc/hosts` from the rootfs and talks to nameservers
over these sockets. Raw sockets are M4.

Named FIFOs differ on the host in two ways fwe makes up for
(`crates/kernel/src/fifo.rs`). macOS reports neither to `kqueue` nor to
`poll` that a FIFO's last writer has gone: fwe's `epoll` and `ppoll`
watching a FIFO's read end wait in short slices and look between them with
the host's `select`, which asks the FIFO's underlying socket and finds it
readable with nothing to read once a writer has been there and gone. They
report `POLLHUP` as Linux does (once to an edge-triggered or one-shot
`epoll` entry; a signal ends the wait between slices), after the data still
buffered has been read. The look reads nothing, so a process holding a
FIFO's read end only to keep it open takes no data from its reader. An
open of a FIFO that waits for its other end runs outside the kernel lock,
so the process's other threads run on.
An `O_PATH` descriptor never opens a FIFO, which on the host would count as
a reader or writer of it: like one of a device or socket the host cannot
open, or of a symbolic link itself (`O_NOFOLLOW`), it is a stand-in that
names the file, whose `fstat`, `readlinkat`, `faccessat2`, `utimensat` and
fdinfo are the file's and through whose `/proc/self/fd` link the file is
opened again.

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
host ownership (shadow ownership is not tracked), and a virtual root passes
permission bits as Linux's does (see Filesystem).

Host user and group ids the guest sees — a file's owner from `stat`, a
signal's sender, a child in `waitid` — are mapped as a rootless container's
user namespace maps them (`host::uid_to_linux`): the host user fwe runs as
is root (0), and every other id is the overflow id 65534 (`nobody`), then
through the guest's own user namespace, if it is in one. So a guest
running as its default root owns the files it creates, which is what git's
check that a repository belongs to its user relies on. What the guest may
do is decided by its capabilities (see Containers).

## Containers

### Shared state

What Linux keeps in one kernel for every process — namespaces, mount
tables, the cgroup tree — has to be seen by every fwe process, so it lives
in fwe's private directory on the host (`crates/kernel/src/shared.rs`): a
directory per record, its data replaced whole by each change under a lock,
and a generation count each process maps, so that it rereads the data only
after another has changed it. A record's name carries a format number, so
one written by another fwe build is never read. fwe also keeps a record of
each process (`crates/kernel/src/procreg.rs`): its start time (so a record
outlives no process into a new one with its pid), cgroup, namespaces, name,
command line and program. A record no live process holds is collected
(`shared::collect`) when a namespace is made and when a fresh fwe starts.

### Mounts

Each mount namespace has a table (`crates/kernel/src/mounts.rs`) of mounts,
each attached at a path to a parent mount, as on Linux: stacked mounts,
`pivot_root(".", ".")` and the unmount of the old root behave as there. A
mount shows a host directory (the rootfs, a bind mount's source, a tmpfs's
backing directory in fwe's private directory), a stack of them (an
overlay), or one of fwe's own filesystems (`proc`, `sysfs`, `devpts`,
`mqueue`; `cgroup2` is the shared tree). `mount` (new mounts, bind and
recursive bind, move, remount, propagation), `umount2`, `pivot_root` and
`chroot` act on it, and `/proc/self/mountinfo` and `/proc/self/mounts`
show it from the process's root.

An overlay (`crates/kernel/src/overlay.rs`) is resolved as Linux's
`overlay` filesystem resolves it: each name in the upper layer, then in
the lower ones in turn, directories of one name merging; a whiteout (a
device node numbered 0:0) hides a name below it and an opaque directory
(`trusted.overlay.opaque`, or `user.overlay.opaque` with `userxattr`) what
is below it. A call that changes a file of a lower layer copies it up
first, its directories with it (a regular file as an APFS clone, which
shares its blocks until written); a removal of what a lower layer has
leaves a whiteout; `getdents64` lists the layers merged. A descriptor of a
lower layer's file that is then changed through it (`fchmod` and the like)
is moved onto the copy, as Linux moves it: the copy records the file it
is of. A descriptor opened through an overlay keeps that overlay's layers,
so it is the overlay's file even once the mount has gone or moved, and a
layer's directory opened as itself is never taken for the overlay's. Each change is built in the
work directory and moved into place with one atomic rename, so other
processes see it whole. The overlay's own attributes are hidden from its
files, and a mount option asking for what fwe does not do (`metacopy=on`,
`redirect_dir=on`, `index=on`) is refused, as by a kernel without it.

### Namespaces

`clone` and `unshare` make the namespaces they ask for: mount, UTS, IPC,
network, cgroup, pid and user (`crates/kernel/src/nsops.rs`). The parent
makes the child's before the host `fork` and has them for the fork, so the
child inherits them (a VM fork child from its snapshot). A process in an
initial namespace sees the host's: its host name, its pids.

- **pid** (`pidns.rs`): a namespace numbers its processes and threads from
  1 and maps each number to its host pid; `getpid`, `getppid`, `kill`,
  `wait4`, `waitid`, the process-group, session and terminal calls and
  the senders in `siginfo` are translated. When its init ends, however it
  ends (its parent watches it, so also when the host kills it), every
  other process in it is killed, and its parent's `wait` reports it only
  once they have gone; from inside the namespace, its init cannot be sent
  `SIGKILL` or `SIGSTOP`.
- **UTS**: `uname`, `sethostname`, `setdomainname` and
  `/proc/sys/kernel/hostname` use its names.
- **network** (`netns.rs`): a loopback interface, down until brought up;
  its sockets reach only loopback addresses, and its ports are its own (a
  bound port is a host loopback port its table maps, translated both
  ways); abstract `AF_UNIX` names are its own.
- **user** (`userns.rs`): credentials are kept as the initial namespace's
  ids and seen through the namespace's `uid_map` and `gid_map`, which are
  written once through `/proc/<pid>/uid_map` and the like, with Linux's
  rules; a process that makes one has every capability in it.
- **cgroup**: `/proc/self/cgroup` and a `cgroup2` mount show the tree from
  its root.
- **IPC**: its identity (there are no System V IPC objects).

An orphan is adopted as on Linux, by its nearest living ancestor that is
a child subreaper (`PR_SET_CHILD_SUBREAPER`), or else by the init of its
dying parent's pid namespace (`crates/kernel/src/reaper.rs`); macOS gives
every orphan to launchd, and only a parent can wait for a process, so fwe
keeps the adoption itself. Each process's record holds its line of
ancestors and whether it is a subreaper, so an orphan's `getppid` (and
`/proc/<pid>`) names its adopter. A process that ends where a reaper
might adopt it records how it ended; one killed by `SIGKILL` cannot, and
whoever finds it gone records that for it. Its parent's `wait` removes the
record, or once the parent has gone, the adopter's `wait` takes it. A
reaper runs a watcher thread that follows its descendants on the host
(`kqueue` process events) and, when an adopted one ends, stops or
continues (the signals it is sent, and then its state), raises a
`SIGCHLD` in the reaper (pending for the guest with a child's `siginfo`,
its disposition, mask and `SA_NOCLDSTOP` acting on it as on a child's; not
through the host, where a `SIGCHLD` held or being delivered would absorb
it) and wakes its threads waiting in `wait`, which look at its
own children and then at its adopted ones. As on Linux, an orphan keeps
the adopter it had when its parent ended: a process that becomes a
subreaper notes the orphans below it that have one already, and one that
stops being a subreaper keeps those it adopted.

`/proc/<pid>` shows the processes of the reader's pid namespace (`stat`,
`status`, `cmdline`, `comm`, `exe`, `cgroup`, `ns`, `fd`, `oom_score_adj`,
the maps), from their records and what the host reports of their
descriptors; `/proc/self/ns` names each namespace, its links followed by
`stat` to the namespace itself (its number the inode, as nsfs shows it),
and `/proc/self/fdinfo` describes each descriptor. A process's
`oom_score_adj` is in its record, inherited by its children (going below
the last value a privileged process set takes `CAP_SYS_RESOURCE`), and so
are its user and group ids, which its files there are owned by.

### cgroups

The cgroup v2 hierarchy (`crates/kernel/src/cgroupfs.rs`) is one tree for
the user's fwe processes, of real directories with their interface files.
`mkdir` makes a cgroup with the files of the controllers its parent
enables; `rmdir` removes an empty one. Writing a pid to `cgroup.procs`
moves the process, under Linux's rule that a cgroup enabling controllers
for its children has no processes. Opening `cgroup.procs`, `cgroup.events`
or a counter shows what is so then. `cgroup.freeze`, `cgroup.kill` and
`pids.max` act. Device programs (`BPF_PROG_TYPE_CGROUP_DEVICE`, loaded with
`bpf`) attached to a cgroup decide every device open and `mknod` of its
members; they run on an interpreter (`crates/kernel/src/bpf.rs`) that
checks each access against the context and the stack and stops a program
that runs too long. A program of another type loads (libraries probe the
kernel's features by loading one) but is not attached (`EINVAL`), and
`/proc/self/fdinfo` shows a program's type, identity and tag (Linux's:
the first 8 bytes of its instructions' SHA-1).

### Capabilities, seccomp and devices

The five capability sets and the securebits (`crates/kernel/src/caps.rs`)
change with `capset`, the capability `prctl`s, `setuid` and `execve` as on
Linux (no file capabilities or set-ID programs), and a privileged call
checks a capability, not the uid: `CAP_SYS_ADMIN` to mount, `CAP_SETUID`
to change uid, `CAP_DAC_OVERRIDE` to pass permission bits, and the like.
seccomp filters (`crates/kernel/src/seccomp.rs`) are classic BPF on
`seccomp_data`, checked before each backend routes a call; the action of
highest precedence is taken, and filters and `no_new_privs` are kept across
`fork` and `execve`. A device node made with `mknod` is an empty file fwe
marks (`crates/kernel/src/devnodes.rs`): `stat` reports the device, and
opening it opens the host device its numbers name. `/dev/full`, which the
host lacks, is fwe's own node.

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
  of a periodic timerfd loses the expirations not yet read; in the native backend a
  thread inside fwe's code during a `fork` (in a system call) is not
  stopped, so a write it makes to guest memory then, such as a `read`
  completing into a buffer, may or may not reach the child; in a fork
  child, an epoll or timerfd descriptor
  duplicated with `dup` is gone (only the original number is rebuilt), a
  periodic timerfd restarts its period, and eventfd counters and signalfd
  queues are the child's own copies while their readiness pipes are shared;
  a VM fork that fails after spawning its child can have that child reaped
  by another thread's `wait4(-1)`; `clone3`
  has no pidfds, chosen tids or cgroups (`ENOSYS`); `waitid` reports no
  `rusage`; a process a signal ends writes no core file, and its status
  never has the core-dump bit.
- **Resources:** the limits the host keeps (`RLIMIT_NPROC`, `RLIMIT_STACK`,
  `RLIMIT_CPU` and the like) cannot be raised past the host's hard limit,
  even by root, and the host acts on them as macOS does (it sends no
  `SIGKILL` at the hard CPU limit).
- **Mappings:** another process's `/proc/<pid>/maps` is not available (a
  process's record is its own); in the hypervisor backend, residency
  (`mincore`, `Rss`) is by the host's 16 KiB pages, so a 4 KiB guest page
  is in memory when its neighbour in the host page is; `PROCMAP_QUERY`
  gives no build IDs; `POSIX_FADV_DONTNEED` leaves the host's cache as it
  is.
- **Locks:** open-file-description locks (`F_OFD_SETLK` and the like)
  fail with `EINVAL`, as on a kernel before 3.15, so a program falls back
  to process locks.
- **Sockets:** a `sendto` to an `AF_UNIX` path that, rooted under the
  rootfs, is longer than the host's 103 bytes fails with `ENAMETOOLONG`
  (`bind` and `connect` reach it from its directory).
- **Files:** `fallocate` reserves space past the end of a file (mode 0
  and `FALLOC_FL_KEEP_SIZE`) and punches holes, but a hole inside a sparse
  file is not filled, and its other modes are `EOPNOTSUPP`, as on a Linux
  filesystem without them. `/dev/shm` outlives the processes that use it,
  until the host clears its temporary files, and a `rename` between it
  and the rootfs succeeds where Linux returns `EXDEV`. A memfd sealed
  against writing cannot be resized, even without `F_SEAL_SHRINK` and
  `F_SEAL_GROW`; `F_SEAL_GROW` alone does not stop a write past the end;
  `F_SEAL_WRITE` succeeds although a writable shared mapping exists
  (Linux fails it with `EBUSY`), does not reach the descriptors another
  process holds, and gives the file a new inode number. A memfd reopened
  through `/proc/self/fd` shares the original's offset. An `O_PATH`
  descriptor of a file fwe could open reads and writes as an ordinary one
  would (Linux refuses both with `EBADF`).
- **Descriptors:** what fwe keeps of an open file for `fcntl` (an owner
  thread, `F_SETSIG`'s signal, a lease) is kept per descriptor, so a
  duplicate's changes do not show in the original as they would on Linux;
  `pwritev2` with `RWF_APPEND` sets `O_APPEND` on the open file for the
  call, which another writer sharing it would see meanwhile. Descriptors received with `SCM_RIGHTS` are not held to
  the guest's `RLIMIT_NOFILE` (every other way of making one is); a reopened
  `/proc/self/fd` entry for a pipe or socket shares the original's file
  description rather than getting a new one.
- **Memory:** `MADV_DONTNEED` on a private file mapping keeps modified pages
  where Linux would restore the file's. In the native backend, writable and
  executable memory takes a fault each time a page goes from being written
  to being run or back, which is slow for code that does both to one page
  often; a host system call writing into such a page while it is
  executable (a `read` into it, for one) fails with `EFAULT`. In the VM, a
  buffer a host call is given whole (`read`'s, an `iovec`'s) that runs from
  one translated guest range into another fails with `EINVAL` (it has no
  single host address), and `ioctl`'s argument is translated but not
  checked against the guest's mappings (it is a pointer only for some
  requests). A guest mapping placed with `MAP_FIXED` exactly where fwe keeps
  the memory of another, translated range makes their addresses ambiguous
  to the kernel within a system call that translated a pointer into that
  range.
- **Filesystem:** of `/dev`, only `null`, `zero`, `full`, `random`,
  `urandom`, `tty` and the `/proc/self/fd` links are provided, and a node
  `mknod` makes opens a host device only for those numbers (`ENXIO`
  otherwise); a node lists as a regular file in `getdents64`. File owners other
  than fwe's own user read as 65534, and a `chown` does not show in a
  later `stat`. A caller without the capabilities is held only to the
  owner's bits of a kept mode, and a directory's search bit is not
  enforced for it.
- **Mounts:** mounts do not propagate between namespaces, whatever their
  propagation type; a remount of a filesystem acts on the one mount; a
  tmpfs's `size=` is not enforced; a mount cannot be busy (`umount2`
  always detaches). An overlay's layers must be host directories (not in
  another overlay); a directory a lower layer has cannot be renamed
  (`EXDEV`, as with `redirect_dir=off`); a rename that leaves a whiteout
  behind, and a `bind` over one, are two host steps, between which another
  process can see the lower layer's file at that name; a lower layer's
  file that another was renamed over, changed through a descriptor of it,
  fails with `ESTALE`, and one moved onto its copy-up loses the
  record locks held through it; descriptors of one overlay directory
  (`dup`, `fork`) each keep their own place in its listing.
- **Namespaces:** a network namespace has a loopback interface only (no
  `veth`; netlink describes and brings up only it, its port numbers
  unique within a process rather than the namespace), and a datagram to one of its ports nobody bound by
  number goes to the host loopback port of that number; the initial
  namespace's sysctls cannot be changed (they would be the host's); a
  port is freed
  when the last descriptor of its socket in the binding process closes;
  capabilities are the process's, not qualified by user namespace;
  `setns` is not implemented; a pid namespace's init killed from outside
  fwe after its parent ran another program (`execve`) ends its namespace
  only once that parent reaps it or a reaper sees it gone; a reaper sees
  an adopted orphan's state after each signal it is sent, so a stop and a
  continue sent together, before it looks, are not reported, and stops
  not yet reported are forgotten when the reaper runs another program;
  `/proc/<pid>` of another process has no `cwd`, `root` or `environ`, and
  shows only fwe's processes in the initial pid namespace; resource limits
  set on another process with `prlimit` take effect at its next limit
  call, `fork` or `execve`, and reading another's reports what was set for
  it, else the caller's own; a `CLONE_PARENT` child's parent is the
  caller's for `getppid`, `/proc` and its adoption, but on the host it is
  the caller's child, which the caller's parent cannot `wait` for (nor
  gets `SIGCHLD` of) while the caller lives.
- **cgroups:** the memory, CPU, I/O and other limits are kept and read
  back but not enforced (only `pids.max` and device programs are); a
  threaded cgroup cannot be made (`cgroup.threads` refuses writes); the
  tree is the user's, not the machine's.
- **Security:** seccomp filters apply to every thread (as with
  `SECCOMP_FILTER_FLAG_TSYNC`), and there is no user-notification listener
  (`SECCOMP_RET_USER_NOTIF` and `SECCOMP_RET_TRACE` fail with `ENOSYS`);
  `sched_setaffinity` is checked and remembered but threads still run on
  any CPU.
- **Signals:** a real-time signal (`SIGRTMIN` and up, which the host lacks)
  can only be sent within the process; standard signals are not queued
  (one pending per signal, as Linux does for them); a blocked signal whose
  action the host applies (one ignored, or a default that ignores or
  continues) loses its sender, which matters only if a handler is
  installed before it is unblocked; a signal from outside fwe (or sent
  to a process group) that arrives while one of fwe's handlers runs comes
  with no sender; a blocked signal pending across an
  `execve` arrives with fwe's own pid as its sender;
  `rt_sigqueueinfo` is not implemented; a signal that
  arrives between a blocking call's start and its host wait can be noticed
  only when the call ends, except for `rt_sigsuspend`, `rt_sigtimedwait`
  and the masked waits, which close that window; a futex wait notices a
  signal within 20 ms; a call rerun after an interruption the guest does
  not see starts its timeout over; a fault signal sent by a process fwe
  did not start is treated as a fault; a process killed by a real-time signal exits with
  status 128 + the signal, since the host cannot report one it lacks; a
  process-wide signal left at its default action and sent while every
  thread blocked it stays with the thread macOS parked it on, rather than
  acting when another thread unblocks it (one the guest catches is
  handed on), and in the VM a caught one is not handed on either.
- **Event descriptors:** `EPOLLEXCLUSIVE` wakes every waiter; `timerfd`
  resolution and clock distinctions; `pselect6` does not write back the
  time left.
- **Process control:** a parent-death signal (`PR_SET_PDEATHSIG`) is
  recorded but never sent, and a new thread does not inherit its creator's
  name.
- **System V IPC:** every change rewrites the namespace's record, so
  filling a namespace with thousands of objects (to its limit, as a stress
  test does) is slow; `SHM_INFO` reports no resident pages; a segment
  stays attached in a hypervisor-backend fork child without being counted
  for it; huge pages (`SHM_HUGETLB`) are refused, as without hugetlbfs.
- **Not implemented:** `rseq`, `membarrier` (optional for libc), loop devices,
  `splice`, `tee` and `vmsplice`, `personality`, `inotify`,
  `name_to_handle_at` and the AIO calls; any system call not listed in
  `crates/kernel/src/syscalls.rs` returns `ENOSYS` and is noted under
  `--strace`.
