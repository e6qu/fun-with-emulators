# Roadmap

Milestones are ordered by what each one unlocks. A milestone is done when its
**Done when** criteria pass as end-to-end tests in CI; checklist items are
the work that gets there. Work for a later milestone may land early when it
is independent (most of M2's system-call surface did), but a milestone is
only ticked off against its criteria.

[PLAN.md](PLAN.md) states the goal and scope; [docs/architecture.md](docs/architecture.md)
describes how the pieces work and lists the current limitations in detail.

**Status (November 2026):** M0 and M1 are done. M2 is in progress: its
system-call surface is implemented, and the hypervisor backend runs
low-address executables with threads, `fork` and `execve`; git, SQLite,
lighttpd, Node, Cargo and apt run natively, and Debian's Python, GCC, Go
and clang in the VM (verified on the software stand-in; a run on real
hardware is still to come), so every target program has a test. What
remains is that run on real hardware, and the `x18` and code-discovery
gaps, which no target program needs yet. M3 is done: crun runs the
standard `alpine` image in its own namespaces, cgroup, capabilities and
seccomp profile, and podman and containerd (with runc) load that image and
run containers of it on overlay mounts. M4 has begun: the Linux Test
Project's system-call tests run under fwe in CI against a baseline of the
ones that pass (651 of 1534), and the bugs they found first are
fixed.

## M0 — Foundation (done)

- [x] Rust workspace, CI on Apple Silicon macOS (15 and 26) plus a Linux
  lint and unit-test job
- [x] ELF loader for static executables
- [x] System calls redirected to our implementation (`svc #0` rewritten to a
  trap)
- [x] End-to-end test harness: assembly and Rust guests built and run under
  `fwe`

**Done when:** a static Linux arm64 binary runs and prints "hello". ✔

## M1 — Core userland (done)

- [x] Processes and threads: `clone` threads with futexes, `fork`, `execve`,
  `wait4`
- [x] Memory: `mmap`, `munmap`, `mprotect`, `mremap`, `madvise`, `brk`
- [x] Files and directories on a Linux root filesystem (`--root`), with
  path resolution confined to it
- [x] Signals: `sigaction`, masks, alternate stacks, delivery through an
  arm64 `rt_sigframe`, `rt_sigreturn`
- [x] Pipes
- [x] Binary translation of what macOS cannot let a Linux process run
  unchanged: `svc #0`, `TPIDR_EL0`, and every use of `x18` in the
  data-processing, load/store, PC-relative and branch classes, confined to
  the executable sections so data is never patched
- [x] Dynamic linking with real, unmodified glibc and musl: the loader hands
  off to the dynamic linker named in `PT_INTERP`; libraries it maps are
  translated through the `PROT_EXEC` `mmap`/`mprotect` path
- [x] Unmodified Debian 12 `aarch64` programs run with their output checked:
  coreutils (`true`, `false`, `echo`, `seq`, `env`, `cat`, `sort`), `ls`
  (through `libselinux` and `libpcre2`) and `bash` (startup, builtins,
  arithmetic, loops)

**Done when:** bash and coreutils run from a Debian rootfs. ✔

Python was originally part of this criterion. Debian's `python3.11` is a
non-PIE executable linked at `0x400000`, inside the 4 GiB that macOS
reserves in every arm64 process, so the in-process backend cannot map it at
all; that is an OS limit, not a gap in the userland. It moves to M2, where
the hypervisor backend that serves such executables is built (static Go
binaries, also on the M2 list, need it for the same reason).

## M2 — Everyday software (in progress)

System-call surface, implemented and covered by end-to-end tests:

- [x] Networking: TCP and UDP over IPv4 and IPv6, `socketpair`, pathed and
  abstract `AF_UNIX`, `SCM_RIGHTS` descriptor passing
- [x] Terminals and job control: `termios`, window size, tty process group,
  sessions, pty allocation through `/dev/ptmx` and `/dev/pts`
- [x] Event APIs: `epoll`, `eventfd`, `timerfd`, `signalfd`
- [x] `/proc` and `/sys`: the files programs read at startup, and the
  directories listable with `getdents64`
- [x] Users, permissions and ownership as virtual credentials
- [x] Signals between processes: `kill` to any pid or process group,
  `tgkill` to one thread, guest dispositions mirrored onto the host so
  signals from children, the terminal, timers and other processes reach
  guest handlers (with `SA_RESTART` and `EINTR` as on Linux),
  `rt_sigsuspend`, `rt_sigtimedwait`, `rt_sigpending`, the masks of `ppoll`
  and `epoll_pwait`, `setitimer`
- [x] Per-thread signal masks, alternate stacks and pending signals; FP and
  SIMD registers saved across a handler
- [x] Process model for shells and spawners: `fork` from a multithreaded
  process, the `vfork` form of `clone` (`posix_spawn`,
  `std::process::Command`), `execve` that discards the old address space
  (so a program can exec itself), `waitid`, and `rusage` from `wait4` and
  `getrusage`
- [x] `EFAULT` for bad guest pointers: the kernel layer reads and writes
  guest memory only through checked copies
- [x] fwe's own descriptors out of the guest's reach: a reserved range
  above a virtual `RLIMIT_NOFILE`, so closing everything from 3 up or
  `close_range` leaves them alone; `/proc/self/fd`

Remaining:

- [x] **Hypervisor backend** for executables linked below 4 GiB (non-PIE
  `ET_EXEC`, which macOS's `__PAGEZERO` keeps out of the process): the guest
  runs at EL0 in a Hypervisor.framework VM, its `svc` trapping unchanged;
  fwe picks the backend automatically. Static and dynamically linked
  programs, signals included (see [docs/hypervisor.md](docs/hypervisor.md)).
  Its tests run on a software stand-in for Hypervisor.framework everywhere
  (hosted CI included), and on the real framework on the self-hosted runner
  (the `hypervisor` job)
- [x] In the VM: threads, and `execve` between the VM and the native backend
  either way (fwe re-executes itself on the new program)
- [x] In the VM: `fork` and `vfork`: the child is a fresh fwe process given
  a copy of the parent's memory (a `vfork` child fetching it as it goes and
  sending back what it changed) and its kernel state
- [x] The VM's memory as the runtimes that run Linux programs this way
  without trouble keep it: stage 2 mapped once, the guest's own 4 KiB page
  tables for every mapping change, no private page in two VMs; pointer
  authentication and BTI as Linux sets them up, where the VM offers them
  (verified on the stand-in; a real-hardware run is still to come)
- [x] Python from the Debian rootfs (carried over from M1): Debian's
  Python 3.11, fetched, runs a standard-library workload in the VM (C
  modules, threads, asyncio, ctypes, `fork`, `subprocess`, and a process
  pool whose semaphores are in `/dev/shm`), verified on the stand-in
- [x] `execveat` and `clone3`; virtual credentials, `RLIMIT_NOFILE` and the
  umask carried across an `execve` that re-executes fwe
- [x] The rest of the process model: `vfork` sharing memory with its parent
  rather than copying it; a native-backend `fork` that stops the parent's
  other threads while memory is copied
- [ ] Code discovery for binaries without section headers, and the `x18`
  forms no tested binary uses yet (`sp`-writeback loads and stores, writes
  to `sp`, `casp`, pointer-authenticated loads), when a target program needs
  them. Done for Node: extended and flag-setting `sp` arithmetic, register
  offsets and out-of-range offsets from `sp`, the vector-element moves, and
  data among code told apart by the unwind table
- [x] Each of the target programs vendored or fetched as a test with checked
  output. Done: git (Debian's git runs a workflow of commits, branches,
  merge, stash, rebase, `grep` through PCRE2's JIT, `gc` and a `file://`
  clone), a database (Debian's SQLite: a write-ahead-logged database with
  concurrent writers, full-text search and JSON) and a web server (Debian's
  lighttpd: static files, directory listings, concurrent clients and CGI
  scripts backed by SQLite) and Node (Debian's Node.js 18, fetched: V8's
  JIT, ICU, OpenSSL's digests, zlib, files, a child process, HTTP and a
  worker thread) and the Rust toolchain (Debian's rustc and Cargo, fetched:
  a two-crate project built in release mode and its unit tests run, linked
  by GNU ld) and `apt` (Debian's apt and dpkg, fetched: a package
  installed from a local repository, run, and removed) and a C compiler
  (Debian's GCC 12, fetched, in the VM: a threaded program, a static
  library, PIE, non-PIE and static executables; and Debian's clang 14, C
  and C++) and Go (Debian's Go 1.19, fetched, in the VM: a module built,
  run and its tests run); the VM's are verified on the stand-in

**Done when:** git, compilers, Node, Go, Rust, `apt`, databases and web
servers run unmodified.

## M3 — Containers (done)

- [x] Namespaces (mount, pid, user, uts, ipc, network, cgroup)
- [x] cgroups v2
- [x] Overlay mounts: layers merged, copy-up, whiteouts and opaque
  directories, as Linux's `overlay` filesystem
- [x] seccomp and capabilities
- [x] An OCI runtime runs a standard image: crun runs the `alpine` image
- [x] podman runs standard images: it loads the `alpine` image and runs
  containers of it, on its default `overlay` storage driver
- [x] containerd runs standard images: `ctr` imports the `alpine` image and
  runs containers of it through containerd's runc shim and runc, with the
  overlay snapshotter

**Done when:** podman and containerd run standard container images. ✔

## M4 — Full compatibility

- [ ] Long-tail system calls. Done so far: `preadv`/`pwritev` and their
  `2` forms, `getpriority`/`setpriority`, CPU-time clock ids, the `mlock`
  family, `fcntl`'s owner, signal, lease and pipe-size commands, futex
  requeue and bitsets, System V IPC (shared memory, semaphores and message
  queues per IPC namespace, between processes), `/proc/self/maps` and
  `smaps` with `PROCMAP_QUERY`, `mincore`, `fadvise64`. Next: loop devices,
  `splice`, `inotify`
- [ ] ptrace and debuggers (gdb, strace)
- [ ] io_uring
- [ ] Advanced networking (netlink beyond a namespace's loopback,
  firewalling, raw sockets, TUN)
- [ ] High pass rates on gVisor's syscall tests, LTP and kselftests. LTP's
  system-call tests (`tools/ltp`, the pinned 20260930 release built for
  arm64 musl, run in an Alpine root) run in CI against a baseline:
  651 of 1534 pass, 57% of the 1139 that apply

**Done when:** real-world workloads run unmodified and conformance suites
pass at high rates.

## M5 — Product

- [ ] Performance tuning
- [ ] Packaging and installation
- [ ] macOS integration
- [ ] Documentation

**Done when:** a shippable release.
