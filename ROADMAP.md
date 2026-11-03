# Roadmap

Milestones are ordered by what each one unlocks. A milestone is done when its
**Done when** criteria pass as end-to-end tests in CI; checklist items are
the work that gets there. Work for a later milestone may land early when it
is independent (most of M2's system-call surface did), but a milestone is
only ticked off against its criteria.

[PLAN.md](PLAN.md) states the goal and scope; [docs/architecture.md](docs/architecture.md)
describes how the pieces work and lists the current limitations in detail.

**Status (November 2026):** M0 and M1 are done. M2 is in progress: its
system-call surface is implemented, and what remains is the hypervisor
backend for low-address executables and running the listed software end to
end.

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
- [x] fwe's own descriptors out of the guest's reach: a reserved range
  above a virtual `RLIMIT_NOFILE`, so closing everything from 3 up or
  `close_range` leaves them alone; `/proc/self/fd`

Remaining:

- [ ] **Hypervisor backend** for executables linked below 4 GiB (non-PIE
  `ET_EXEC`: Debian's `python3.11` at `0x400000`, static Go at `0x10000`).
  The feasibility spike (`fwe --hv-spike`, see
  [docs/hypervisor-spike.md](docs/hypervisor-spike.md)) runs a low-address
  guest in a Hypervisor.framework VM and services its traps. The backend
  itself: run the guest at EL0 under a minimal EL1 vector so `svc #0` traps
  as is (no rewrite needed), keep guest addresses equal to host addresses by
  mapping the VM's memory at the same addresses in the host so the kernel
  layer is shared unchanged, implement `Platform` for it, and have the loader
  pick it automatically for images the native backend cannot map. CI
  coverage runs on the self-hosted Apple Silicon runner (the `hypervisor`
  job); hosted runners cannot run a VM.
- [ ] Python from the Debian rootfs (carried over from M1)
- [ ] The rest of the process model: `execve` from a process with other
  live threads, `execveat`, `clone3`; `vfork` sharing memory with its
  parent rather than copying it
- [ ] `EFAULT` for bad guest pointers the kernel reads itself, instead of a
  crash
- [ ] The remaining `x18` forms (`sp`-writeback and `sp`-register-offset
  loads and stores, `sp`-operand arithmetic, `casp`, pointer-authenticated
  loads) and code discovery for binaries without section headers
- [ ] Each of the target programs vendored or fetched as a test with checked
  output: git, a C compiler, Node, Go, the Rust toolchain, `apt`, a database,
  a web server

**Done when:** git, compilers, Node, Go, Rust, `apt`, databases and web
servers run unmodified.

## M3 — Containers

- [ ] Namespaces (mount, pid, user, uts, ipc, network, cgroup)
- [ ] cgroups v2
- [ ] Overlay mounts
- [ ] seccomp and capabilities

**Done when:** podman and containerd run standard container images.

## M4 — Full compatibility

- [ ] Long-tail system calls
- [ ] ptrace and debuggers (gdb, strace)
- [ ] io_uring
- [ ] Advanced networking (netlink, firewalling, raw sockets, TUN)
- [ ] High pass rates on gVisor's syscall tests, LTP and kselftests

**Done when:** real-world workloads run unmodified and conformance suites
pass at high rates.

## M5 — Product

- [ ] Performance tuning
- [ ] Packaging and installation
- [ ] macOS integration
- [ ] Documentation

**Done when:** a shippable release.
