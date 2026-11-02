# Roadmap

Milestones are sequential; each is done when its exit criteria are met.
See [PLAN.md](PLAN.md) for the overall plan.

## M0 — Foundation

- [x] Rust project skeleton and build
- [x] CI running on Apple Silicon macOS
- [x] ELF loader for static binaries
- [x] System call redirection to our implementation
- [x] Test harness

**Done when:** a static Linux arm64 binary runs and prints "hello".

## M1 — Core userland

- [x] Processes and threads: `clone` threads + futex, `fork`, `execve`, `wait4`
  (single-threaded `fork`; address-space teardown on `execve` is partial)
- [x] Memory management (`mmap`, `mprotect`, `brk`, and friends)
- [x] Files and directories, with a Linux root filesystem
- [x] Signals
- [x] Pipes
- [~] Dynamic linking with glibc and musl: musl works end to end — the loader
  maps the program and the interpreter named in `PT_INTERP`, hands off at the
  interpreter's entry with `AT_BASE`/`AT_ENTRY`/`AT_PHDR` set, and the real
  `ld-musl-aarch64.so.1` self-relocates, resolves the program's relocations
  against the shared libc, sets up the thread pointer and starts it. Libraries
  the linker maps at run time are translated through the `mmap`/`mprotect`
  `PROT_EXEC` path, the same as the initial image. End-to-end tests run genuine
  dynamic binaries (a minimal `_start` and a full crt/`__libc_start_main`/stdio
  program) against a vendored musl build. glibc (needed for a Debian rootfs) is
  next.
- [~] Binary translation of `x18` (and the other registers macOS treats
  specially): macOS clears `x18` on every exception return — including
  involuntary preemption, where the custom x18 ABI was observed being dropped —
  so guest uses of `x18` are rewritten to a per-thread slot before the code
  runs, exactly as `svc #0` and `TPIDR_EL0` already are. The data-processing
  classes and all the load/store forms (unsigned/unscaled/register-offset/
  pre-post-index/pair, general-purpose and SIMD base) are handled, with stack
  spills adjusted for the stub's push and literal pools protected from the
  scan, as are the PC-relative forms (`adr`/`adrp`/`ldr`-literal) and the
  compare/test/indirect branches through `x18` — enough to run a compiled
  Rust/musl binary and a real `ld-musl` unmodified. Only executable code is
  rewritten: code extents come from the section headers (the `SHF_EXECINSTR`
  sections), so data that shares an executable segment with the code — a
  dynamic linker's symbol, string and hash tables, for instance — is left
  intact. Only `sp`-writeback spills and code discovery for fully stripped
  binaries without section headers remain. This
  keeps execution in-process at native speed; **no hypervisor or VM is used**
  (that is a non-goal of this project — see PLAN.md).
- [ ] Executables linked below 4 GiB (static non-PIE C/Rust, Go): macOS
  reserves the low 4 GiB, so these are handled by load-time relocation in the
  same translation pass, not by a VM.

**Done when:** bash, coreutils and Python run from a Debian rootfs.

## M2 — Everyday software

- [x] Networking (TCP/UDP over IPv4/IPv6, `socketpair`, pathed and abstract
  `AF_UNIX`, `SCM_RIGHTS` descriptor passing; netlink and raw sockets are M4)
- [x] Terminals and job control (`termios`, window size, tty process group,
  sessions, pty allocation via `/dev/ptmx` + `/dev/pts`)
- [x] Event APIs (`epoll`, `eventfd`, `timerfd`, `signalfd`)
- [x] `/proc` and `/sys` (startup files served and the directories are
  listable with `getdents64`)
- [x] Users, permissions and ownership (virtual credentials)

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
- [ ] High pass rates on gVisor syscall tests, LTP and kselftests

**Done when:** real-world workloads run unmodified and conformance suites
pass at high rates.

## M5 — Product

- [ ] Performance tuning
- [ ] Packaging and installation
- [ ] macOS integration
- [ ] Documentation

**Done when:** a shippable release.
