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
- [ ] Dynamic linking with glibc and musl
- [ ] Hypervisor backend for executables linked below 4 GiB (static non-PIE,
  Go), sharing the kernel layer
- [ ] Rewrite guest uses of x18: macOS clears x18 on every exception return,
  and the custom x18 ABI (macOS 26.4+) was observed being dropped on
  preemption, so rewriting is the general fix

**Done when:** bash, coreutils and Python run from a Debian rootfs.

## M2 — Everyday software

- [ ] Networking (sockets, DNS)
- [ ] Terminals and job control
- [ ] Event APIs (`epoll`, `eventfd`, `timerfd`, `signalfd`)
- [ ] `/proc` and `/sys`
- [ ] Users, permissions and ownership

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
