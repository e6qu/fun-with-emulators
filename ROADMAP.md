# Roadmap

A milestone is done when its **Done when** criteria pass as end-to-end tests
in CI; its checklist is the work that gets there. [PLAN.md](PLAN.md) states
the goal and the 1.0 finish line; [docs/architecture.md](docs/architecture.md)
describes how each part works and lists the current limitations in detail.

## Status

| Milestone | State |
|---|---|
| M0 Foundation | Done |
| M1 Core userland | Done |
| M2 Everyday software | Done except one item: the VM backend's run on real hardware |
| M3 Containers | Done |
| M4 Compatibility | In progress: LTP's system-call tests at 877 of 1550 (75% of the 1176 that apply) |
| M5 Release | Not started |

What runs, unmodified, with its output checked in CI:
- **Natively, in-process:** Debian's coreutils, bash, git, SQLite, lighttpd,
  Node.js (V8's JIT), rustc with Cargo, and apt.
- **In the VM:** Python, GCC, clang and Go, for executables linked below
  4 GiB. These pass on the software stand-in for Hypervisor.framework only.
- **Containers:** crun, podman and containerd run the `alpine` image.

## Done

**M0 — Foundation.** Rust workspace; CI on macOS 15 and 26 plus a Linux
unit-test job; ELF loading; system calls trapped by rewriting `svc #0`; an
end-to-end harness of assembly and Rust guests. *A static Linux binary
prints "hello".*

**M1 — Core userland.** Processes and threads (`clone`, futexes, `fork`,
`execve`, `wait4`), memory, files on a Linux root filesystem confined to it,
signals with Linux's frame layout, pipes, rewriting of what macOS cannot run
unchanged (`svc`, `TPIDR_EL0`, `x18`), and real glibc and musl dynamic
linking. *bash and coreutils run from a Debian rootfs.*

**M2 — Everyday software** (all but the real-hardware run):
- networking (TCP, UDP, IPv4 and IPv6, `AF_UNIX` with descriptor passing);
- terminals, ptys and job control;
- `epoll`, `eventfd`, `timerfd` and `signalfd`;
- the `/proc` and `/sys` programs read;
- virtual credentials;
- signals between processes and per thread;
- the process model shells and spawners need (`vfork`, `posix_spawn`,
  `execveat`, `clone3`);
- `EFAULT` for bad pointers;
- fwe's own descriptors out of the guest's reach;
- the hypervisor backend for executables linked below 4 GiB, with threads,
  `fork`, `vfork` and `execve` in both directions, pointer authentication
  and BTI.

*The target programs (git, compilers, Node, Go, Rust, apt, a database, a web
server) run unmodified.*

**M3 — Containers.** Mount, pid, user, UTS, IPC, network and cgroup
namespaces; cgroups v2 with device programs; overlay mounts; seccomp and
capabilities. *crun, podman and containerd run standard images.*

**M4, done:**
- the LTP system-call suite in CI against a baseline, and the bugs it found;
- `preadv`/`pwritev` and their `2` forms;
- priorities and CPU-time clocks;
- the `fcntl` owner, signal, lease and pipe-size commands;
- futex requeue and bitsets;
- System V IPC per IPC namespace;
- `/proc/<pid>/maps` and `smaps` with `PROCMAP_QUERY`;
- the `mlock` family with locked-memory accounting;
- `mincore` and `fadvise64`;
- loop devices (`/dev/loop-control`, `/dev/loopN`, the `LOOP_*` and
  `BLK*` requests, `/sys/block`), on which LTP's device tests run with
  tmpfs;
- `splice`, `tee` and `vmsplice`; `personality`; the scheduling policies
  (`sched_setattr` and the rest); the clock refused as Linux refuses it
  without `CAP_SYS_TIME`;
- POSIX message queues per IPC namespace, with notifications across
  processes (a signal with its value, or the C library's thread through a
  netlink socket).
- the new mount API (`fsopen`, `fsconfig`, `fsmount`, `fspick`,
  `open_tree`, `move_mount`, `mount_setattr`, `statmount`, `listmount`),
  with peer groups kept and mount ids in `statx`;
- namespace descriptors: `/proc/<pid>/ns/*` opened, `setns` and the
  `NS_GET_*` requests;
- inotify, its events raised by fwe from every process's file calls;
- keys and keyrings (`add_key`, `request_key`, `keyctl`), shared by every
  process, with Diffie-Hellman, asymmetric and encrypted keys;
- mounts as Linux has them: propagation (between peers, to slaves, across
  namespaces), the `nodev`, `noexec`, `nosymfollow` and access-time flags
  acted on, busy mounts refused, `MNT_EXPIRE`, and `pivot_root` of a
  chroot.

## Left to 1.0

### M2 — finish

- [ ] The VM backend verified on real hardware: the `hv_` tests and
  `fwe --hv-spike` pass in the self-hosted `hypervisor` job. The machine
  must be one whose crash costs nothing, such as a rented bare-metal Mac
  ([docs/hypervisor.md](docs/hypervisor.md)), never the development Mac.
  This needs a runner registered and `FWE_HV_SELF_HOSTED` set: an owner's
  action, not code.

**Done when:** the target programs run unmodified, the VM's on real
hardware.

### M4 — Compatibility

In order of what each item unblocks. The LTP counts are from the latest
run.

- [ ] **ptrace** for the debuggers: enough for `strace` and `gdb` to trace
  and debug a guest program (attach, system-call stops, registers, memory,
  breakpoints, signals).
- [ ] **Ownership for non-root:** `chown` recorded and shown by `stat`,
  and permission checks for a guest that is not root (the `chown`,
  `fchown`, `lchown`, `creat` and `mkdir` failures).
- [ ] **Every other failure LTP points at**, among them:
  - `EPOLLEXCLUSIVE`;
  - `eventfd` and real-time signals across processes;
  - core dumps and the core-dump bit;
  - `rename`, `statx`, `mremap`, `madvise` details.
- [ ] **The `x18` and code-discovery gaps:** the rare `x18` forms and
  binaries stripped of section headers, when a program needs them.

**Done when:** every one of LTP's system-call tests passes, in CI against
the baseline, but those for what is not planned for 1.0 and those that fail
or skip on Linux too with the same build, each listed with the reason in
`tools/ltp/exceptions.txt`; `strace` and `gdb` work on a guest
program; the target programs and container engines keep passing.

### M5 — Release

- [ ] **Performance:** benchmarks in CI of startup, system-call cost,
  `fork`/`exec`, and a C project's build. Compared with native macOS and a
  Linux VM (Lima or OrbStack). The hot spots fixed: the single kernel lock,
  trap cost, and record rewrites.
- [ ] **Packaging:** a signed and notarized `fwe` carrying the hypervisor
  entitlement, a Homebrew formula, and a command that fetches and unpacks a
  Debian or Alpine root filesystem.
- [ ] **User documentation:** installing, running programs and containers,
  and what is not supported.

**Done when:** a user installs a release and runs a Debian or Alpine
userland and podman with it, following the documentation.

## Not planned for 1.0

Each of these fails cleanly (`ENOSYS` or `EINVAL`), so programs that probe
for it fall back:
- io_uring;
- networking beyond loopback in namespaces (veth, firewalling, raw
  sockets, TUN);
- kselftests and gVisor's system-call suite as gates;
- x86_64 Linux binaries;
- `kcmp`: macOS cannot tell whether two descriptors share an open file
  description, and programs that use it (CRIU, systemd) fall back;
- `fanotify`: its permission events would hold every process's file
  calls on another's answer; it is refused (`ENOSYS`), and programs fall
  back to inotify;
- graphical programs.
