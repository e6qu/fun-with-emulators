# Plan

## Goal

Run unmodified Linux arm64 binaries natively on macOS (Apple Silicon),
in-process and without a Linux kernel — in the spirit of Wine, but for
Linux. The project is written in Rust.

## Approach

A Rust implementation of the Linux userspace ABI that runs on macOS:

- Linux binaries are loaded into macOS processes and execute directly on the
  CPU at native speed.
- Linux system calls are redirected to our own implementation instead of the
  macOS kernel.
- Our implementation provides Linux behaviour — processes, threads, memory,
  files, signals, networking, namespaces and cgroups — built on top of macOS.

The in-process path carries every position-independent binary, which is the
norm for distribution packages. The one class it physically cannot run is a
non-PIE executable linked into the low 4 GiB that macOS reserves in every
arm64 process (Debian's `python3.11`, static Go binaries): the OS refuses the
mapping and the image cannot be relocated. For exactly those, a
**minimalistic Hypervisor.framework backend** supplies a guest address space
without that reservation — a VM for the CPU and memory only, with system
calls trapped straight into the same kernel layer. A full virtual machine
with its own Linux kernel is a non-goal; the hypervisor path is as thin as
possible and used only where the in-process path cannot reach.

## Scope

In scope:

- The Linux userspace ABI on arm64: system calls, ELF loading, signals,
  `/proc`, `/sys`, `/dev`, ioctls, netlink, namespaces and cgroups.
- Running real Linux distributions' userland (Debian, Alpine, and others).
- Running container tooling and standard container images.

Out of scope:

- Linux kernel modules and other private kernel ABI (kprobes, kexec, kernel
  memory access).
- Hardware drivers.
- x86 Linux binaries.

## Architecture

Four layers, described in [docs/architecture.md](docs/architecture.md):

1. **Loader** — maps a Linux ELF image, and its dynamic linker, into the
   process and builds the Linux initial stack.
2. **Execution backend** — runs guest code. The native backend rewrites the
   few instructions macOS cannot let a Linux process execute unchanged
   (`svc`, `TPIDR_EL0`, `x18`) and traps system calls; the hypervisor
   backend runs the guest in a VM and traps `svc` directly.
3. **Kernel layer** — Linux system call semantics on top of macOS, shared by
   both backends behind a small `Platform` trait.
4. **Linux environment** — a root filesystem with synthesized `/proc`, `/sys`
   and `/dev`.

## Principles

- **Compatibility first.** The measure of success is unmodified Linux binaries
  working.
- **Native performance.** Stay lightweight; no heavy virtualization.
- **No blockers.** Every implementation challenge is something to overcome.
- **Measured progress.** Conformance test suites and real workloads define
  what "working" means.

## Measuring progress

- **Real workloads:** unmodified distribution binaries run as end-to-end
  tests with their output checked. This is what milestones are ticked off
  against today; the list grows with each milestone.
- **Conformance:** gVisor's syscall test suite, the Linux Test Project (LTP)
  and kselftests, tracked as pass rates (from M4).
- **Performance:** benchmarks against native macOS tools and a Linux VM (M5).

## Workstreams

With the core userland running, work proceeds in parallel across:

- Core kernel (processes, memory, signals)
- Filesystems and VFS
- Networking
- Containers (namespaces, cgroups, security)
- Execution backends and performance
- Testing and CI infrastructure

Milestones and status are in [ROADMAP.md](ROADMAP.md). How work is
delivered — large outcome-sized pull requests, tests as the definition of
done — is in [AGENTS.md](AGENTS.md).
