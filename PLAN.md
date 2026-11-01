# Plan

## Goal

Run unmodified Linux arm64 binaries natively on macOS (Apple Silicon), with no
virtual machine and no Linux kernel — in the spirit of Wine, but for Linux.

The project is written in Rust.

## Approach

A Rust implementation of the Linux userspace ABI that runs on macOS:

- Linux binaries are loaded into macOS processes and execute directly on the
  CPU at native speed.
- Linux system calls are redirected to our own implementation instead of the
  macOS kernel.
- Our implementation provides Linux behaviour — processes, threads, memory,
  files, signals, networking, namespaces and cgroups — built on top of macOS.

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

1. **Loader** — starts Linux binaries as macOS processes.
2. **Linux kernel layer** — the Rust core implementing Linux behaviour on top
   of macOS.
3. **Execution backends** — native in-process execution by default, with a
   lightweight hypervisor-based mode for anything that needs it. Both share
   the same core.
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

- **Conformance:** gVisor's syscall test suite, the Linux Test Project (LTP)
  and kselftests, tracked as pass rates.
- **Real workloads:** a growing list of applications and distribution test
  suites that must pass.
- **Performance:** benchmarks against native macOS tools and a Linux VM.

## Workstreams

Once the core userland runs, work proceeds in parallel across:

- Core kernel (processes, memory, signals)
- Filesystems and VFS
- Networking
- Containers (namespaces, cgroups, security)
- Execution backends and performance
- Testing and CI infrastructure

See [ROADMAP.md](ROADMAP.md) for milestones.
