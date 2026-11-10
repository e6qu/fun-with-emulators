# Plan

## Goal

Run unmodified Linux arm64 binaries on macOS (Apple Silicon) without a Linux
kernel, in the spirit of Wine. fwe is written in Rust.

## Approach

fwe implements the Linux userspace ABI on top of macOS. A Linux program runs
directly on the CPU inside an `fwe` process; its system calls go to fwe's
kernel layer, which provides Linux's processes, threads, memory, files,
signals, networking, namespaces and cgroups on macOS, with fwe's own
`/proc`, `/sys` and `/dev`.

Two backends share that kernel layer:
- **Native**, for every position-independent binary, which is what
  distributions ship: fwe rewrites the few instructions macOS cannot let a
  Linux program run unchanged.
- **Hypervisor**, for non-PIE executables linked into the low 4 GiB that
  macOS reserves in every arm64 process: a minimal Hypervisor.framework VM
  gives the guest an address space of its own, for CPU and memory only.

A virtual machine running a Linux kernel is a non-goal.
[docs/architecture.md](docs/architecture.md) describes how each part works.

## Scope

In scope:
- the Linux userspace ABI on arm64: system calls, ELF loading, signals,
  `/proc`, `/sys`, `/dev`, ioctls, namespaces and cgroups;
- distributions' userland (Debian, Alpine);
- container engines and standard images;
- Wine, for ARM64 Windows console programs.

Out of scope:
- kernel modules and private kernel interfaces;
- hardware drivers;
- x86 binaries;
- graphical programs.

## The finish line: 1.0

1.0 is reached when all of these hold, as [ROADMAP.md](ROADMAP.md) defines
them in M2, M4 and M5:
- the target programs (git, compilers, Node, Go, Rust, apt, a database, a
  web server) run unmodified, those in the VM on real hardware;
- container engines (Docker, podman, containerd) build and run images,
  rootless podman included;
- every LTP system-call test passes, but those for what is not planned for
  1.0 and those that fail or skip on Linux too with the same build, each
  listed with its reason;
- `strace` and `gdb` work on a guest program;
- Wine runs ARM64 Windows console programs;
- a signed release installs and runs them, with user documentation.

The roadmap lists what 1.0 leaves out under "Not planned for 1.0".

## Principles

- **Compatibility first:** success is unmodified Linux binaries working.
- **Native performance:** in-process, with no virtual machine where one is
  not needed.
- **No blockers:** an implementation problem is something to solve.
- **Measured progress:** real workloads and LTP define what "working"
  means.

## Measuring progress

- **Workloads:** unmodified distribution binaries run as end-to-end tests
  with their output checked.
- **Conformance:** LTP's system-call tests run in CI against a baseline of
  those that pass (`tools/ltp`); a test that stops passing fails CI.
- **Performance:** benchmarks against native macOS and a Linux VM (M5).

[AGENTS.md](AGENTS.md) describes how work is delivered.
