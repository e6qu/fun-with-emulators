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
3. **Execution** — guest code runs in-process at native speed by default.
   Instructions macOS cannot let a Linux process run unchanged (`svc`,
   `TPIDR_EL0`, and `x18` uses) are rewritten before execution. This native
   path is the default and carries the great majority of binaries (everything
   position-independent). It cannot, however, run a non-PIE `ET_EXEC` linked
   into the low 4 GiB that macOS reserves with a mandatory `__PAGEZERO` (e.g.
   Debian's `python3.11`): the OS forbids the mapping and the image cannot be
   relocated. For exactly those binaries a **minimalistic Hypervisor.framework
   backend** is under evaluation — a VM only for the CPU and memory, with
   `svc` trapped straight into the same kernel layer, so the guest's own
   address space provides the low addresses. A full virtual machine with its
   own Linux kernel remains a non-goal; the hypervisor fallback is as thin as
   possible and used only where the native path physically cannot reach. See
   `docs/hypervisor-spike.md`.
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

## Development process

The project is built with agentic coding, so work is packed into large,
outcome-sized pull requests rather than small granular ones:

- **One PR per testable outcome** — usually a milestone, or a large slice of
  one. Many logical commits, one PR.
- **Tests decide when it is done.** A PR is ready when its "Done when"
  criteria pass in CI; conformance tests, real binaries and benchmarks prove
  it, not line-by-line review.
- **Self-reviewed before opening.** Builds, tests and a review pass happen
  before the PR goes up.
- **Descriptions for skimming:** what it delivers, how it was verified, what
  is left for later.
- **No preparatory PRs.** Refactors, scaffolding and dependency changes go
  into the PR that needs them.
- **Split only** for parallel workstreams that touch separate areas, or for a
  shared foundation other in-flight work depends on.

Details for contributors and agents are in [AGENTS.md](AGENTS.md).

## Workstreams

Once the core userland runs, work proceeds in parallel across:

- Core kernel (processes, memory, signals)
- Filesystems and VFS
- Networking
- Containers (namespaces, cgroups, security)
- Execution backends and performance
- Testing and CI infrastructure

See [ROADMAP.md](ROADMAP.md) for milestones.
