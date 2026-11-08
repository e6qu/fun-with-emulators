# Plan

## Goal

Run unmodified Linux arm64 binaries on macOS (Apple Silicon), in-process and
without a Linux kernel, in the spirit of Wine. It is written in Rust.

## Approach

fwe implements the Linux userspace ABI on top of macOS:

- A Linux program is loaded into an `fwe` process and runs directly on the
  CPU.
- Its system calls go to fwe's kernel layer instead of the macOS kernel.
- That layer provides Linux behaviour on macOS: processes, threads, memory,
  files, signals, networking, namespaces and cgroups.

The in-process path runs every position-independent binary, which is what
distributions ship. The one class it cannot run is a non-PIE executable
linked into the low 4 GiB that macOS reserves in every arm64 process. For
those, a minimal Hypervisor.framework backend gives the guest an address
space of its own: a VM for the CPU and memory only, with system calls going
to the same kernel layer. A virtual machine running a Linux kernel is a
non-goal.

## Architecture

Four layers, described in [docs/architecture.md](docs/architecture.md):

1. **Loader:** maps a Linux ELF image and its dynamic linker, and builds
   the Linux initial stack.
2. **Execution backends:**
   - the native backend rewrites the few instructions macOS cannot let a
     Linux process run unchanged (`svc`, `TPIDR_EL0`, `x18`) and traps
     system calls;
   - the hypervisor backend runs the guest in a VM and traps `svc` directly
     ([docs/hypervisor.md](docs/hypervisor.md)).
3. **Kernel layer:** Linux system-call semantics on macOS, shared by both
   backends behind a small `Platform` trait.
4. **Linux environment:** a root filesystem with fwe's own `/proc`, `/sys`
   and `/dev`.

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

1.0 is reached when all of these hold, as M2, M4 and M5 of
[ROADMAP.md](ROADMAP.md) define them:
- the target programs (git, compilers, Node, Go, Rust, apt, a database, a
  web server) and container engines (Docker, podman, containerd) run
  unmodified, building and running images, rootless podman included,
  the VM's verified on real hardware;
- every one of LTP's system-call tests passes, but those for what is not
  planned for 1.0 and those that fail or skip on Linux too with the same
  build (its C library's differences), each listed with the reason;
- `strace` and `gdb` work on a guest program;
- Wine runs ARM64 Windows console programs;
- a signed release installs and runs them, with user documentation.

What 1.0 leaves out is listed in the roadmap under "Not planned for 1.0".

## Principles

- **Compatibility first:** the measure of success is unmodified Linux
  binaries working.
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

How work is delivered (large outcome-sized pull requests, with tests as the
definition of done) is in [AGENTS.md](AGENTS.md).
