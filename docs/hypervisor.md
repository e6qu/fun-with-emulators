# The hypervisor backend

Some Linux binaries are **non-PIE `ET_EXEC` executables linked at a fixed low
address**: Debian's `/usr/bin/python3.11` at `0x400000`, static Go at
`0x10000`, anything a toolchain links without `-pie`. The native backend
cannot run them. macOS gives every arm64 process a mandatory 4 GiB
`__PAGEZERO`, enforced as the minimum address of the process's map, so the
address the binary needs is unmappable, and a non-PIE image has no relocation
information to move it elsewhere. This is an OS limit, not an implementation
gap: Apple's loader refuses a smaller `__PAGEZERO` on Apple Silicon, and
other emulators hit the same wall.

A hardware VM sidesteps it: the guest gets an address space of its own with no
`__PAGEZERO`. On macOS the userspace API for one is **Hypervisor.framework**,
which needs the `com.apple.security.hypervisor` entitlement but no root — an
ad-hoc signature carrying the entitlement is enough. fwe picks this backend
automatically for an executable it cannot map in-process.

## How it works

The code is in `crates/native/src/hv/`.

- **The VM** (`vm.rs`). A 40-bit guest-physical address space. Stage 1 maps
  it all as identity 32 MiB blocks of normal memory accessible to EL0, so it
  never faults; what the guest may touch, and how, is decided at stage 2 by
  which host memory is mapped where, with the guest's protections. The top
  block holds fwe's page tables and an exception vector, mapped for EL1 only.
- **Execution.** The guest runs at EL0. Every exception it takes enters the
  vector, which executes `hvc #0`, so the vCPU stops and the backend reads
  `ESR_EL1` to see what happened: an `svc` (a Linux system call, unchanged —
  nothing is rewritten, and `x18` and `TPIDR_EL0` are simply the guest's), a
  `brk`, an undefined instruction, an alignment fault. An access to memory the
  guest has not mapped stops the vCPU with a stage-2 abort, which becomes
  `SIGSEGV`.
- **Memory.** Guest memory is host memory mapped into the VM. Everything the
  guest maps itself — stack, break, `mmap`s, the dynamic linker and the
  libraries it loads — is placed at the same address in the VM as in the
  host, so guest pointers are host pointers, as in the native backend. Only
  the executable's image, at the low address the host cannot map, lives
  elsewhere in the host: that one range is registered with the kernel layer,
  which translates guest pointers into it wherever it uses them — in its
  checked copies of guest memory (`crates/kernel/src/uaccess.rs`), in the
  pointer arguments it hands to host system calls (a table of which arguments
  are pointers), and in `iovec`s. The kernel's memory system calls tell the
  backend about every mapping change (`Platform::map_guest` and friends), so
  the VM's view follows the host's.
- **The kernel.** System calls go to the same kernel layer as the native
  backend's, through a `Platform` of the backend's own.
- **Signals.** As in the native backend, guest dispositions are mirrored onto
  the host and the vCPU thread runs under the guest's mask. The handler
  records the signal and stops the vCPU (`hv_vcpus_exit`), and the run loop
  delivers it — so a signal reaches a guest busy in a loop without system
  calls too. The framework's own threads are created with every guest signal
  blocked, so the host never hands one to them.

## Status

Programs linked below 4 GiB run in the VM, static and dynamically linked: the
assembly test programs, Rust/musl programs, and a non-PIE glibc program
whose own `ld.so` maps `libc.so.6`, relocates and applies RELRO — the shape of
Debian's `python3.11`. Not supported in the VM yet: threads (`clone` of a
thread), `fork`/`vfork` and `execve`, which fail with `ENOSYS`; these are on
the [roadmap](../ROADMAP.md). A memory call (`mmap` with a fixed address,
`munmap`, `mprotect`, `madvise`, `mremap`) on a range that runs across the
edge of the executable's image fails with `EINVAL`, since that range has no
single host address.

## Running it (Apple Silicon, no root)

```sh
cargo build --release -p fwe
codesign --sign - --entitlements hypervisor.entitlements --force target/release/fwe
target/release/fwe ./program-linked-low
```

Without the entitlement, or on a host without hypervisor support, fwe
explains that the program needs the hypervisor backend and exits with status
126. `fwe --hv-spike` runs a tiny guest in a VM — a quick check that the
hypervisor works on a machine: it prints `hv: hello from the guest` and
reports the status 42 the guest exits with. `sysctl kern.hv_support` must be
`1`.

## Tests and CI

The end-to-end tests whose names start with `hv_` sign a copy of `fwe` with the
entitlement and run low-linked programs in the VM. Where the host has no
hypervisor they report that they were skipped and pass.

GitHub's hosted macOS runners are themselves virtual machines without nested
virtualization, so Hypervisor.framework is unavailable there. This is
measured, not assumed — the `macos` jobs run an informational step that
reports it:

- `macos-15`: `kern.hv_support` OID does not exist.
- `macos-26`: `kern.hv_support: 0`.
- Both: `hv_vm_create` returns `0xfae9400f` (`HV_UNSUPPORTED`), even though the
  binary is correctly signed with the entitlement.

So in hosted CI the backend is compiled and lint-checked (it cannot rot) but
its tests skip. They run for real on a **self-hosted Apple Silicon runner**,
in the `hypervisor` job.

### Registering the self-hosted runner (one time)

On an Apple Silicon Mac (bare metal, not a VM), confirm `sysctl
kern.hv_support` is `1`, then register it as a repository runner:
`Settings → Actions → Runners → New self-hosted runner`, choose macOS/ARM64,
and follow the shown `./config.sh` / `./run.sh` steps. GitHub labels it
`self-hosted`, `macOS`, `ARM64` automatically. Install a Rust toolchain for
the runner user (`rustup`) and the Xcode command line tools (`clang`).

Then set the repository variable that enables the job:
`Settings → Secrets and variables → Actions → Variables → New variable`,
name `FWE_HV_SELF_HOSTED`, value `true`. The job stays skipped until this is
set, so it never blocks PRs when no runner exists. Once set, it runs the
`hv_` end-to-end tests and `fwe --hv-spike` on every push.

Until then, the tests run wherever a developer runs `cargo test` on an Apple
Silicon Mac.
