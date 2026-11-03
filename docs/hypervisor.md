# Hypervisor backend — feasibility spike

Some Linux binaries are **non-PIE `ET_EXEC` linked at a fixed low address**
(Debian's `/usr/bin/python3.11` at `0x400000`, static Go at `0x10000`). The
native backend cannot run these: macOS gives every arm64 process a mandatory
4 GiB `__PAGEZERO`, so the low address the binary needs is unmappable, and a
non-PIE image has no relocation information to move it elsewhere. This is an
OS limitation, not an implementation gap — Apple's loader refuses a smaller
`__PAGEZERO` on Apple Silicon, and other emulators (FEX) hit the same wall.

A hardware VM sidesteps it: the guest gets its own address space with no
`__PAGEZERO`, so it can be mapped at its own low address and run there. On
macOS the only userspace API for a hardware VM is **Hypervisor.framework**
(HVF). It needs the `com.apple.security.hypervisor` entitlement but **no
root** — an ad-hoc code signature with the entitlement is enough.

This spike proves the mechanism end to end, before committing to a full
backend.

## What the spike does

`fwe --hv-spike` (see `crates/native/src/hv.rs`):

1. Creates a VM and a vCPU with Hypervisor.framework.
2. Maps 2 MiB of RAM at guest-physical **`0x400000`** — deliberately in the
   low region the native backend is denied.
3. Loads a tiny guest there and runs it at EL1 with the MMU off (so virtual
   address == physical address).
4. The guest issues "system calls" — `write(1, msg, len)` then
   `exit_group(42)` — using `HVC #0` to trap to the VMM.
5. The VMM services each trap with a host system call (copying the guest's
   buffer out of VM RAM for `write`) and resumes the guest, then reports what
   the guest printed and the status it exited with.

The point of the spike is only to show that a low-address guest runs and
traps cleanly.

## From spike to backend

The backend itself is an M2 item on the [roadmap](../ROADMAP.md). What it
adds over the spike:

- The guest runs at **EL0** under a minimal EL1 exception vector, so Linux's
  own `svc #0` traps to the VMM as is; no instruction rewriting is needed on
  this path (and `x18`/`TPIDR_EL0` are the guest's, since no macOS code runs
  on the vCPU).
- Guest memory is backed by host mappings the kernel layer reads and
  writes. Addresses above 4 GiB can be the same in the guest and the host,
  as the native backend guarantees, but the low range the image needs is
  exactly what the host process cannot map (the mandatory `__PAGEZERO`), so
  guest pointers into it are translated to where the host maps it: in the
  kernel's guest-memory accessors (`crates/kernel/src/uaccess.rs`, the one
  place it touches guest memory) and for the pointers it passes to host
  system calls.
- A `Platform` implementation and a trap loop that feed `Kernel::enter_syscall`
  with the vCPU's register file, the way the native backend's `SIGTRAP`
  handler does.
- The loader picks this backend automatically for an `ET_EXEC` image linked
  below 4 GiB, which it rejects today.

Its exit criterion is Debian's `python3.11` running from the rootfs.

## Running it (Apple Silicon, no root)

```sh
cargo build --release -p fwe
codesign --sign - --entitlements hv-spike.entitlements --force \
    target/release/fwe
target/release/fwe --hv-spike
```

Expected output:

```
hv: hello from the guest
fwe: hv spike guest exited with status 42
```

(The process exits with status 42.) Check `sysctl kern.hv_support` returns `1`
first; if it is `0` the machine has no hypervisor support. Without the
entitlement, `hv_vm_create` fails and `fwe` reports
`hv spike failed: hv_vm_create failed: ...` rather than crashing.

## CI: hosted runners can't, a self-hosted runner can

GitHub's hosted macOS runners are themselves virtual machines without nested
virtualization, so HVF is unavailable there. This is measured, not assumed —
the `macos` jobs run an informational step that reports it:

- `macos-15`: `kern.hv_support` OID does not exist.
- `macos-26`: `kern.hv_support: 0`.
- Both: `hv_vm_create` returns `0xfae9400f` (`HV_UNSUPPORTED`), even though the
  binary is correctly codesigned with the entitlement.

So the code is always compiled and lint-checked for `aarch64-apple-darwin` in
CI (it cannot rot), and the informational step keeps reporting availability in
case a hosted runner ever gains it — but the spike is actually *run* on a
**self-hosted Apple Silicon runner**, where `kern.hv_support` is `1`.

### Registering the self-hosted runner (one time)

On an Apple Silicon Mac (bare metal, not a VM), confirm `sysctl
kern.hv_support` is `1`, then register it as a repository runner:
`Settings → Actions → Runners → New self-hosted runner`, choose macOS/ARM64,
and follow the shown `./config.sh` / `./run.sh` steps. GitHub labels it
`self-hosted`, `macOS`, `ARM64` automatically. Install a Rust toolchain for
the runner user (`rustup`), since the job builds with `cargo`.

Then set the repository variable that enables the job:
`Settings → Secrets and variables → Actions → Variables → New variable`,
name `FWE_HV_SELF_HOSTED`, value `true`. The `hypervisor` job stays skipped
until this is set, so it never blocks PRs when no runner exists. Once set, the
job codesigns `fwe` with the entitlement and runs `fwe --hv-spike` on every
push, asserting the guest prints its message and exits with status 42 — real
CI coverage of the hypervisor path.

Until then, validate by hand with the steps above.
