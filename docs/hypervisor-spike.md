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

A real backend will run the guest at EL0 under a minimal EL1 vector so that
Linux's `SVC #0` traps the same way, and will dispatch into the existing
kernel (`fwe-kernel`) instead of the two hard-coded calls here. The point of
the spike is only to show that a low-address guest runs and traps cleanly.

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

## Why it is not in CI

GitHub's hosted macOS runners are themselves virtual machines, and nested
virtualization is unavailable on their hardware, so `hv_vm_create` cannot
succeed there. The spike therefore is not exercised by the end-to-end test
suite; it is validated by hand on real Apple Silicon. The code is still
compiled and lint-checked for `aarch64-apple-darwin` in CI so it cannot rot.
