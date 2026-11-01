# Architecture

## Components

```
fwe (CLI)
 └── native backend (crates/native)
      ├── loader      ELF image → host mappings at guest addresses
      ├── rewrite     svc #0 → brk #0x4c58 before code becomes executable
      ├── stack       Linux initial stack: argc, argv, envp, auxv
      └── trap        SIGTRAP handler → kernel → resume guest
 └── kernel layer (crates/kernel)
      Linux system call semantics on top of macOS, behind a Platform trait
 └── ABI (crates/abi), ELF (crates/elf)
```

The kernel layer does not depend on how guest code runs. Backends implement
`fwe_kernel::Platform`. A hypervisor backend can be added beside the native
one and share the kernel.

## Memory model

Guest addresses are host addresses. The native backend maps guest memory at
the guest's own virtual addresses inside the `fwe` process, so guest pointers
are used directly. Where layouts match, they are passed straight to macOS
system calls, which validate them. Future backends keep this property.

The guest sees the host page size (16K on Apple Silicon) through `AT_PAGESZ`,
which the arm64 Linux ABI permits.

macOS reserves the low 4 GiB of every arm64 process: the kernel refuses to
start an executable with a smaller `__PAGEZERO`. Position-independent
executables (the norm for distribution packages) are loaded anywhere, and
ET_EXEC images linked above 4 GiB at their addresses. ET_EXEC images linked
below 4 GiB (static non-PIE C and Rust builds at 0x200000 or 0x400000, Go at
0x10000) need guest-controlled address translation: the planned hypervisor
backend, which shares the kernel layer.

## System call path

1. The loader, and `mmap`/`mprotect` with `PROT_EXEC`, map code writable
   first and call `Platform::prepare_exec`, which rewrites every aligned
   `svc #0` into `brk #0x4c58` and flushes the instruction cache. Then the
   final protections are applied.
2. The guest executes the `brk`. macOS delivers `SIGTRAP` on a dedicated
   signal stack.
3. The handler checks that the trapping instruction is ours, reads the
   system call number from `x8` and arguments from `x0`–`x5`, and calls
   `Kernel::syscall`.
4. The result goes into `x0`, `pc` advances past the `brk`, and returning
   from the handler resumes the guest. All other registers are preserved.

## Registers macOS treats differently

- **TPIDR_EL0** holds the Linux thread pointer, but macOS does not preserve
  it for user code (it stores per-CPU data there). Every `mrs`/`msr` of
  `TPIDR_EL0` is rewritten into a branch to a stub that reads or writes a
  slot in the host thread's TSD instead, located through `TPIDRRO_EL0`
  (per-thread, read-only to user code). Stubs live in space reserved right
  after the image, within branch range.
- **x18** is a scratch register for Linux code, but macOS reserves it and
  clears it on every exception return (system calls, page faults,
  preemption). On macOS 26.4 and later, `fwe` switches the guest thread into
  the custom x18 ABI (`<os/arch/arm64.h>`) when entering guest code, and the
  trap handlers leave it while running host code. On older macOS, guest x18
  uses still need to be rewritten (roadmap); until then programs that keep
  values in x18 across a page fault can fail. `fwe --host-info` reports
  whether x18 is preserved on the current host. On macOS 26.6 virtual
  machines (GitHub's runners) the host was observed to leave the mode on its
  own when the thread is preempted; `fwe` detects this, never switches the
  mode off when it is already off (which aborts), and treats x18 as not
  preserved.

## Filesystem

The guest sees a filesystem rooted at a host directory (the rootfs), set with
`fwe --root DIR`; with no `--root` the root is the host `/`, reproducing
pass-through behaviour. Guest paths are resolved under the root in
`crates/kernel/src/fs.rs`, one component at a time, following symlinks
ourselves and clamping `..` so a path can never escape the root — the
containment `openat2(RESOLVE_IN_ROOT)` gives on Linux, done by hand so it
works on macOS too. Absolute symlink targets re-root at the rootfs rather
than the host `/`.

Guest file descriptors are host file descriptors: an opened file's host fd is
returned to the guest unchanged, so `read`, `write`, `lseek`, `fstat` and the
rest act on it directly. `getdents64` passes through on a Linux host (the
kernel already produces the arm64 layout) and is translated from
`getdirentries` on macOS. Creation modes have the umask applied by the kernel.

## Dynamic linking

A dynamically linked executable names an interpreter (the dynamic linker,
e.g. `/lib/ld-linux-aarch64.so.1` or `/lib/ld-musl-aarch64.so.1`) in a
`PT_INTERP` segment. The loader maps the executable, then resolves the
interpreter path **through the rootfs**, maps it too (it is a PIE, loaded at
an arbitrary base), and starts the guest at the interpreter's entry point
rather than the executable's. The auxiliary vector carries `AT_BASE` (the
interpreter's load base), `AT_ENTRY` (the executable's entry), and
`AT_PHDR`/`AT_PHENT`/`AT_PHNUM` for the executable, as Linux provides them.
The interpreter maps the executable's shared libraries itself through our
`openat` and file-backed `mmap`.

## Signals

The kernel stores each signal's `sigaction`, the blocked mask and the
alternate stack. When a guest raises a signal against itself (`kill`,
`tgkill`, `raise`) it is marked pending and delivered on return to the guest;
synchronous faults (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`) are offered to a
handler at the point of the fault. Delivery builds an arm64 `rt_sigframe` on
the guest stack (or the alternate stack under `SA_ONSTACK`), points the
registers at the handler with `x0`/`x1`/`x2` set per `SA_SIGINFO`, and sets
the return address to the handler's `sa_restorer` or, lacking one, a
`rt_sigreturn` trampoline the backend maps at startup. `rt_sigreturn`
restores the saved registers, mask and alternate stack. The backend exposes
the guest register file to the kernel for the duration of a trap as a
`Regs` value (copied from and back to the host signal context), which the
coming thread support reuses. Floating-point and vector state is not yet
saved across a handler.

## Translation

Linux numbers (errno, flags, clock ids, signals, rlimits, ioctls) are
translated to macOS values in `crates/kernel/src/host.rs`, using the `libc`
crate for host values. `crates/abi` holds the Linux side. Syscall numbers and
errno values are generated from the Linux UAPI headers by `tools/gen-abi.py`.

## Known limitations in M0

These are tracked on the roadmap:

- Single-threaded guests only (no `clone` thread creation yet).
- Floating-point/vector registers are not saved across a signal handler.
- Executables linked below 4 GiB are rejected (see above).
- x18 is not preserved before macOS 26.4 (see above).
- A data word equal to `svc #0` inside an executable segment would be
  rewritten too.
- Guest pointers the kernel reads itself are not yet fault-checked; a bad
  pointer crashes `fwe` instead of returning `EFAULT`.
