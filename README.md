# fun-with-emulators

Run unmodified Linux arm64 binaries on macOS (Apple Silicon), in-process and
at native speed — we implement the Linux kernel's userspace ABI rather than
run a Linux kernel. Like Wine, but for Linux. Written in Rust.

See [PLAN.md](PLAN.md) for the plan and [ROADMAP.md](ROADMAP.md) for
milestones.

## Status

Milestone M0 is done: static Linux arm64 executables run natively on macOS 15
and 26.

M1 (core userland) is largely in place and runs **real, unmodified
distribution binaries** end to end:

- **Dynamic linking with glibc and musl** — the loader hands off to the
  interpreter named in `PT_INTERP` (a genuine `ld-linux-aarch64.so.1` /
  `ld-musl-aarch64.so.1`), which self-relocates, resolves the program's
  relocations against the shared libc, and starts it.
- **Debian `aarch64` programs**: coreutils (`true`, `echo`, `seq`, `env`,
  `cat`, `sort`), `ls` (with its `libselinux` → `libpcre2` dependency graph),
  and **bash** (startup, builtins, arithmetic, loops).
- **`x18` binary translation** — macOS clobbers `x18` on every exception
  return, so guest uses of it (and `svc`, `TPIDR_EL0`) are rewritten to a
  per-thread slot before execution, confined to the real code via the section
  headers. This is what lets a real `ld.so` and libc run unmodified.
- Plus processes and threads (`clone`+futex, `fork`, `execve`, `wait4`),
  memory, signals, pipes, and a root filesystem with synthesized `/proc`.

What is left in M1 is **non-PIE executables linked into the low 4 GiB** that
macOS reserves (for example Debian's `python3.11` at `0x400000`). These cannot
run in-process — the reservation is mandatory on Apple Silicon and a non-PIE
image cannot be relocated — so they are handled by a **minimalistic
Hypervisor.framework backend**, where the guest's own address space supplies
the low addresses and `svc` traps into the same kernel layer. A feasibility
spike exists (`fwe --hv-spike`); see
[docs/hypervisor-spike.md](docs/hypervisor-spike.md).

## Usage

```sh
cargo build --release
target/release/fwe ./hello                 # run a Linux arm64 static executable
target/release/fwe --strace ./hello        # trace its system calls
target/release/fwe --root ./rootfs ./hello # run with ./rootfs as /
```

## How it works

`fwe` loads the ELF image into its own address space, rewrites each `svc #0`
(Linux system call) into a trapping `brk` — along with guest uses of `x18` and
`TPIDR_EL0`, which macOS treats specially — sets up a Linux initial stack, and
jumps to the entry point. Guest code then runs directly on the CPU. Each
system call traps into `fwe`'s signal handler, which runs the Linux system
call in the kernel layer and resumes the guest. A dynamically linked program's
interpreter and libraries are loaded and translated the same way. The one case
this in-process model cannot reach — a non-PIE executable in the low 4 GiB
macOS reserves — is handled by the separate hypervisor backend.
See [docs/architecture.md](docs/architecture.md).

## Layout

| Path | Contents |
|---|---|
| `crates/abi` | Linux arm64 userspace ABI: syscall numbers, errno, flags, structs |
| `crates/elf` | ELF parsing and load planning |
| `crates/kernel` | Linux system call implementations on top of the host |
| `crates/native` | Native execution backend: loader, syscall rewriting, traps |
| `crates/fwe` | The `fwe` command and end-to-end tests |
| `guests/` | Linux test programs (assembly and Rust) |
| `tools/gen-abi.py` | Generates ABI tables from Linux UAPI headers |

## Testing

```sh
cargo test
```

On macOS on Apple Silicon this includes end-to-end tests that build the
programs in `guests/` (needs `clang`, from the Xcode command line tools) and
run them under `fwe`. Elsewhere only unit tests run.

## License

MIT — see [LICENSE](LICENSE).
