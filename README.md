# fun-with-emulators

Run unmodified Linux arm64 binaries natively on macOS (Apple Silicon) — no
virtual machine, no Linux kernel. Like Wine, but for Linux. Written in Rust.

See [PLAN.md](PLAN.md) for the plan and [ROADMAP.md](ROADMAP.md) for
milestones.

## Status

Milestone M0 is done: static Linux arm64 executables (static PIE, and
ET_EXEC linked above 4 GiB) run natively on macOS 15 and 26.

M1 is in progress. Landed: a root filesystem with the file and directory
system calls (`openat`, the `stat` family, `getdents64`, `renameat2`,
symlinks with rootfs containment, and more), and the **dynamic loader**
(`PT_INTERP` interpreters are loaded from the rootfs and handed control with
the right auxiliary vector). Next: threads and signal delivery. Running real
glibc/musl programs end to end also needs the x18 fix, which — together with
executables linked below 4 GiB — is deferred to the hypervisor backend; run
`fwe --host-info` to see how the current host treats registers that matter
to Linux code.

## Usage

```sh
cargo build --release
target/release/fwe ./hello                 # run a Linux arm64 static executable
target/release/fwe --strace ./hello        # trace its system calls
target/release/fwe --root ./rootfs ./hello # run with ./rootfs as /
```

## How it works

`fwe` loads the ELF image into its own address space, rewrites each `svc #0`
(Linux system call) into a trapping `brk`, sets up a Linux initial stack and
jumps to the entry point. Guest code runs
directly on the CPU. Each system call traps into `fwe`'s signal handler, which
runs the Linux system call in the kernel layer and resumes the guest.
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
