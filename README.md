# fun-with-emulators

Run unmodified Linux arm64 binaries on macOS (Apple Silicon), in-process and
at native speed — we implement the Linux kernel's userspace ABI rather than
run a Linux kernel. Like Wine, but for Linux. Written in Rust.

## Status

Real, unmodified Debian `aarch64` programs run end to end: coreutils, `ls`
with its shared-library graph, and `bash`, dynamically linked against a
genuine glibc (musl works too). Processes, threads, memory, signals, files on
a Linux rootfs, networking, terminals, event descriptors and a synthetic
`/proc` are in place.

What does not run yet is a non-PIE executable linked into the low 4 GiB that
macOS reserves (Debian's `python3.11`, static Go). Those need the
minimalistic hypervisor backend, which exists as a feasibility spike
(`fwe --hv-spike`). See [ROADMAP.md](ROADMAP.md) for milestones and status,
[PLAN.md](PLAN.md) for the goal and scope, and
[docs/architecture.md](docs/architecture.md) for how it works and what is
still missing.

## Usage

```sh
cargo build --release
target/release/fwe ./hello                 # run a Linux arm64 executable
target/release/fwe --strace ./hello        # trace its system calls
target/release/fwe --root ./rootfs ./hello # run with ./rootfs as /
```

A dynamically linked program needs its dynamic linker and libraries under
the root, at the paths the program names (for Debian binaries, a Debian
rootfs).

## How it works

`fwe` maps the ELF image into its own address space at the guest's
addresses, rewrites each `svc #0` into a trapping `brk` — along with uses
of `x18` and `TPIDR_EL0`, which macOS treats specially — builds a Linux
initial stack, and jumps to the entry point. Guest code then runs directly
on the CPU. Each system call traps into a signal handler, which runs the
Linux system call in the kernel layer and resumes the guest. A dynamically
linked program's interpreter and libraries are loaded and translated the
same way. See [docs/architecture.md](docs/architecture.md).

## Layout

| Path | Contents |
|---|---|
| `crates/abi` | Linux arm64 userspace ABI: syscall numbers, errno, flags, structs |
| `crates/elf` | ELF parsing and load planning |
| `crates/kernel` | Linux system call implementations on top of the host |
| `crates/native` | Native execution backend: loader, instruction rewriting, traps; the hypervisor spike |
| `crates/fwe` | The `fwe` command and end-to-end tests |
| `guests/asm`, `guests/c`, `guests/rust` | Linux test programs built by the tests |
| `guests/musl`, `guests/glibc`, `guests/debian` | Vendored, unmodified runtimes and Debian binaries the tests run |
| `tools/gen-abi.py` | Generates ABI tables from Linux UAPI headers |
| `docs/` | Architecture and the hypervisor spike |

## Testing

```sh
cargo test
```

On macOS on Apple Silicon this includes the end-to-end tests, which build the
programs in `guests/` (needs `clang`, from the Xcode command line tools) and
run them under `fwe`. Elsewhere only unit tests run. See
[AGENTS.md](AGENTS.md) for the full set of checks CI runs.

## License

MIT — see [LICENSE](LICENSE). The vendored runtimes and Debian binaries under
`guests/` carry their own licenses, noted in each directory's README.
