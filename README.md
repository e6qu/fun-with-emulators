# fun-with-emulators

Run unmodified Linux arm64 binaries on macOS (Apple Silicon). `fwe`
implements the Linux kernel's userspace ABI rather than running a Linux
kernel: like Wine, but for Linux. Written in Rust.

## How it works

An Apple Silicon Mac has the same processor architecture as an arm64 Linux
machine, so a Linux program's instructions run on it directly; what differs
is the kernel. `fwe` plays the Linux kernel: each guest process is one `fwe`
process, which carries out the program's system calls with macOS's own and
provides itself what macOS lacks (namespaces, cgroups, epoll, inotify,
System V IPC, keyrings and more). A program runs in one of two backends:

- **Native**, inside the `fwe` process, for every position-independent
  program, which is most of what a distribution ships. `fwe` first rewrites
  the few instructions macOS cannot let a Linux program run unchanged.
- **Hypervisor**, for a program linked at a fixed address below 4 GiB,
  which macOS reserves: it runs unmodified in a small Hypervisor.framework
  VM, its system calls served by the same code. `fwe` must be signed with
  the hypervisor entitlement for this
  ([docs/hypervisor.md](docs/hypervisor.md)).

[docs/linux-on-macos.md](docs/linux-on-macos.md) explains this in detail.

## Status

Unmodified Debian programs run natively against glibc or musl (coreutils,
bash, git, SQLite, lighttpd, Node.js, rustc with Cargo, apt) and in the VM
(Python, GCC, clang, Go; verified on a software stand-in for the framework,
not yet on real hardware). crun, podman and containerd run the `alpine`
image, and Docker Engine loads, runs and builds images (BuildKit) and
brings up Docker Compose projects, natively, with no VM. All 1213 of LTP's system-call tests that apply pass.
[ROADMAP.md](ROADMAP.md) has the details and what is left to 1.0.

## Documentation

| Document | Contents |
|---|---|
| [PLAN.md](PLAN.md) | Goal, approach, scope and the 1.0 finish line |
| [ROADMAP.md](ROADMAP.md) | What is done and what is left to 1.0 |
| [docs/linux-on-macos.md](docs/linux-on-macos.md) | Which binaries run where, which instructions are rewritten, how the VM is used, and how each Linux concept maps onto macOS |
| [docs/architecture.md](docs/architecture.md) | How each part of fwe works, and its current limitations |
| [docs/hypervisor.md](docs/hypervisor.md) | The hypervisor backend, its safety rules, and running it |

## Usage

```sh
cargo build --release
target/release/fwe ./hello                 # run a Linux arm64 executable
target/release/fwe --root ./rootfs ./hello # with ./rootfs as /
target/release/fwe --strace ./hello        # trace its system calls
target/release/fwe --strace --strace-file=trace.log ./hello  # every process, to a file
```

A dynamically linked program needs its dynamic linker and libraries under
the root, at the paths the program names. For Debian binaries, that means a
Debian rootfs.

## Layout

| Path | Contents |
|---|---|
| `crates/abi` | Linux arm64 ABI: system-call numbers, errno values, flags, structures |
| `crates/elf` | ELF parsing, load planning, unwind tables, build IDs |
| `crates/kernel` | Linux system calls on top of the host |
| `crates/native` | The native backend (loader, code rewriting, traps) and the hypervisor backend with its stand-in |
| `crates/fwe` | The `fwe` command and the end-to-end tests |
| `guests/asm`, `guests/c`, `guests/rust` | Linux test programs the tests build |
| `guests/musl`, `guests/glibc`, `guests/debian`, `guests/alpine` | Vendored or fetched binaries the tests run, with their provenance |
| `tools/gen-abi.py` | Generates the ABI tables from Linux's UAPI headers |
| `tools/ltp` | Builds LTP and runs its system-call tests against the baseline |
| `docs/` | Linux on macOS, the architecture, and the hypervisor backend |

## Testing

```sh
cargo test
```

On Apple Silicon macOS this includes the end-to-end tests, which build the
programs in `guests/` (needing `clang` from the Xcode command line tools)
and run them under `fwe`. The hypervisor backend's tests run on a software
stand-in (`brew install unicorn`), never on a real VM unless asked to.
Elsewhere only the unit tests run. [AGENTS.md](AGENTS.md) lists every check
CI runs.

LTP's system-call tests run under `fwe` against `tools/ltp/baseline.txt`;
CI fails if a test in the baseline stops passing:

```sh
tools/ltp/build.sh target/ltp      # needs zig 0.17.0: LTP in an Alpine root
cargo build
tools/ltp/run.py --fwe target/debug/fwe --root target/ltp/root
```

## License

MIT, see [LICENSE](LICENSE). The binaries under `guests/` carry their own
licenses, noted in each directory's README.
