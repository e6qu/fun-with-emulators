# fun-with-emulators

Run unmodified Linux arm64 binaries on macOS (Apple Silicon). `fwe`
implements the Linux kernel's userspace ABI rather than running a Linux
kernel: like Wine, but for Linux. Written in Rust.

## How it works

A Mac with Apple Silicon has the same processor architecture as an arm64
Linux machine, so a Linux program's instructions can run on it directly.
What differs is the kernel. `fwe` plays the Linux kernel: each guest
process is one `fwe` process, which catches every system call the program
makes, carries it out with macOS's own calls, and turns what macOS reports
(signals, key strokes, children ending, errors) into what Linux would have
said. Files, sockets and terminals are the host's; what macOS lacks or
shapes differently (namespaces, cgroups, epoll, inotify, System V IPC,
keyrings and more) `fwe` provides itself, shared between its processes.

Programs run in one of two backends, chosen per program:

- **Native.** The program runs inside the `fwe` process, on the CPU, at
  native speed. Before its code may execute, `fwe` rewrites the few
  instructions macOS cannot let a Linux program run unchanged: each
  system call (`svc #0`) becomes a trap into `fwe`, and accesses to the
  thread pointer and to the `x18` register, which macOS reserves, go
  through short stubs. Every position-independent program runs this way,
  which is most of what a Linux distribution ships.
- **Hypervisor.** A program linked at a fixed address below 4 GiB cannot
  be placed in a macOS process, which reserves that range. `fwe` runs it
  in a small Hypervisor.framework VM instead: the program's code runs
  unmodified at EL0 with an address space of its own, and each system
  call leaves the VM and is served by the same code as in the native
  backend.

[docs/linux-on-macos.md](docs/linux-on-macos.md) explains all of this in
detail.

## Status

Unmodified Debian `aarch64` programs run natively, against a genuine glibc
(musl works too): coreutils, bash, git, SQLite, lighttpd, Node.js, rustc
with Cargo, and apt.

Executables linked below 4 GiB run in a Hypervisor.framework VM:
- that covers Debian's Python, GCC, clang and Go;
- `fwe` must be signed with the hypervisor entitlement for this
  ([docs/hypervisor.md](docs/hypervisor.md));
- it is verified on a software stand-in for the framework, not yet on real
  hardware.

Container engines run standard images: crun, podman and containerd run
`alpine`.

LTP's system-call tests pass at 1150 of 1551 (97% of those that apply).

## Documentation

| Document | Contents |
|---|---|
| [PLAN.md](PLAN.md) | Goal, approach, scope and the 1.0 finish line |
| [ROADMAP.md](ROADMAP.md) | What is done and what is left to 1.0 |
| [docs/linux-on-macos.md](docs/linux-on-macos.md) | Which binaries run in which backend, which instructions are rewritten, how the VM is used; how each Linux concept (system calls, memory, processes, signals, namespaces, cgroups…) maps onto macOS, and how host events (signals, key strokes, children ending, errors…) reach the guest |
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

On Apple Silicon macOS this includes the end-to-end tests:
- They build the programs in `guests/`, which needs `clang` from the Xcode
  command line tools, and run them under `fwe`.
- The hypervisor backend's tests run on a software stand-in, which needs
  `brew install unicorn`. They never use a real VM unless asked to.

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
