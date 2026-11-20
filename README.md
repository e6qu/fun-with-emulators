# fun-with-emulators

`fwe` aims to be a practical, performant and fully compatible Linux
environment on macOS (Apple Silicon): unmodified Linux arm64 programs,
containers (Docker, Podman), graphical Linux programs, Windows programs
(console and graphical) through Linux's Wine, and sandboxes such as
gVisor. It implements the Linux kernel's user-space ABI rather than
running a Linux kernel: Wine's approach, for Linux. Written in Rust.

## How it works

An Apple Silicon Mac has the same processor architecture as an arm64
Linux machine, so a Linux program's instructions run on it directly; what
differs is the kernel. `fwe` plays the Linux kernel: each guest process is
one `fwe` process, which carries out the program's system calls with
macOS's own and provides what macOS lacks (namespaces, cgroups, epoll,
inotify, System V IPC, keyrings and more). A program runs in one of two
backends:

- **Native**, inside the `fwe` process, for every position-independent
  program, which is most of what a distribution ships, and for a static
  one linked low whose link kept its relocations, moved above 4 GiB.
  `fwe` rewrites the few instructions macOS does not let a Linux program
  run unchanged, and runs code a program makes at run time (a JIT's) by
  translation into a code cache of its own ([docs/jit.md](docs/jit.md)).
- **Hypervisor**, for any other program linked at a fixed address below
  4 GiB, which macOS reserves: it runs unmodified in a small
  Hypervisor.framework VM, its system calls served by the same code. This
  needs `fwe` signed with the hypervisor entitlement
  ([docs/hypervisor.md](docs/hypervisor.md)).

[docs/linux-on-macos.md](docs/linux-on-macos.md) explains this in detail.

## Status

What runs unmodified, its output checked in CI:

- **Natively:** Debian's coreutils, bash, git, SQLite, lighttpd, rustc
  with Cargo, apt and Node.js; Alpine's Node.js, OpenJDK, LuaJIT, Racket
  and Guile, whose JIT compilers' code runs translated.
- **In the VM:** Debian's Python, GCC, clang and Go, and Alpine's SBCL,
  verified on a software stand-in for Hypervisor.framework, not yet on
  real hardware.
- **Containers, natively:** crun, Podman and containerd run the `alpine`
  image; Podman builds, pushes, pulls and runs images, rootless too;
  Docker Engine runs and builds images (BuildKit) and brings up Docker
  Compose projects.
- **Windows:** Wine runs ARM64 Windows console programs in the VM
  (`fwe --vm`, on the stand-in).
- **Conformance:** every LTP system-call test that applies passes.

Native speed, graphical programs and gVisor are the work left to 1.0;
[ROADMAP.md](ROADMAP.md) has the details.

## Documentation

| Document | Contents |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Installing fwe, a Linux userland, running programs and containers, and what does not work |
| [PLAN.md](PLAN.md) | Goal, approach, scope, principles and the 1.0 finish line |
| [ROADMAP.md](ROADMAP.md) | What is done and what is left to 1.0 |
| [docs/linux-on-macos.md](docs/linux-on-macos.md) | Which binaries run where, which instructions are rewritten, how the VM is used, and how each Linux concept maps onto macOS |
| [docs/linking.md](docs/linking.md) | How programs are built and loaded, Linux and macOS on arm64: ELF and Mach-O, relocations, static and dynamic linking, PIE and static PIE and their code, virtual memory, ASLR, thread-local storage, program start |
| [docs/arm64.md](docs/arm64.md) | arm64 assembly as fwe's work needs it: registers, encoding, calling conventions on Linux and macOS, atomics, barriers, system registers |
| [docs/architecture.md](docs/architecture.md) | How each part of fwe works, and its current limitations |
| [docs/comparisons.md](docs/comparisons.md) | fwe beside Wine, WSL, Linux VMs, gVisor, QEMU, Rosetta, FreeBSD's Linuxulator and others |
| [docs/jit.md](docs/jit.md) | How code a program makes at run time (a JIT compiler's) runs by translation, what it costs, and the runtimes tested |
| [docs/hypervisor.md](docs/hypervisor.md) | The hypervisor backend, its safety rules, and running it |

## Usage

```sh
brew tap e6qu/fwe https://github.com/e6qu/fun-with-emulators
brew install --HEAD fwe
fwe --pull debian:trixie ~/debian          # a Debian userland, from its image
fwe --root ~/debian ~/debian/bin/bash      # a shell in it
fwe ./hello                                # a Linux arm64 executable
fwe --strace ./hello                       # with its system calls traced
```

The [user guide](docs/user-guide.md) covers the rest.

## Layout

| Path | Contents |
|---|---|
| `crates/abi` | Linux arm64 ABI: system-call numbers, errno values, flags, structures |
| `crates/elf` | ELF parsing, load planning, unwind tables, build IDs |
| `crates/kernel` | Linux system calls on top of the host |
| `crates/native` | The native backend (loader, code rewriting, traps) and the hypervisor backend with its stand-in |
| `crates/fwe` | The `fwe` command and the end-to-end tests |
| `guests/asm`, `guests/c`, `guests/rust`, `guests/windows` | Test programs the tests build |
| `guests/musl`, `guests/glibc`, `guests/debian`, `guests/alpine`, `guests/ioccc` | Vendored or fetched programs the tests run, with their provenance |
| `tools/gen-abi.py` | Generates the ABI tables from Linux's UAPI headers |
| `tools/ltp` | Builds LTP and runs its system-call tests against the baseline |
| `tools/bench` | The benchmarks and their budgets (`run.py`, run in CI), and `vm.sh`, which runs them beside a Linux VM on your Mac |
| `docs/` | The user guide, Linux on macOS, how programs are linked and loaded, the architecture, comparisons and the hypervisor backend |

## Testing

```sh
cargo test
```

On Apple Silicon macOS this includes the end-to-end tests, which build the
programs in `guests/` (with `clang` from the Xcode command line tools)
and run them under `fwe`. Tests of distribution programs download them
first (`guests/*/fetch`); the container, Wine, JDK, debugger and image
tests run only where CI sets their variable (`FWE_PODMAN_TESTS` and the
like). The hypervisor backend's tests run on a software stand-in (`brew
install unicorn`), never on a real VM unless asked to. Elsewhere only
the unit tests run. [AGENTS.md](AGENTS.md) lists every check CI runs.

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
