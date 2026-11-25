# Working in this repository

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
when, and only when, they appear in all capitals, as shown here.

## Development process

This project is developed with agentic coding. Work is delivered in large,
outcome-sized pull requests, not small granular ones:

- One PR MUST deliver one testable outcome, usually a milestone or a large
  slice of one from [ROADMAP.md](ROADMAP.md).
- Inside a PR, commits are logical steps; there are no preparatory PRs.
  Refactors, scaffolding and dependency changes MUST go into the PR that
  needs them.
- A PR is ready when its outcome is proven by tests in CI: its "Done when"
  criteria in [ROADMAP.md](ROADMAP.md), which lays the work left out as
  PRs, or new end-to-end tests for a slice of one.
- A PR that changes speed MUST bring its own measurement: counters of where
  the time goes, micro benchmarks that isolate the costs it changes and
  macro benchmarks of programs at work, in CI, built before the change
  they judge.
- A PR MUST be self-reviewed before it is opened: build, lint, tests and a
  review pass.
- Work SHOULD NOT be split into more than one PR, except for parallel
  workstreams that touch separate areas, or for a shared foundation that
  other in-flight work depends on.
- A PR MUST finish its own scope. Its description states what is delivered
  and how it was verified, and MUST NOT leave part of its scope for later.

## Commits

- The author MUST be the repository owner's configured identity.
- Commit messages MUST NOT carry trailers of any kind (`Co-authored-by`,
  `Signed-off-by` or similar).

## Commands

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
RUSTDOCFLAGS="-D warnings -A rustdoc::private-intra-doc-links" cargo doc --workspace --no-deps --document-private-items --target aarch64-apple-darwin
cargo test                      # end-to-end tests run on macOS arm64 only
python3 tools/gen-abi.py        # regenerate crates/abi/src/generated.rs
```

These are what CI runs. On a non-macOS host the macOS-specific code is
type-checked by the `aarch64-apple-darwin` clippy run and the kernel crate's
unit tests run natively; end-to-end behaviour is verified in CI on macOS
runners. The end-to-end tests build the guests into `target/guests` and need
`clang` from the Xcode command line tools.

The hypervisor backend needs the hypervisor entitlement and a bare-metal
Apple Silicon host. Its end-to-end tests (`hv_*`) run on a software
stand-in for Hypervisor.framework (`fwe --hv-standin`, which needs
`brew install unicorn`), and on the real framework only with
`FWE_HV_TESTS=1`, which the self-hosted `hypervisor` job sets. On the
development Mac, `FWE_HV_TESTS` MUST NOT be set and a VM program MUST NOT
be run by hand: misusing the hypervisor can bring the machine down (see
[docs/hypervisor.md](docs/hypervisor.md)). On the stand-in, by hand:

```sh
target/debug/fwe --hv-standin ./program-linked-low
```

To run a low-linked program on the real framework, on a machine meant for it:

```sh
cargo build --release -p fwe
codesign --sign - --entitlements hypervisor.entitlements --force target/release/fwe
target/release/fwe ./program-linked-low
```

## Documents

Each document has one job; content MUST NOT be duplicated across them.

| Document | Holds |
|---|---|
| [README.md](README.md) | What the project is, a short status, how to run and test it |
| [docs/user-guide.md](docs/user-guide.md) | For users: installing, a Linux userland, running programs and containers, what does not work; its tested recipes run in CI |
| [PLAN.md](PLAN.md) | Goal, approach, scope, the 1.0 finish line, principles, how progress is measured |
| [ROADMAP.md](ROADMAP.md) | Status, what is done, what is left to 1.0 as PRs with "Done when" criteria, and what is not planned |
| [docs/linux-on-macos.md](docs/linux-on-macos.md) | How Linux programs run on macOS: which binaries run where and what costs least, how languages and runtimes fare, which instructions are rewritten, how the VM is used; Linux to macOS (what Linux does, what macOS has, what fwe does) and macOS to Linux (what happens on the host, what the guest sees) |
| [docs/linking.md](docs/linking.md) | Background, not fwe: how programs are built and loaded on Linux and macOS on arm64 (ELF and Mach-O, relocations, static and dynamic linking, PIE, static PIE and their code, virtual memory, ASLR, TLS, program start) |
| [docs/arm64.md](docs/arm64.md) | Background, not fwe: the arm64 instruction set as fwe's work needs it (registers, encoding, exception levels, the procedure call standard and how Linux's and Apple's differ, branches, loads, stores and atomics, barriers, system registers, PAC and BTI) |
| [docs/architecture.md](docs/architecture.md) | How each part works, and the current limitations |
| [docs/comparisons.md](docs/comparisons.md) | fwe beside other ways to run Linux programs (Wine, VMs, WSL, gVisor, translators, the Linuxulator, rebuilding) and what it takes from each |
| [docs/jit.md](docs/jit.md) | Code made at run time (JIT compilers', self-modifying code): why and how it runs by translation, how changes are found, what it costs, the runtimes tested, how other translators do it |
| [docs/hypervisor.md](docs/hypervisor.md) | The hypervisor backend, how to run it, and its CI arrangement |
| `guests/*/README.md` | Provenance and licenses of vendored test fixtures |
| `notes/research/*.md` | Research notes: dated, sourced surveys of other projects (Linux on macOS, Wine on Apple Silicon and on Asahi Linux, terminals) and of what fwe could do in-process; kept as written, not maintained |

A PR that changes behaviour MUST update them in the same PR: it ticks the
roadmap item its tests prove, removes a lifted limitation from
`docs/architecture.md` and the roadmap, updates `docs/linux-on-macos.md`
where how fwe maps a Linux feature, or passes a host event to the guest,
changes, and keeps module-level doc comments in the code consistent with
what the code now does. Docs MUST state what is true now, with no history
of how it got there.

### Requirement language

Every document and code comment in the repository but `notes/research`
follows BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), as
updated by [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)):

- A requirement MUST use the key words in capitals: a rule for
  contributors, a contract a caller MUST keep (a function's `# Safety`
  preconditions, an argument's limits), an invariant whose breach does
  harm (a crashed machine, lost data, undefined behaviour), and what a user
  MUST do for a program to work.
- The key words SHOULD be used sparingly (RFC 2119, section 6). What fwe,
  Linux or macOS does is stated in the plain present tense ("fwe maps…",
  "Linux returns…"), not as a requirement.
- "must", "should", "shall", "may", "required", "recommended" and
  "optional" MUST NOT appear in lower case where they could be read as a
  requirement: a requirement takes the capitals, and anything else is
  reworded ("can" or "might" for a possibility, "needs" or "takes" for
  what a mechanism depends on).
- A document that uses the key words MUST carry the notice above near its
  beginning. Code comments are covered by the notice in each crate's root
  documentation (`lib.rs` or `main.rs`) and in `driver/vulkan/fwe_vk.h` for
  the C driver.
- A generated file's comments change through its generator
  (`tools/gen-abi.py`, `tools/gen-vulkan.py`), never by hand.

## Conventions

- Every `unsafe` block MUST have a `// SAFETY:` comment.
- Linux ABI values live in `crates/abi`; host translation lives in
  `crates/kernel/src/host.rs`.
- A new system call MUST get a unit test in the kernel crate where
  possible, and a guest program plus end-to-end test when its behaviour
  depends on the backend.
- Vendored binaries under `guests/` MUST be unmodified, with provenance and
  license recorded in that directory's README.
- Implementation problems are things to solve, not blockers.
- A process running a Hypervisor.framework VM MUST NOT end, exec or fork
  with the VM alive. The VM tests MUST run one at a time, never in
  parallel (a forking guest's parent and child each have a VM), and MUST
  NOT run while another hypervisor client such as Podman's `krunkit` runs
  (stop it first; the tests skip otherwise): misusing the hypervisor can
  bring the machine down (see [docs/hypervisor.md](docs/hypervisor.md)).
  VM changes MUST be verified on a machine whose crash costs nothing, with
  the run instrumented so a crash can be traced; a software stand-in MUST
  NOT replace that.
