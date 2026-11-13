# Working in this repository

## Development process

This project is developed with agentic coding. Work is delivered in large,
outcome-sized pull requests, not small granular ones:

- One PR delivers one testable outcome — usually a milestone or a large slice
  of one from [ROADMAP.md](ROADMAP.md).
- Inside a PR, commits are logical steps; there are no preparatory PRs.
  Refactors, scaffolding and dependency changes go into the PR that needs
  them.
- A PR is ready when its outcome is proven by tests in CI — a milestone's
  "Done when" criteria, or new end-to-end tests for a slice of one.
- Self-reviewed before opening: build, lint, tests and a review pass.
- Split only for parallel workstreams that touch separate areas, or for a
  shared foundation that other in-flight work depends on.
- PR descriptions state what is delivered, how it was verified and what is
  left for later.

## Commits

- Author: the repository owner's configured identity.
- No trailers of any kind in commit messages (no `Co-authored-by`,
  `Signed-off-by` or similar).

## Commands

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
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
`FWE_HV_TESTS=1`, which the self-hosted `hypervisor` job sets. Do not set it,
or run a VM program by hand, on the development Mac: misusing the hypervisor
can bring the machine down (see [docs/hypervisor.md](docs/hypervisor.md)).
On the stand-in, by hand:

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

Each document has one job; do not duplicate content across them.

| Document | Holds |
|---|---|
| [README.md](README.md) | What the project is, a short status, how to run and test it |
| [docs/user-guide.md](docs/user-guide.md) | For users: installing, a Linux userland, running programs and containers, what does not work; its tested recipes run in CI |
| [PLAN.md](PLAN.md) | Goal, approach, scope, the 1.0 finish line, principles, how progress is measured |
| [ROADMAP.md](ROADMAP.md) | Status, what is done, what is left to 1.0 with "Done when" criteria, and what is not planned |
| [docs/linux-on-macos.md](docs/linux-on-macos.md) | How Linux programs run on macOS: which binaries run where and what costs least, how languages and runtimes fare, which instructions are rewritten, how the VM is used; Linux to macOS (what Linux does, what macOS has, what fwe does) and macOS to Linux (what happens on the host, what the guest sees) |
| [docs/architecture.md](docs/architecture.md) | How each part works, and the current limitations |
| [docs/hypervisor.md](docs/hypervisor.md) | The hypervisor backend, how to run it, and its CI arrangement |
| `guests/*/README.md` | Provenance and licenses of vendored test fixtures |

A PR that changes behaviour updates them in the same PR: tick the roadmap
item its tests prove, remove a lifted limitation from
`docs/architecture.md` and the roadmap, update `docs/linux-on-macos.md`
where how fwe maps a Linux feature, or passes a host event to the guest,
changes, and keep module-level doc comments in the code consistent with
what the code now does. Docs state what is true now: no history of how it got there.

## Conventions

- Every `unsafe` block has a `// SAFETY:` comment.
- Linux ABI values live in `crates/abi`; host translation lives in
  `crates/kernel/src/host.rs`.
- New system calls get a unit test in the kernel crate where possible, and a
  guest program plus end-to-end test when behaviour depends on the backend.
- Vendored binaries under `guests/` are unmodified, with provenance and
  license recorded in that directory's README.
- Treat implementation problems as things to solve, not as blockers.
- A process running a Hypervisor.framework VM must never end, exec or fork
  with the VM alive, and the VM tests run one at a time, never in parallel
  (a forking guest's parent and child each have a VM) and never while
  another hypervisor client such as Podman's `krunkit` runs (stop it first;
  the tests skip otherwise): misusing the hypervisor can bring the machine
  down (see [docs/hypervisor.md](docs/hypervisor.md)).
  VM changes are verified on a machine whose crash costs nothing, with the
  run instrumented so a crash can be traced; a software stand-in never
  replaces that.
